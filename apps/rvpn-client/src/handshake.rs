use anyhow::{Context, Result, bail};
use rvpn_config::HandshakeConfig;
use rvpn_core::SessionId;
use rvpn_crypto::{AuthConfig, ObfuscationKey};
use rvpn_protocol::{
    HandshakeMessage, Header, InitiatorHandshake, Packet, PacketKind, ProtectedSession,
};
use rvpn_transport::{SendOptions, UdpTransport};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::time::{sleep, timeout};

fn wrap(encoded: bytes::Bytes, obfuscation: Option<&ObfuscationKey>) -> Result<bytes::Bytes> {
    Ok(match obfuscation {
        Some(key) => key.wrap(&encoded)?,
        None => encoded,
    })
}

pub async fn maybe_rekey(
    session: &mut ProtectedSession,
    transport: &UdpTransport,
    server: SocketAddr,
    auth: &AuthConfig,
    obfuscation: Option<&ObfuscationKey>,
    handshake: &HandshakeConfig,
    packet_limit: u64,
) -> Result<()> {
    if packet_limit != 0 && session.should_rekey(packet_limit) {
        *session = establish(
            transport,
            server,
            auth,
            obfuscation,
            handshake,
            Some(session),
        )
        .await?;
        tracing::info!(key_phase = session.key_phase(), "rotated RVPN session keys");
    }
    Ok(())
}

pub async fn establish(
    transport: &UdpTransport,
    server: SocketAddr,
    auth: &AuthConfig,
    obfuscation: Option<&ObfuscationKey>,
    policy: &HandshakeConfig,
    old: Option<&ProtectedSession>,
) -> Result<ProtectedSession> {
    let (mut handshake, initiation) = InitiatorHandshake::start(auth.identity(), auth.verifier())?;
    let (kind, session_id, key_phase) = match old {
        Some(session) => (
            PacketKind::Rekey,
            session.session_id(),
            session
                .key_phase()
                .checked_add(1)
                .context("key phase exhausted")?,
        ),
        None => (PacketKind::Handshake, SessionId::ZERO, 0),
    };
    let old_phase = old.map_or(0, ProtectedSession::key_phase);
    let mut initiation_packet = Packet {
        header: Header {
            kind,
            key_phase: old_phase,
            sequence: 0,
            session_id,
        },
        payload: initiation.encode(),
    };

    let response = 'retry: loop {
        for attempt in 1..=policy.retry_limit {
            let wire = wrap(initiation_packet.encode(), obfuscation)?;
            transport
                .send_to(server, wire, SendOptions::default())
                .await?;
            let deadline = Instant::now() + Duration::from_millis(policy.retry_jitter_ms);
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match timeout(remaining, transport.receive()).await {
                    Ok(Ok(datagram)) if datagram.peer == server => {
                        let payload = match obfuscation {
                            Some(key) => match key.unwrap(&datagram.payload) {
                                Ok(payload) => payload,
                                Err(_) => continue,
                            },
                            None => datagram.payload,
                        };
                        if let Ok(packet) = Packet::decode(payload) {
                            if packet.header.kind == kind
                                && (old.is_none() || packet.header.session_id == session_id)
                            {
                                match HandshakeMessage::decode(packet.payload) {
                                    Ok(response @ HandshakeMessage::Response { .. }) => {
                                        let advertised_session = match response {
                                            HandshakeMessage::Response { session_id, .. } => {
                                                session_id
                                            }
                                            _ => unreachable!(),
                                        };
                                        if packet.header.session_id == advertised_session
                                            && handshake.authenticates_response(response)?
                                        {
                                            break 'retry response;
                                        }
                                    }
                                    Ok(HandshakeMessage::CookieReply { cookie }) => {
                                        // Cheap, immediate resend — doesn't consume a retry attempt.
                                        handshake.attach_cookie(cookie);
                                        initiation_packet.payload = handshake.initiation().encode();
                                        let wire = wrap(initiation_packet.encode(), obfuscation)?;
                                        transport
                                            .send_to(server, wire, SendOptions::default())
                                            .await?;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    Ok(Ok(_)) => continue,
                    Ok(Err(error)) => return Err(error.into()),
                    Err(_) => break,
                }
            }
            tracing::debug!(attempt, %server, "handshake response timed out; retransmitting");
        }

        bail!(
            "RVPN handshake timed out after {} attempts to {}",
            policy.retry_limit,
            server
        );
    };
    let finish_session_id = match response {
        HandshakeMessage::Response { session_id, .. } => session_id,
        _ => unreachable!(),
    };
    let (finish, new_session, _remote_identity) = match old {
        Some(_) => handshake.finish_for_session(response, session_id, key_phase)?,
        None => handshake.finish(response)?,
    };
    let finish_packet = Packet {
        header: Header {
            kind,
            key_phase: old_phase,
            sequence: 1,
            session_id: finish_session_id,
        },
        payload: finish.encode(),
    };
    for attempt in 1..=policy.retry_limit {
        let wire = wrap(finish_packet.encode(), obfuscation)?;
        transport
            .send_to(server, wire, SendOptions::default())
            .await?;
        if attempt != policy.retry_limit {
            sleep(Duration::from_millis(policy.retry_jitter_ms)).await;
        }
    }
    Ok(new_session)
}
