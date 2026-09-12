//! Handshake initiation, confirmation, and rekeying for the RVPN client.

use anyhow::{Context, Result, bail};
use rvpn_config::HandshakeConfig;
use rvpn_core::SessionId;
use rvpn_crypto::HandshakePsk;
use rvpn_protocol::{
    HandshakeMessage, Header, InitiatorHandshake, Packet, PacketKind, ProtectedSession,
};
use rvpn_transport::{SendOptions, UdpTransport};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::time::{sleep, timeout};

/// Checks whether the session should rekey and performs the rekey flight if needed.
pub async fn maybe_rekey(
    session: &mut ProtectedSession,
    transport: &UdpTransport,
    server: SocketAddr,
    psk: [u8; 32],
    handshake: &HandshakeConfig,
    packet_limit: u64,
) -> Result<()> {
    if packet_limit != 0 && session.should_rekey(packet_limit) {
        *session = establish(transport, server, psk, handshake, Some(session)).await?;
        tracing::info!(key_phase = session.key_phase(), "rotated RVPN session keys");
    }
    Ok(())
}

/// Retransmits each handshake flight. Rekeys retain the established session ID.
pub async fn establish(
    transport: &UdpTransport,
    server: SocketAddr,
    psk: [u8; 32],
    policy: &HandshakeConfig,
    old: Option<&ProtectedSession>,
) -> Result<ProtectedSession> {
    let (handshake, initiation) = InitiatorHandshake::start(HandshakePsk::from_bytes(psk))?;
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
    let initiation_packet = Packet {
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
            transport
                .send_to(server, initiation_packet.encode(), SendOptions::default())
                .await?;
            let deadline = Instant::now() + Duration::from_millis(policy.retry_interval_ms);
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match timeout(remaining, transport.receive()).await {
                    Ok(Ok(datagram)) if datagram.peer == server => {
                        if let Ok(packet) = Packet::decode(datagram.payload) {
                            if packet.header.kind == kind
                                && (old.is_none() || packet.header.session_id == session_id)
                            {
                                if let Ok(response @ HandshakeMessage::Response { .. }) =
                                    HandshakeMessage::decode(packet.payload)
                                {
                                    // The first response introduces its newly assigned session ID;
                                    // rekey responses must remain bound to the existing one.
                                    let advertised_session = match response {
                                        HandshakeMessage::Response { session_id, .. } => session_id,
                                        _ => unreachable!(),
                                    };
                                    if packet.header.session_id == advertised_session
                                        && handshake.authenticates_response(response)?
                                    {
                                        break 'retry response;
                                    }
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
    let (finish, new_session) = match old {
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
        transport
            .send_to(server, finish_packet.encode(), SendOptions::default())
            .await?;
        if attempt != policy.retry_limit {
            sleep(Duration::from_millis(policy.retry_interval_ms)).await;
        }
    }
    Ok(new_session)
}
