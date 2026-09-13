//! Responder handshake handling, rekey flights, and session establishment.

use anyhow::{Context, Result};
use rvpn_config::{CertificateAuthorityConfig, HandshakeConfig, PeerIdentity};
use rvpn_core::SessionId;
use rvpn_crypto::ObfuscationKey;
use rvpn_protocol::{HandshakeMessage, Header, Packet, PacketKind, ResponderHandshake};
use rvpn_transport::{SendOptions, UdpTransport};
use std::{collections::HashMap, net::SocketAddr};

use crate::state::{ActivePeer, PendingHandshake, PendingSource};

async fn send_wire(
    transport: &UdpTransport,
    endpoint: SocketAddr,
    encoded: bytes::Bytes,
    obfuscation: Option<&ObfuscationKey>,
) -> Result<()> {
    let wire = match obfuscation {
        Some(key) => key.wrap(&encoded)?,
        None => encoded,
    };
    transport
        .send_to(endpoint, wire, SendOptions::default())
        .await?;
    Ok(())
}

pub async fn begin_initial(
    transport: &UdpTransport,
    identities: &[PeerIdentity],
    certificate_authority: Option<&CertificateAuthorityConfig>,
    obfuscation: Option<&ObfuscationKey>,
    pending: &mut HashMap<SessionId, PendingHandshake>,
    endpoint: SocketAddr,
    initiation: HandshakeMessage,
) -> Result<()> {
    for identity in identities {
        let (handshake, response) = ResponderHandshake::accept(
            identity.auth.identity(),
            identity.auth.verifier(),
            initiation,
        )?;
        let session_id = match response {
            HandshakeMessage::Response { session_id, .. } => session_id,
            _ => unreachable!(),
        };
        let packet = Packet {
            header: Header {
                kind: PacketKind::Handshake,
                key_phase: 0,
                sequence: 0,
                session_id,
            },
            payload: response.encode(),
        };
        send_wire(transport, endpoint, packet.encode(), obfuscation).await?;
        pending.insert(
            session_id,
            PendingHandshake {
                source: PendingSource::Known(identity.clone()),
                handshake,
                endpoint,
                packet,
                kind: PacketKind::Handshake,
                attempts: 1,
            },
        );
    }

    if let Some(ca) = certificate_authority {
        let auth = ca.to_auth_config()?;
        let (handshake, response) =
            ResponderHandshake::accept(auth.identity(), auth.verifier(), initiation)?;
        let session_id = match response {
            HandshakeMessage::Response { session_id, .. } => session_id,
            _ => unreachable!(),
        };
        let packet = Packet {
            header: Header {
                kind: PacketKind::Handshake,
                key_phase: 0,
                sequence: 0,
                session_id,
            },
            payload: response.encode(),
        };
        send_wire(transport, endpoint, packet.encode(), obfuscation).await?;
        pending.insert(
            session_id,
            PendingHandshake {
                source: PendingSource::CertificateAuthority(ca.clone()),
                handshake,
                endpoint,
                packet,
                kind: PacketKind::Handshake,
                attempts: 1,
            },
        );
    }
    Ok(())
}

pub async fn begin_rekey(
    transport: &UdpTransport,
    obfuscation: Option<&ObfuscationKey>,
    pending: &mut HashMap<SessionId, PendingHandshake>,
    endpoint: SocketAddr,
    current: &ActivePeer,
    initiation: HandshakeMessage,
) -> Result<()> {
    if pending.contains_key(&current.session.session_id()) {
        tracing::debug!(peer = %current.identity.name, session_id = ?current.session.session_id(), "rekey already in progress for peer; ignoring initiation");
        return Ok(());
    }
    let phase = current
        .session
        .key_phase()
        .checked_add(1)
        .context("key phase exhausted")?;
    let (handshake, response) = ResponderHandshake::accept_for_session(
        current.identity.auth.identity(),
        current.identity.auth.verifier(),
        initiation,
        current.session.session_id(),
        phase,
    )?;
    let packet = Packet {
        header: Header {
            kind: PacketKind::Rekey,
            key_phase: current.session.key_phase(),
            sequence: 0,
            session_id: current.session.session_id(),
        },
        payload: response.encode(),
    };
    send_wire(transport, endpoint, packet.encode(), obfuscation).await?;
    pending.insert(
        current.session.session_id(),
        PendingHandshake {
            source: PendingSource::Known(current.identity.clone()),
            handshake,
            endpoint,
            packet,
            kind: PacketKind::Rekey,
            attempts: 1,
        },
    );
    Ok(())
}

pub async fn maybe_send_rekey(
    transport: &UdpTransport,
    obfuscation: Option<&ObfuscationKey>,
    peer: &mut ActivePeer,
    packet_limit: u64,
) -> Result<()> {
    if packet_limit != 0 && peer.session.should_rekey(packet_limit) {
        let request = peer.session.seal(PacketKind::Rekey, b"")?;
        send_wire(transport, peer.endpoint, request.encode(), obfuscation).await?;
    }
    Ok(())
}

pub fn finish_pending(
    pending: &mut HashMap<SessionId, PendingHandshake>,
    active: &mut HashMap<SessionId, ActivePeer>,
    endpoint: SocketAddr,
    packet: Packet,
) -> Result<()> {
    let Some(pending_handshake) = pending.remove(&packet.header.session_id) else {
        tracing::debug!(session_id = ?packet.header.session_id, %endpoint, "received finish for unknown or expired pending handshake");
        return Ok(());
    };
    if pending_handshake.endpoint != endpoint || pending_handshake.kind != packet.header.kind {
        tracing::warn!(
            session_id = ?packet.header.session_id,
            expected_endpoint = %pending_handshake.endpoint,
            actual_endpoint = %endpoint,
            expected_kind = ?pending_handshake.kind,
            actual_kind = ?packet.header.kind,
            "discarding finish packet with mismatched endpoint or packet kind"
        );
        return Ok(());
    }
    let finish = HandshakeMessage::decode(packet.payload)?;
    let (session, remote_identity) = pending_handshake.handshake.finish(finish)?;
    let id = session.session_id();

    let identity = match pending_handshake.source {
        PendingSource::Known(identity) => identity,
        PendingSource::CertificateAuthority(ca) => {
            let Some(subject) = remote_identity else {
                tracing::warn!(session_id = ?id, "certificate handshake finished without a verified subject key");
                return Ok(());
            };
            let subject_hex = hex::encode(subject.to_bytes());
            let allowed_ips = ca.resolve_allowed_ips(&subject_hex)?;
            rvpn_config::PeerIdentity {
                name: format!("cert:{}", &subject_hex[..subject_hex.len().min(16)]),
                allowed_ips,
                auth: ca.to_auth_config()?,
            }
        }
    };

    let name = identity.name.clone();
    active.insert(
        id,
        ActivePeer {
            identity,
            session,
            endpoint,
        },
    );
    tracing::info!(%name, session_id = ?id, %endpoint, "authenticated RVPN peer established");
    Ok(())
}

pub async fn retransmit_pending(
    transport: &UdpTransport,
    obfuscation: Option<&ObfuscationKey>,
    pending: &mut HashMap<SessionId, PendingHandshake>,
    policy: &HandshakeConfig,
) -> Result<()> {
    pending.retain(|_, state| state.attempts < policy.retry_limit);
    for state in pending.values_mut() {
        send_wire(
            transport,
            state.endpoint,
            state.packet.encode(),
            obfuscation,
        )
        .await?;
        state.attempts += 1;
    }
    Ok(())
}
