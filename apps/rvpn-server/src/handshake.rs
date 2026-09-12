//! Responder handshake handling, rekey flights, and session establishment.

use anyhow::{Context, Result};
use rvpn_config::{HandshakeConfig, PeerIdentity};
use rvpn_core::SessionId;
use rvpn_crypto::HandshakePsk;
use rvpn_protocol::{
    HandshakeMessage, Header, Packet, PacketKind, ResponderHandshake,
};
use rvpn_transport::{SendOptions, UdpTransport};
use std::{collections::HashMap, net::SocketAddr};

use crate::state::{ActivePeer, PendingHandshake};

pub async fn begin_initial(
    transport: &UdpTransport,
    identities: &[PeerIdentity],
    pending: &mut HashMap<SessionId, PendingHandshake>,
    endpoint: SocketAddr,
    initiation: HandshakeMessage,
) -> Result<()> {
    for identity in identities {
        let (handshake, response) = ResponderHandshake::accept(
            HandshakePsk::from_bytes(identity.pre_shared_key),
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
        transport
            .send_to(endpoint, packet.encode(), SendOptions::default())
            .await?;
        pending.insert(
            session_id,
            PendingHandshake {
                identity: identity.clone(),
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
        HandshakePsk::from_bytes(current.identity.pre_shared_key),
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
    transport
        .send_to(endpoint, packet.encode(), SendOptions::default())
        .await?;
    pending.insert(
        current.session.session_id(),
        PendingHandshake {
            identity: current.identity.clone(),
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
    peer: &mut ActivePeer,
    packet_limit: u64,
) -> Result<()> {
    if packet_limit != 0 && peer.session.should_rekey(packet_limit) {
        let request = peer.session.seal(PacketKind::Rekey, b"")?;
        transport
            .send_to(peer.endpoint, request.encode(), SendOptions::default())
            .await?;
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
    let session = pending_handshake.handshake.finish(finish)?;
    let id = session.session_id();
    let name = pending_handshake.identity.name.clone();
    active.insert(
        id,
        ActivePeer {
            identity: pending_handshake.identity,
            session,
            endpoint,
        },
    );
    tracing::info!(%name, session_id = ?id, %endpoint, "authenticated RVPN peer established");
    Ok(())
}

pub async fn retransmit_pending(
    transport: &UdpTransport,
    pending: &mut HashMap<SessionId, PendingHandshake>,
    policy: &HandshakeConfig,
) -> Result<()> {
    pending.retain(|_, state| state.attempts < policy.retry_limit);
    for state in pending.values_mut() {
        transport
            .send_to(
                state.endpoint,
                state.packet.encode(),
                SendOptions::default(),
            )
            .await?;
        state.attempts += 1;
    }
    Ok(())
}
