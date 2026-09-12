//! Server state structures, peer registries, and prefix matching.

use ipnet::IpNet;
use rvpn_config::PeerIdentity;
use rvpn_core::SessionId;
use rvpn_protocol::{Packet, PacketKind, ProtectedSession, ResponderHandshake};
use rvpn_transport::{SendOptions, UdpTransport};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

/// An established, authenticated client session.
pub struct ActivePeer {
    pub identity: PeerIdentity,
    pub session: ProtectedSession,
    pub endpoint: SocketAddr,
}

/// An in-progress handshake flight awaiting confirmation.
pub struct PendingHandshake {
    pub identity: PeerIdentity,
    pub handshake: ResponderHandshake,
    pub endpoint: SocketAddr,
    pub packet: Packet,
    pub kind: PacketKind,
    pub attempts: u32,
}

/// Closes all active client sessions by sending an authenticated close packet.
pub async fn close_all(transport: &UdpTransport, active: &mut HashMap<SessionId, ActivePeer>) {
    for peer in active.values_mut() {
        if let Ok(close) = peer.session.seal(PacketKind::Close, b"") {
            let _ = transport
                .send_to(peer.endpoint, close.encode(), SendOptions::default())
                .await;
        }
    }
}

/// Returns `true` when `address` falls within any of `prefixes`, or when
/// `prefixes` is empty (meaning the peer is unrestricted / any destination
/// is routable to it).
pub fn ip_in_prefixes(prefixes: &[IpNet], address: IpAddr) -> bool {
    prefixes.is_empty() || prefixes.iter().any(|prefix| prefix.contains(&address))
}
