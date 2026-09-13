//! Server state structures, peer registries, and prefix matching.

use ipnet::IpNet;
use rvpn_config::{CertificateAuthorityConfig, PeerIdentity};
use rvpn_core::SessionId;
use rvpn_crypto::ObfuscationKey;
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

/// Where a pending handshake's final identity should come from once its
/// Finish message has been authenticated.
pub enum PendingSource {
    /// Identity and `allowed_ips` are already known (PSK or pinned-key peer).
    Known(PeerIdentity),
    /// Identity is only known once the client's certificate subject key is
    /// extracted from its authenticated Finish message.
    CertificateAuthority(CertificateAuthorityConfig),
}

/// An in-progress handshake flight awaiting confirmation.
pub struct PendingHandshake {
    pub source: PendingSource,
    pub handshake: ResponderHandshake,
    pub endpoint: SocketAddr,
    pub packet: Packet,
    pub kind: PacketKind,
    pub attempts: u32,
}

/// Closes all active client sessions by sending an authenticated close packet.
pub async fn close_all(
    transport: &UdpTransport,
    active: &mut HashMap<SessionId, ActivePeer>,
    obfuscation: Option<&ObfuscationKey>,
) {
    for peer in active.values_mut() {
        if let Ok(close) = peer.session.seal(PacketKind::Close, b"") {
            let encoded = close.encode();
            let wire = match obfuscation {
                Some(key) => key.wrap(&encoded).unwrap_or(encoded),
                None => encoded,
            };
            let _ = transport
                .send_to(peer.endpoint, wire, SendOptions::default())
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
