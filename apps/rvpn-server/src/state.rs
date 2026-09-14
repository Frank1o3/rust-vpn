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

pub struct ActivePeer {
    pub identity: PeerIdentity,
    pub session: ProtectedSession,
    pub endpoint: SocketAddr,
}

pub enum PendingSource {
    Known(PeerIdentity),
    CertificateAuthority(CertificateAuthorityConfig),
}

pub struct PendingHandshake {
    pub source: PendingSource,
    pub handshake: ResponderHandshake,
    pub endpoint: SocketAddr,
    pub packet: Packet,
    pub kind: PacketKind,
    pub attempts: u32,
}

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

pub fn ip_in_prefixes(prefixes: &[IpNet], address: IpAddr) -> bool {
    prefixes.is_empty() || prefixes.iter().any(|prefix| prefix.contains(&address))
}
