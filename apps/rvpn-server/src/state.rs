use rvpn_config::{CertificateAuthorityConfig, PeerIdentity};
use rvpn_core::SessionId;
use rvpn_crypto::ObfuscationKey;
use rvpn_protocol::{Packet, PacketKind, ProtectedSession, ResponderHandshake};
use rvpn_transport::{SendOptions, UdpTransport};
use std::{collections::HashMap, net::SocketAddr, time::Instant};

pub struct ActivePeer {
    pub identity: PeerIdentity,
    pub session: ProtectedSession,
    pub endpoint: SocketAddr,
    pub last_rx: Instant,
    pub last_rekey_request: Option<Instant>,
}

impl ActivePeer {
    pub fn new(identity: PeerIdentity, session: ProtectedSession, endpoint: SocketAddr) -> Self {
        Self {
            identity,
            session,
            endpoint,
            last_rx: Instant::now(),
            last_rekey_request: None,
        }
    }
}

pub fn same_peer(a: &PeerIdentity, b: &PeerIdentity) -> bool {
    a.name == b.name && a.allowed_ips == b.allowed_ips
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

#[cfg(test)]
mod tests {
    use super::*;
    use rvpn_crypto::AuthConfig;

    fn identity(name: &str, ips: &[&str]) -> PeerIdentity {
        PeerIdentity {
            name: name.into(),
            allowed_ips: ips.iter().map(|prefix| prefix.parse().unwrap()).collect(),
            auth: AuthConfig::Psk([1; 32]),
        }
    }

    #[test]
    fn same_peer_requires_matching_name_and_addresses() {
        let laptop = identity("laptop", &["10.42.0.2/32"]);
        assert!(same_peer(&laptop, &identity("laptop", &["10.42.0.2/32"])));
        assert!(!same_peer(&laptop, &identity("phone", &["10.42.0.2/32"])));
        assert!(!same_peer(&laptop, &identity("laptop", &["10.42.0.9/32"])));
    }
}
