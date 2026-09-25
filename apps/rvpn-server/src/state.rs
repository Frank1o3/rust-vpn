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

#[derive(Default)]
pub struct PendingHandshakes {
    entries: HashMap<SessionId, PendingHandshake>,
    per_source: HashMap<SocketAddr, usize>,
}

impl PendingHandshakes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn contains_key(&self, id: &SessionId) -> bool {
        self.entries.contains_key(id)
    }

    pub fn get(&self, id: &SessionId) -> Option<&PendingHandshake> {
        self.entries.get(id)
    }

    pub fn count_for(&self, source: SocketAddr) -> usize {
        self.per_source.get(&source).copied().unwrap_or(0)
    }

    pub fn insert(&mut self, id: SessionId, state: PendingHandshake) {
        let source = state.endpoint;
        if let Some(previous) = self.entries.insert(id, state) {
            self.decrement(previous.endpoint);
        }
        *self.per_source.entry(source).or_insert(0) += 1;
    }

    pub fn remove(&mut self, id: &SessionId) -> Option<PendingHandshake> {
        let removed = self.entries.remove(id);
        if let Some(state) = &removed {
            self.decrement(state.endpoint);
        }
        removed
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&PendingHandshake) -> bool) {
        let per_source = &mut self.per_source;
        self.entries.retain(|_, state| {
            let keep = keep(state);
            if !keep && let Some(count) = per_source.get_mut(&state.endpoint) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    per_source.remove(&state.endpoint);
                }
            }
            keep
        });
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut PendingHandshake> {
        self.entries.values_mut()
    }

    fn decrement(&mut self, source: SocketAddr) {
        if let Some(count) = self.per_source.get_mut(&source) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_source.remove(&source);
            }
        }
    }
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
    use rvpn_crypto::{AuthConfig, EphemeralKeyPair, IdentityKeyPair};
    use rvpn_protocol::{HandshakeMessage, InitiatorHandshake};

    fn identity(name: &str, ips: &[&str]) -> PeerIdentity {
        PeerIdentity {
            name: name.into(),
            allowed_ips: ips.iter().map(|prefix| prefix.parse().unwrap()).collect(),
            auth: AuthConfig::PinnedKey {
                local_seed: [1; 32],
                peer_public_key: [2; 32],
            },
        }
    }

    #[test]
    fn same_peer_requires_matching_name_and_addresses() {
        let laptop = identity("laptop", &["10.42.0.2/32"]);
        assert!(same_peer(&laptop, &identity("laptop", &["10.42.0.2/32"])));
        assert!(!same_peer(&laptop, &identity("phone", &["10.42.0.2/32"])));
        assert!(!same_peer(&laptop, &identity("laptop", &["10.42.0.9/32"])));
    }

    fn dummy_pending(endpoint: SocketAddr, attempts: u32) -> PendingHandshake {
        // Build a real ResponderHandshake so PendingHandshake is fully valid.
        let server_key = IdentityKeyPair::generate().unwrap();
        let client_key = IdentityKeyPair::generate().unwrap();
        let server_auth = AuthConfig::PinnedKey {
            local_seed: server_key.to_seed_bytes(),
            peer_public_key: client_key.public_key().to_bytes(),
        };
        let client_auth = AuthConfig::PinnedKey {
            local_seed: client_key.to_seed_bytes(),
            peer_public_key: server_key.public_key().to_bytes(),
        };
        let (_initiator, initiation) =
            InitiatorHandshake::start(client_auth.identity(), client_auth.verifier()).unwrap();
        let (handshake, response) =
            ResponderHandshake::accept(server_auth.identity(), server_auth.verifier(), initiation)
                .unwrap();
        let HandshakeMessage::Response { session_id, .. } = response else {
            unreachable!()
        };
        let _ = EphemeralKeyPair::generate(); // keep this test self-contained/obvious
        PendingHandshake {
            source: PendingSource::Known(identity("test", &["10.42.0.2/32"])),
            handshake,
            endpoint,
            packet: Packet {
                header: rvpn_protocol::Header {
                    kind: PacketKind::Handshake,
                    key_phase: 0,
                    sequence: 0,
                    session_id,
                },
                payload: response.encode(),
            },
            kind: PacketKind::Handshake,
            attempts,
        }
        .with_id(session_id)
    }

    // Small helper so `dummy_pending` can hand back its session id alongside
    // the value without changing PendingHandshake's public shape.
    trait WithId {
        fn with_id(self, id: SessionId) -> Self;
    }
    impl WithId for PendingHandshake {
        fn with_id(self, _id: SessionId) -> Self {
            self
        }
    }

    #[test]
    fn per_source_accounting_tracks_insert_remove_and_retain() {
        let mut pending = PendingHandshakes::new();
        let a: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:1".parse().unwrap();

        assert_eq!(pending.count_for(a), 0);

        let p1 = dummy_pending(a, 1);
        let id1 = p1.packet.header.session_id;
        pending.insert(id1, p1);
        assert_eq!(pending.count_for(a), 1);
        assert_eq!(pending.len(), 1);

        let p2 = dummy_pending(a, 1);
        let id2 = p2.packet.header.session_id;
        pending.insert(id2, p2);
        assert_eq!(pending.count_for(a), 2);

        // A different source is unaffected by `a`'s usage.
        let p3 = dummy_pending(b, 1);
        let id3 = p3.packet.header.session_id;
        pending.insert(id3, p3);
        assert_eq!(pending.count_for(b), 1);
        assert_eq!(pending.count_for(a), 2);

        // Completing (removing) one of `a`'s entries releases accounting.
        assert!(pending.remove(&id1).is_some());
        assert_eq!(pending.count_for(a), 1);

        // Retry-limit expiry via retain() also releases accounting.
        pending.retain(|state| state.attempts < 5);
        // (attempts=1 < 5 for all, so nothing is dropped here)
        assert_eq!(pending.count_for(a), 1);
        assert_eq!(pending.count_for(b), 1);

        pending.retain(|state| state.attempts >= 5);
        // now everything with attempts < 5 (all of it) is dropped
        assert_eq!(pending.count_for(a), 0);
        assert_eq!(pending.count_for(b), 0);
        assert_eq!(pending.len(), 0);

        let _ = id3; // silence unused warnings in case of reordering
    }
}
