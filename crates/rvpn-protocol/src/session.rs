use crate::{Header, Packet, PacketKind, ProtocolError, ReplayError, ReplayWindow};
use bytes::Bytes;
use rvpn_core::SessionId;
use rvpn_crypto::{CryptoError, PacketNonce, SessionKeys};
use std::time::{Duration, Instant};
use thiserror::Error;

struct PreviousPhase {
    key_phase: u32,
    keys: SessionKeys,
    replay: ReplayWindow,
    expires_at: Instant,
}

pub struct ProtectedSession {
    session_id: SessionId,
    key_phase: u32,
    next_send_sequence: u64,
    receive_replay: ReplayWindow,
    keys: SessionKeys,
    created_at: Instant,
    previous: Option<PreviousPhase>,
}

impl ProtectedSession {
    pub fn new(session_id: SessionId, key_phase: u32, keys: SessionKeys) -> Self {
        Self {
            session_id,
            key_phase,
            next_send_sequence: 0,
            receive_replay: ReplayWindow::default(),
            keys,
            created_at: Instant::now(),
            previous: None,
        }
    }

    pub fn inherit_previous(&mut self, previous: &ProtectedSession) {
        if previous.session_id == self.session_id && previous.key_phase < self.key_phase {
            self.previous = Some(PreviousPhase {
                key_phase: previous.key_phase,
                keys: previous.keys.clone(),
                replay: previous.receive_replay.clone(),
                expires_at: Instant::now() + Duration::from_secs(15),
            });
        }
    }

    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub const fn key_phase(&self) -> u32 {
        self.key_phase
    }

    pub fn should_rekey(&self, packet_limit: u64) -> bool {
        (packet_limit > 0 && self.next_send_sequence >= packet_limit)
            || self.created_at.elapsed() >= Duration::from_secs(120)
    }

    pub fn should_rekey_with_policy(
        &self,
        packet_limit: u64,
        time_limit: Option<Duration>,
    ) -> bool {
        (packet_limit > 0 && self.next_send_sequence >= packet_limit)
            || time_limit.is_some_and(|limit| self.created_at.elapsed() >= limit)
    }

    pub fn seal(&mut self, kind: PacketKind, plaintext: &[u8]) -> Result<Packet, SessionError> {
        if kind == PacketKind::Handshake {
            return Err(SessionError::HandshakeNotProtected);
        }
        if self.next_send_sequence == u64::MAX {
            return Err(SessionError::SequenceExhausted);
        }
        let header = Header {
            kind,
            key_phase: self.key_phase,
            sequence: self.next_send_sequence,
            session_id: self.session_id,
        };
        let payload = self.keys.seal(
            PacketNonce::from_sequence(header.key_phase, header.sequence),
            &header.encode(),
            plaintext,
        )?;
        self.next_send_sequence += 1;
        Ok(Packet { header, payload })
    }

    pub fn open(&mut self, packet: Packet) -> Result<Bytes, SessionError> {
        if packet.header.kind == PacketKind::Handshake {
            return Err(SessionError::HandshakeNotProtected);
        }
        if packet.header.session_id != self.session_id {
            return Err(SessionError::UnexpectedSession);
        }
        if packet.header.key_phase != self.key_phase {
            if let Some(prev) = &mut self.previous {
                if prev.key_phase == packet.header.key_phase && Instant::now() <= prev.expires_at {
                    let plaintext = prev.keys.open(
                        PacketNonce::from_sequence(packet.header.key_phase, packet.header.sequence),
                        &packet.header.encode(),
                        &packet.payload,
                    )?;
                    prev.replay.check_and_record(packet.header.sequence)?;
                    return Ok(plaintext);
                }
            }
            return Err(SessionError::UnexpectedKeyPhase(packet.header.key_phase));
        }
        let plaintext = self.keys.open(
            PacketNonce::from_sequence(packet.header.key_phase, packet.header.sequence),
            &packet.header.encode(),
            &packet.payload,
        )?;
        self.receive_replay
            .check_and_record(packet.header.sequence)?;
        Ok(plaintext)
    }
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("handshake packets are not handled by an established session")]
    HandshakeNotProtected,
    #[error("send sequence is exhausted; rekey before sending more packets")]
    SequenceExhausted,
    #[error("packet belongs to a different session")]
    UnexpectedSession,
    #[error("packet key phase {0} is not active")]
    UnexpectedKeyPhase(u32),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Replay(#[from] ReplayError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvpn_crypto::{EphemeralKeyPair, SessionRole};

    fn pair() -> (ProtectedSession, ProtectedSession) {
        let initiator = EphemeralKeyPair::generate().unwrap();
        let responder = EphemeralKeyPair::generate().unwrap();
        let initiator_public = initiator.public_key();
        let responder_public = responder.public_key();
        let send = SessionKeys::derive(
            initiator.agree(responder_public).unwrap(),
            &[8; 32],
            SessionRole::Initiator,
        )
        .unwrap();
        let receive = SessionKeys::derive(
            responder.agree(initiator_public).unwrap(),
            &[8; 32],
            SessionRole::Responder,
        )
        .unwrap();
        let session_id = SessionId::new([4; 16]);
        (
            ProtectedSession::new(session_id, 0, send),
            ProtectedSession::new(session_id, 0, receive),
        )
    }

    #[test]
    fn configured_rekey_policy_honors_time_limit_without_packet_limit() {
        let (session, _) = pair();
        assert!(session.should_rekey_with_policy(0, Some(Duration::ZERO)));
        assert!(!session.should_rekey_with_policy(0, None));
    }

    #[test]
    fn configured_packet_rekey_policy_is_independent_of_hardcoded_time() {
        let (mut sender, _) = pair();
        assert!(!sender.should_rekey_with_policy(2, None));
        sender.seal(PacketKind::Data, b"one").unwrap();
        assert!(!sender.should_rekey_with_policy(2, None));
        sender.seal(PacketKind::Data, b"two").unwrap();
        assert!(sender.should_rekey_with_policy(2, None));
    }

    #[test]
    fn protects_packets_and_rejects_replays() {
        let (mut sender, mut receiver) = pair();
        let packet = sender.seal(PacketKind::Data, b"ip packet").unwrap();
        assert_eq!(receiver.open(packet.clone()).unwrap(), b"ip packet"[..]);
        assert!(matches!(
            receiver.open(packet),
            Err(SessionError::Replay(ReplayError::Duplicate))
        ));
    }

    #[test]
    fn forged_packet_does_not_consume_a_replay_sequence() {
        let (mut sender, mut receiver) = pair();
        let packet = sender.seal(PacketKind::Data, b"packet").unwrap();
        let mut forged = packet.clone();
        forged.payload = Bytes::from_static(b"bad tag");
        assert!(matches!(
            receiver.open(forged),
            Err(SessionError::Crypto(CryptoError::AuthenticationFailed))
        ));
        assert_eq!(receiver.open(packet).unwrap(), b"packet"[..]);
    }
}
