//! Coordination of protocol framing with cryptographic packet protection.

use crate::{Header, Packet, PacketKind, ProtocolError, ReplayError, ReplayWindow};
use bytes::Bytes;
use rvpn_core::SessionId;
use rvpn_crypto::{CryptoError, PacketNonce, SessionKeys};
use thiserror::Error;

/// One established packet-protection phase for a known RVPN session.
///
/// A caller may construct this only after its handshake has authenticated peers
/// and bound the transcript used to derive `keys`. Handshake packets themselves
/// are intentionally not accepted by this post-handshake packet protector.
pub struct ProtectedSession {
    session_id: SessionId,
    key_phase: u32,
    next_send_sequence: u64,
    receive_replay: ReplayWindow,
    keys: SessionKeys,
}

impl ProtectedSession {
    /// Creates a packet-protection session at the supplied negotiated key phase.
    pub fn new(session_id: SessionId, key_phase: u32, keys: SessionKeys) -> Self {
        Self {
            session_id,
            key_phase,
            next_send_sequence: 0,
            receive_replay: ReplayWindow::default(),
            keys,
        }
    }

    /// Returns the session identifier authenticated in every protected header.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Encrypts a post-handshake payload and binds its header as AEAD AAD.
    pub fn seal(&mut self, kind: PacketKind, plaintext: &[u8]) -> Result<Packet, SessionError> {
        if kind == PacketKind::Handshake {
            return Err(SessionError::HandshakeNotProtected);
        }
        // A rekey must occur before the counter wraps. Reserving the all-ones
        // value gives the next phase a clear boundary and prevents nonce reuse.
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

    /// Authenticates, decrypts, then replay-checks a packet for this session.
    ///
    /// Authentication intentionally precedes marking the replay window: forged
    /// packets must not advance the window or cause a denial of legitimate data.
    pub fn open(&mut self, packet: Packet) -> Result<Bytes, SessionError> {
        if packet.header.kind == PacketKind::Handshake {
            return Err(SessionError::HandshakeNotProtected);
        }
        if packet.header.session_id != self.session_id {
            return Err(SessionError::UnexpectedSession);
        }
        if packet.header.key_phase != self.key_phase {
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

/// Errors that join packet framing, authentication, and replay policy.
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
