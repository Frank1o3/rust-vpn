use crate::ProtocolError;
use bytes::{Buf, BufMut, Bytes, BytesMut};

const EPHEMERAL_KEY_LEN: usize = 32;
const HANDSHAKE_LEN: usize = 1 + EPHEMERAL_KEY_LEN;

/// Fixed-size unauthenticated ephemeral handshake messages.
///
/// These messages only carry X25519 public keys. Identity authentication and
/// transcript signatures/MACs are deliberately not claimed or implemented.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeMessage {
    /// First message from the initiator.
    Initiation([u8; EPHEMERAL_KEY_LEN]),
    /// Response from the responder.
    Response([u8; EPHEMERAL_KEY_LEN]),
}

impl HandshakeMessage {
    /// Serializes a fixed-size handshake message.
    pub fn encode(self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(HANDSHAKE_LEN);
        match self {
            Self::Initiation(key) => {
                bytes.put_u8(1);
                bytes.extend_from_slice(&key);
            }
            Self::Response(key) => {
                bytes.put_u8(2);
                bytes.extend_from_slice(&key);
            }
        }
        bytes.freeze()
    }

    /// Decodes exactly one fixed-size handshake message.
    pub fn decode(mut input: Bytes) -> Result<Self, ProtocolError> {
        if input.remaining() != HANDSHAKE_LEN {
            return Err(ProtocolError::InvalidHandshake);
        }
        let kind = input.get_u8();
        let mut key = [0; EPHEMERAL_KEY_LEN];
        input.copy_to_slice(&mut key);
        match kind {
            1 => Ok(Self::Initiation(key)),
            2 => Ok(Self::Response(key)),
            _ => Err(ProtocolError::InvalidHandshake),
        }
    }
}

/// Local handshake role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

/// Legal message-order state only; it contains no key material or identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeState {
    New(HandshakeRole),
    AwaitingResponse,
    AwaitingCompletion,
    Established,
}

impl HandshakeState {
    /// Creates a handshake in its role-specific starting state.
    pub const fn new(role: HandshakeRole) -> Self {
        Self::New(role)
    }

    /// Records a sent handshake message and checks its legal ordering.
    pub fn on_send(&mut self, message: HandshakeMessage) -> Result<(), ProtocolError> {
        match (*self, message) {
            (Self::New(HandshakeRole::Initiator), HandshakeMessage::Initiation(_)) => {
                *self = Self::AwaitingResponse;
                Ok(())
            }
            (Self::AwaitingCompletion, HandshakeMessage::Response(_)) => {
                *self = Self::Established;
                Ok(())
            }
            _ => Err(ProtocolError::InvalidHandshake),
        }
    }

    /// Records a received handshake message and checks its legal ordering.
    pub fn on_receive(&mut self, message: HandshakeMessage) -> Result<(), ProtocolError> {
        match (*self, message) {
            (Self::New(HandshakeRole::Responder), HandshakeMessage::Initiation(_)) => {
                *self = Self::AwaitingCompletion;
                Ok(())
            }
            (Self::AwaitingResponse, HandshakeMessage::Response(_)) => {
                *self = Self::Established;
                Ok(())
            }
            _ => Err(ProtocolError::InvalidHandshake),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_message_order_and_strict_message_length() {
        let init = HandshakeMessage::Initiation([1; 32]);
        let response = HandshakeMessage::Response([2; 32]);
        let mut initiator = HandshakeState::new(HandshakeRole::Initiator);
        initiator.on_send(init).unwrap();
        initiator.on_receive(response).unwrap();
        assert_eq!(initiator, HandshakeState::Established);
        let mut responder = HandshakeState::new(HandshakeRole::Responder);
        responder.on_receive(init).unwrap();
        responder.on_send(response).unwrap();
        assert_eq!(responder, HandshakeState::Established);
        assert!(HandshakeMessage::decode(Bytes::from_static(&[1; 32])).is_err());
    }
}
