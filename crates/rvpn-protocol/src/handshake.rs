//! Authenticated-handshake message framing and state ordering.

use crate::ProtocolError;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rvpn_core::SessionId;

const PUBLIC_KEY_LEN: usize = 32;
const RANDOM_LEN: usize = 32;
const AUTH_TAG_LEN: usize = 32;
const INITIATION_LEN: usize = 1 + PUBLIC_KEY_LEN + RANDOM_LEN;
const RESPONSE_LEN: usize = 1 + PUBLIC_KEY_LEN + RANDOM_LEN + SessionId::LENGTH + AUTH_TAG_LEN;
const FINISH_LEN: usize = 1 + AUTH_TAG_LEN;
const SERVER_AUTH_DOMAIN: &[u8] = b"rvpn-v1/handshake/server";
const CLIENT_AUTH_DOMAIN: &[u8] = b"rvpn-v1/handshake/client";

/// First, second, and final message of the PSK-authenticated ephemeral handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeMessage {
    /// Client's unauthenticated ephemeral public key and random value.
    Initiation {
        public_key: [u8; PUBLIC_KEY_LEN],
        random: [u8; RANDOM_LEN],
    },
    /// Server response authenticated over the initiation and response fields.
    Response {
        public_key: [u8; PUBLIC_KEY_LEN],
        random: [u8; RANDOM_LEN],
        session_id: SessionId,
        authenticator: [u8; AUTH_TAG_LEN],
    },
    /// Client confirmation authenticated over the complete prior transcript.
    Finish { authenticator: [u8; AUTH_TAG_LEN] },
}

impl HandshakeMessage {
    /// Encodes one strict, self-delimiting handshake message.
    pub fn encode(self) -> Bytes {
        let capacity = match self {
            Self::Initiation { .. } => INITIATION_LEN,
            Self::Response { .. } => RESPONSE_LEN,
            Self::Finish { .. } => FINISH_LEN,
        };
        let mut output = BytesMut::with_capacity(capacity);
        match self {
            Self::Initiation { public_key, random } => {
                output.put_u8(1);
                output.extend_from_slice(&public_key);
                output.extend_from_slice(&random);
            }
            Self::Response {
                public_key,
                random,
                session_id,
                authenticator,
            } => {
                output.put_u8(2);
                output.extend_from_slice(&public_key);
                output.extend_from_slice(&random);
                output.extend_from_slice(&session_id.into_bytes());
                output.extend_from_slice(&authenticator);
            }
            Self::Finish { authenticator } => {
                output.put_u8(3);
                output.extend_from_slice(&authenticator);
            }
        }
        output.freeze()
    }

    /// Parses exactly one handshake message; trailing bytes are forbidden.
    pub fn decode(mut input: Bytes) -> Result<Self, ProtocolError> {
        let kind = *input.first().ok_or(ProtocolError::InvalidHandshake)?;
        let expected = match kind {
            1 => INITIATION_LEN,
            2 => RESPONSE_LEN,
            3 => FINISH_LEN,
            _ => return Err(ProtocolError::InvalidHandshake),
        };
        if input.remaining() != expected {
            return Err(ProtocolError::InvalidHandshake);
        }
        input.advance(1);
        let mut public_key = [0; PUBLIC_KEY_LEN];
        let mut random = [0; RANDOM_LEN];
        match kind {
            1 => {
                input.copy_to_slice(&mut public_key);
                input.copy_to_slice(&mut random);
                Ok(Self::Initiation { public_key, random })
            }
            2 => {
                input.copy_to_slice(&mut public_key);
                input.copy_to_slice(&mut random);
                let mut session_id = [0; SessionId::LENGTH];
                input.copy_to_slice(&mut session_id);
                let mut authenticator = [0; AUTH_TAG_LEN];
                input.copy_to_slice(&mut authenticator);
                Ok(Self::Response {
                    public_key,
                    random,
                    session_id: SessionId::new(session_id),
                    authenticator,
                })
            }
            3 => {
                let mut authenticator = [0; AUTH_TAG_LEN];
                input.copy_to_slice(&mut authenticator);
                Ok(Self::Finish { authenticator })
            }
            _ => unreachable!(),
        }
    }
}

/// Canonical byte inputs for PSK authentication and transcript hashing.
///
/// Constructing these internally prevents a client and server from accidentally
/// authenticating different field subsets or message encodings.
pub struct HandshakeTranscript {
    initiation: HandshakeMessage,
    response: HandshakeMessage,
}

impl HandshakeTranscript {
    /// Starts a transcript after parsing or constructing an initiation.
    pub fn new(initiation: HandshakeMessage) -> Result<Self, ProtocolError> {
        if !matches!(initiation, HandshakeMessage::Initiation { .. }) {
            return Err(ProtocolError::InvalidHandshake);
        }
        Ok(Self {
            initiation,
            response: HandshakeMessage::Finish {
                authenticator: [0; AUTH_TAG_LEN],
            },
        })
    }

    /// Returns the canonical first handshake message.
    pub const fn initiation(&self) -> HandshakeMessage {
        self.initiation
    }

    /// Creates the canonical input which a server must PSK-authenticate.
    pub fn server_authentication_input(
        &self,
        response_without_tag: HandshakeMessage,
    ) -> Result<Bytes, ProtocolError> {
        let HandshakeMessage::Response {
            public_key,
            random,
            session_id,
            ..
        } = response_without_tag
        else {
            return Err(ProtocolError::InvalidHandshake);
        };
        let unsigned = HandshakeMessage::Response {
            public_key,
            random,
            session_id,
            authenticator: [0; AUTH_TAG_LEN],
        };
        Ok(join(
            SERVER_AUTH_DOMAIN,
            &[self.initiation.encode(), unsigned.encode()],
        ))
    }

    /// Records an authenticated server response for client-finish construction.
    pub fn set_response(&mut self, response: HandshakeMessage) -> Result<(), ProtocolError> {
        if !matches!(response, HandshakeMessage::Response { .. }) {
            return Err(ProtocolError::InvalidHandshake);
        }
        self.response = response;
        Ok(())
    }

    /// Creates the canonical input which a client must PSK-authenticate.
    pub fn client_authentication_input(&self) -> Result<Bytes, ProtocolError> {
        if !matches!(self.response, HandshakeMessage::Response { .. }) {
            return Err(ProtocolError::InvalidHandshake);
        }
        Ok(join(
            CLIENT_AUTH_DOMAIN,
            &[self.initiation.encode(), self.response.encode()],
        ))
    }

    /// Returns the exact final transcript bytes used for session-key derivation.
    pub fn final_bytes(&self, finish: HandshakeMessage) -> Result<Bytes, ProtocolError> {
        if !matches!(finish, HandshakeMessage::Finish { .. }) {
            return Err(ProtocolError::InvalidHandshake);
        }
        Ok(join(
            b"rvpn-v1/handshake/transcript",
            &[
                self.initiation.encode(),
                self.response.encode(),
                finish.encode(),
            ],
        ))
    }
}

fn join(domain: &[u8], parts: &[Bytes]) -> Bytes {
    let capacity = domain.len() + parts.iter().map(Bytes::len).sum::<usize>();
    let mut output = BytesMut::with_capacity(capacity);
    output.extend_from_slice(domain);
    for part in parts {
        output.extend_from_slice(part);
    }
    output.freeze()
}

/// Local endpoint role for legal handshake ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

/// Legal handshake ordering, independent from crypto key ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeState {
    New(HandshakeRole),
    AwaitingResponse,
    AwaitingFinish,
    Established,
}

impl HandshakeState {
    pub const fn new(role: HandshakeRole) -> Self {
        Self::New(role)
    }
    /// Advances after transmitting a legal message.
    pub fn on_send(&mut self, message: HandshakeMessage) -> Result<(), ProtocolError> {
        match (*self, message) {
            (Self::New(HandshakeRole::Initiator), HandshakeMessage::Initiation { .. }) => {
                *self = Self::AwaitingResponse;
                Ok(())
            }
            (Self::AwaitingFinish, HandshakeMessage::Response { .. }) => Ok(()),
            (Self::AwaitingFinish, HandshakeMessage::Finish { .. }) => {
                *self = Self::Established;
                Ok(())
            }
            _ => Err(ProtocolError::InvalidHandshake),
        }
    }
    /// Advances after receiving a legal message.
    pub fn on_receive(&mut self, message: HandshakeMessage) -> Result<(), ProtocolError> {
        match (*self, message) {
            (Self::New(HandshakeRole::Responder), HandshakeMessage::Initiation { .. }) => {
                *self = Self::AwaitingFinish;
                Ok(())
            }
            (Self::AwaitingResponse, HandshakeMessage::Response { .. }) => {
                *self = Self::AwaitingFinish;
                Ok(())
            }
            (Self::AwaitingFinish, HandshakeMessage::Finish { .. }) => {
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
    fn framing_transcript_and_state_order_are_strict() {
        let initiation = HandshakeMessage::Initiation {
            public_key: [1; 32],
            random: [2; 32],
        };
        let response = HandshakeMessage::Response {
            public_key: [3; 32],
            random: [4; 32],
            session_id: SessionId::new([5; 16]),
            authenticator: [6; 32],
        };
        let finish = HandshakeMessage::Finish {
            authenticator: [7; 32],
        };
        assert_eq!(
            HandshakeMessage::decode(initiation.encode()).unwrap(),
            initiation
        );
        assert!(HandshakeMessage::decode(Bytes::from_static(&[1; 64])).is_err());
        let mut transcript = HandshakeTranscript::new(initiation).unwrap();
        assert!(
            !transcript
                .server_authentication_input(response)
                .unwrap()
                .is_empty()
        );
        transcript.set_response(response).unwrap();
        assert!(!transcript.client_authentication_input().unwrap().is_empty());
        assert!(!transcript.final_bytes(finish).unwrap().is_empty());
        let mut initiator = HandshakeState::new(HandshakeRole::Initiator);
        initiator.on_send(initiation).unwrap();
        initiator.on_receive(response).unwrap();
        initiator.on_send(finish).unwrap();
        assert_eq!(initiator, HandshakeState::Established);
        let mut responder = HandshakeState::new(HandshakeRole::Responder);
        responder.on_receive(initiation).unwrap();
        responder.on_send(response).unwrap();
        responder.on_receive(finish).unwrap();
        assert_eq!(responder, HandshakeState::Established);
    }
}
