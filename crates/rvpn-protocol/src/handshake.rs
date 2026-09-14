//! Authenticated-handshake message framing and state ordering.

use crate::ProtocolError;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rvpn_core::SessionId;

const PUBLIC_KEY_LEN: usize = 32;
const RANDOM_LEN: usize = 32;
const PSK_PROOF_LEN: usize = 32;
const SIGNATURE_PROOF_LEN: usize = 64;
const CERTIFICATE_LEN: usize = 112;
const CERTIFICATE_PROOF_LEN: usize = CERTIFICATE_LEN + SIGNATURE_PROOF_LEN;
const COOKIE_LEN: usize = 32;
const INITIATION_LEN: usize = 1 + PUBLIC_KEY_LEN + RANDOM_LEN + 1 + COOKIE_LEN;
const COOKIE_REPLY_LEN: usize = 1 + COOKIE_LEN;
const SERVER_AUTH_DOMAIN: &[u8] = b"rvpn-v1/handshake/server";
const CLIENT_AUTH_DOMAIN: &[u8] = b"rvpn-v1/handshake/client";

/// Authentication proof carried in a `Response` or `Finish` message. Variable
/// length and self-describing via a leading tag byte, so it isn't tied to
/// any single authentication mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthProof {
    /// HMAC-SHA-256 tag under a pre-shared key.
    Psk([u8; PSK_PROOF_LEN]),
    /// Ed25519 signature under a pinned long-term public key.
    PinnedKey([u8; SIGNATURE_PROOF_LEN]),
    /// Ed25519 signature plus the certificate that authorizes the signing key.
    Certificate {
        certificate: [u8; CERTIFICATE_LEN],
        signature: [u8; SIGNATURE_PROOF_LEN],
    },
}

impl AuthProof {
    fn tag(&self) -> u8 {
        match self {
            Self::Psk(_) => 0,
            Self::PinnedKey(_) => 1,
            Self::Certificate { .. } => 2,
        }
    }

    fn encoded_len(&self) -> usize {
        1 + match self {
            Self::Psk(_) => PSK_PROOF_LEN,
            Self::PinnedKey(_) => SIGNATURE_PROOF_LEN,
            Self::Certificate { .. } => CERTIFICATE_PROOF_LEN,
        }
    }

    fn encode_into(&self, out: &mut BytesMut) {
        out.put_u8(self.tag());
        match self {
            Self::Psk(tag) => out.extend_from_slice(tag),
            Self::PinnedKey(sig) => out.extend_from_slice(sig),
            Self::Certificate {
                certificate,
                signature,
            } => {
                out.extend_from_slice(certificate);
                out.extend_from_slice(signature);
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let (&tag, rest) = bytes.split_first().ok_or(ProtocolError::InvalidHandshake)?;
        match (tag, rest.len()) {
            (0, PSK_PROOF_LEN) => {
                let mut out = [0; PSK_PROOF_LEN];
                out.copy_from_slice(rest);
                Ok(Self::Psk(out))
            }
            (1, SIGNATURE_PROOF_LEN) => {
                let mut out = [0; SIGNATURE_PROOF_LEN];
                out.copy_from_slice(rest);
                Ok(Self::PinnedKey(out))
            }
            (2, CERTIFICATE_PROOF_LEN) => {
                let mut certificate = [0; CERTIFICATE_LEN];
                let mut signature = [0; SIGNATURE_PROOF_LEN];
                certificate.copy_from_slice(&rest[..CERTIFICATE_LEN]);
                signature.copy_from_slice(&rest[CERTIFICATE_LEN..]);
                Ok(Self::Certificate {
                    certificate,
                    signature,
                })
            }
            _ => Err(ProtocolError::InvalidHandshake),
        }
    }

    /// A zero-filled proof of the same shape, used to compute the bytes a
    /// signer/HMAC must cover before the real proof exists.
    pub(crate) fn placeholder(tag: u8) -> Self {
        match tag {
            0 => Self::Psk([0; PSK_PROOF_LEN]),
            1 => Self::PinnedKey([0; SIGNATURE_PROOF_LEN]),
            2 => Self::Certificate {
                certificate: [0; CERTIFICATE_LEN],
                signature: [0; SIGNATURE_PROOF_LEN],
            },
            _ => unreachable!("tag values are only ever produced by this module"),
        }
    }

    pub(crate) fn zeroed(&self) -> Self {
        Self::placeholder(self.tag())
    }
}

/// First, second, and final message of the PSK-, pinned-key-, or
/// certificate-authenticated ephemeral handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeMessage {
    /// Client's unauthenticated ephemeral public key and random value.
    Initiation {
        public_key: [u8; PUBLIC_KEY_LEN],
        random: [u8; RANDOM_LEN],
        cookie: Option<[u8; COOKIE_LEN]>,
    },
    /// Server response authenticated over the initiation and response fields.
    Response {
        public_key: [u8; PUBLIC_KEY_LEN],
        random: [u8; RANDOM_LEN],
        session_id: SessionId,
        proof: AuthProof,
    },
    /// Client confirmation authenticated over the complete prior transcript.
    Finish {
        proof: AuthProof,
    },
    CookieReply {
        cookie: [u8; COOKIE_LEN],
    },
}

impl HandshakeMessage {
    /// Encodes one strict, self-delimiting handshake message.
    pub fn encode(self) -> Bytes {
        match self {
            Self::Initiation {
                public_key,
                random,
                cookie,
            } => {
                let mut output = BytesMut::with_capacity(INITIATION_LEN);
                output.put_u8(1);
                output.extend_from_slice(&public_key);
                output.extend_from_slice(&random);
                match cookie {
                    Some(cookie) => {
                        output.put_u8(1);
                        output.extend_from_slice(&cookie);
                    }
                    None => {
                        output.put_u8(0);
                        output.extend_from_slice(&[0; COOKIE_LEN]);
                    }
                }
                output.freeze()
            }
            Self::Response {
                public_key,
                random,
                session_id,
                proof,
            } => {
                let mut output = BytesMut::with_capacity(
                    1 + PUBLIC_KEY_LEN + RANDOM_LEN + SessionId::LENGTH + proof.encoded_len(),
                );
                output.put_u8(2);
                output.extend_from_slice(&public_key);
                output.extend_from_slice(&random);
                output.extend_from_slice(&session_id.into_bytes());
                proof.encode_into(&mut output);
                output.freeze()
            }
            Self::Finish { proof } => {
                let mut output = BytesMut::with_capacity(1 + proof.encoded_len());
                output.put_u8(3);
                proof.encode_into(&mut output);
                output.freeze()
            }
            Self::CookieReply { cookie } => {
                let mut output = BytesMut::with_capacity(COOKIE_REPLY_LEN);
                output.put_u8(4);
                output.extend_from_slice(&cookie);
                output.freeze()
            }
        }
    }

    /// Parses exactly one handshake message; trailing bytes are forbidden.
    pub fn decode(mut input: Bytes) -> Result<Self, ProtocolError> {
        let kind = *input.first().ok_or(ProtocolError::InvalidHandshake)?;
        match kind {
            1 => {
                if input.remaining() != INITIATION_LEN {
                    return Err(ProtocolError::InvalidHandshake);
                }
                input.advance(1);
                let mut public_key = [0; PUBLIC_KEY_LEN];
                let mut random = [0; RANDOM_LEN];
                input.copy_to_slice(&mut public_key);
                input.copy_to_slice(&mut random);
                let has_cookie = input.get_u8();
                let mut cookie_bytes = [0; COOKIE_LEN];
                input.copy_to_slice(&mut cookie_bytes);
                let cookie = (has_cookie == 1).then_some(cookie_bytes);
                Ok(Self::Initiation {
                    public_key,
                    random,
                    cookie,
                })
            }
            2 => {
                const FIXED: usize = 1 + PUBLIC_KEY_LEN + RANDOM_LEN + SessionId::LENGTH;
                if input.remaining() < FIXED {
                    return Err(ProtocolError::InvalidHandshake);
                }
                input.advance(1);
                let mut public_key = [0; PUBLIC_KEY_LEN];
                let mut random = [0; RANDOM_LEN];
                input.copy_to_slice(&mut public_key);
                input.copy_to_slice(&mut random);
                let mut session_id = [0; SessionId::LENGTH];
                input.copy_to_slice(&mut session_id);
                let proof = AuthProof::decode(&input)?;
                Ok(Self::Response {
                    public_key,
                    random,
                    session_id: SessionId::new(session_id),
                    proof,
                })
            }
            3 => {
                input.advance(1);
                let proof = AuthProof::decode(&input)?;
                Ok(Self::Finish { proof })
            }
            4 => {
                if input.remaining() != COOKIE_REPLY_LEN {
                    return Err(ProtocolError::InvalidHandshake);
                }
                input.advance(1);
                let mut cookie = [0; COOKIE_LEN];
                input.copy_to_slice(&mut cookie);
                Ok(Self::CookieReply { cookie })
            }
            _ => Err(ProtocolError::InvalidHandshake),
        }
    }
}

/// Canonical byte inputs for authentication and transcript hashing.
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
                proof: AuthProof::Psk([0; PSK_PROOF_LEN]),
            },
        })
    }

    /// Returns the canonical first handshake message.
    pub const fn initiation(&self) -> HandshakeMessage {
        self.initiation
    }

    /// Creates the canonical input which a responder must authenticate,
    /// given a response with its proof zeroed to the correct shape.
    pub fn server_authentication_input(
        &self,
        response_without_tag: HandshakeMessage,
    ) -> Result<Bytes, ProtocolError> {
        let HandshakeMessage::Response {
            public_key,
            random,
            session_id,
            proof,
        } = response_without_tag
        else {
            return Err(ProtocolError::InvalidHandshake);
        };
        let unsigned = HandshakeMessage::Response {
            public_key,
            random,
            session_id,
            proof: proof.zeroed(),
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

    /// Creates the canonical input which a client must authenticate.
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
            cookie: None,
        };
        let response = HandshakeMessage::Response {
            public_key: [3; 32],
            random: [4; 32],
            session_id: SessionId::new([5; 16]),
            proof: AuthProof::Psk([6; 32]),
        };
        let finish = HandshakeMessage::Finish {
            proof: AuthProof::Psk([7; 32]),
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

    #[test]
    fn certificate_proof_round_trips_through_encode_decode() {
        let response = HandshakeMessage::Response {
            public_key: [1; 32],
            random: [2; 32],
            session_id: SessionId::new([3; 16]),
            proof: AuthProof::Certificate {
                certificate: [9; CERTIFICATE_LEN],
                signature: [8; SIGNATURE_PROOF_LEN],
            },
        };
        assert_eq!(
            HandshakeMessage::decode(response.encode()).unwrap(),
            response
        );
    }
}
