use crate::ProtocolError;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rvpn_core::SessionId;
use rvpn_crypto::Mac1Key;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const RANDOM_LEN: usize = 32;
pub const SIGNATURE_PROOF_LEN: usize = 64;
pub const CERTIFICATE_LEN: usize = 112;
pub const COOKIE_LEN: usize = 32;
pub const MAC1_LEN: usize = 16;

pub const PROOF_BODY_LEN: usize = 1 + CERTIFICATE_LEN + SIGNATURE_PROOF_LEN; // 177
pub const SEALED_PROOF_LEN: usize = PROOF_BODY_LEN + 16; // 193

pub const INITIATION_LEN: usize = 1 + PUBLIC_KEY_LEN + RANDOM_LEN + 1 + COOKIE_LEN + MAC1_LEN; // 114
pub const RESPONSE_PUBLIC_LEN: usize = 1 + PUBLIC_KEY_LEN + RANDOM_LEN + SessionId::LENGTH; // 81
pub const RESPONSE_LEN: usize = RESPONSE_PUBLIC_LEN + SEALED_PROOF_LEN; // 274
pub const FINISH_LEN: usize = 1 + SEALED_PROOF_LEN; // 194
pub const COOKIE_REPLY_LEN: usize = 1 + COOKIE_LEN; // 33

pub const SERVER_AUTH_DOMAIN: &[u8] = b"rvpn-v3/handshake/server";
pub const CLIENT_AUTH_DOMAIN: &[u8] = b"rvpn-v3/handshake/client";
pub const TRANSCRIPT_DOMAIN: &[u8] = b"rvpn-v3/handshake/transcript";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthProof {
    PinnedKey([u8; SIGNATURE_PROOF_LEN]),
    Certificate {
        certificate: [u8; CERTIFICATE_LEN],
        signature: [u8; SIGNATURE_PROOF_LEN],
    },
}

impl AuthProof {
    pub const fn tag(&self) -> u8 {
        match self {
            Self::PinnedKey(_) => 0,
            Self::Certificate { .. } => 1,
        }
    }

    pub fn encode_body(&self) -> [u8; PROOF_BODY_LEN] {
        let mut body = [0u8; PROOF_BODY_LEN];
        body[0] = self.tag();
        match self {
            Self::PinnedKey(sig) => {
                body[1..1 + SIGNATURE_PROOF_LEN].copy_from_slice(sig);
            }
            Self::Certificate {
                certificate,
                signature,
            } => {
                body[1..1 + CERTIFICATE_LEN].copy_from_slice(certificate);
                body[1 + CERTIFICATE_LEN..1 + CERTIFICATE_LEN + SIGNATURE_PROOF_LEN]
                    .copy_from_slice(signature);
            }
        }
        body
    }

    pub fn decode_body(bytes: &[u8; PROOF_BODY_LEN]) -> Result<Self, ProtocolError> {
        match bytes[0] {
            0 => {
                let mut sig = [0u8; SIGNATURE_PROOF_LEN];
                sig.copy_from_slice(&bytes[1..1 + SIGNATURE_PROOF_LEN]);
                Ok(Self::PinnedKey(sig))
            }
            1 => {
                let mut certificate = [0u8; CERTIFICATE_LEN];
                let mut signature = [0u8; SIGNATURE_PROOF_LEN];
                certificate.copy_from_slice(&bytes[1..1 + CERTIFICATE_LEN]);
                signature.copy_from_slice(
                    &bytes[1 + CERTIFICATE_LEN..1 + CERTIFICATE_LEN + SIGNATURE_PROOF_LEN],
                );
                Ok(Self::Certificate {
                    certificate,
                    signature,
                })
            }
            _ => Err(ProtocolError::InvalidHandshake),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeMessage {
    Initiation {
        public_key: [u8; PUBLIC_KEY_LEN],
        random: [u8; RANDOM_LEN],
        cookie: Option<[u8; COOKIE_LEN]>,
        mac1: [u8; MAC1_LEN],
    },
    Response {
        public_key: [u8; PUBLIC_KEY_LEN],
        random: [u8; RANDOM_LEN],
        session_id: SessionId,
        sealed_proof: [u8; SEALED_PROOF_LEN],
    },
    Finish {
        sealed_proof: [u8; SEALED_PROOF_LEN],
    },
    CookieReply {
        cookie: [u8; COOKIE_LEN],
    },
}

impl HandshakeMessage {
    pub fn mac1_input(
        public_key: &[u8; PUBLIC_KEY_LEN],
        random: &[u8; RANDOM_LEN],
        cookie: Option<&[u8; COOKIE_LEN]>,
    ) -> [u8; 1 + PUBLIC_KEY_LEN + RANDOM_LEN + 1 + COOKIE_LEN] {
        let mut input = [0u8; 1 + PUBLIC_KEY_LEN + RANDOM_LEN + 1 + COOKIE_LEN];
        input[0] = 1;
        input[1..1 + PUBLIC_KEY_LEN].copy_from_slice(public_key);
        input[1 + PUBLIC_KEY_LEN..1 + PUBLIC_KEY_LEN + RANDOM_LEN].copy_from_slice(random);
        match cookie {
            Some(cookie) => {
                input[1 + PUBLIC_KEY_LEN + RANDOM_LEN] = 1;
                input[1 + PUBLIC_KEY_LEN + RANDOM_LEN + 1..].copy_from_slice(cookie);
            }
            None => {
                input[1 + PUBLIC_KEY_LEN + RANDOM_LEN] = 0;
            }
        }
        input
    }

    pub fn compute_mac1(
        key: &Mac1Key,
        public_key: &[u8; PUBLIC_KEY_LEN],
        random: &[u8; RANDOM_LEN],
        cookie: Option<&[u8; COOKIE_LEN]>,
    ) -> [u8; MAC1_LEN] {
        let input = Self::mac1_input(public_key, random, cookie);
        key.compute(&input)
    }

    pub fn verify_mac1(&self, key: &Mac1Key) -> bool {
        match self {
            Self::Initiation {
                public_key,
                random,
                cookie,
                mac1,
            } => {
                let input = Self::mac1_input(public_key, random, cookie.as_ref());
                key.verify(&input, mac1)
            }
            _ => false,
        }
    }

    pub fn response_public_bytes(
        public_key: &[u8; PUBLIC_KEY_LEN],
        random: &[u8; RANDOM_LEN],
        session_id: SessionId,
    ) -> [u8; RESPONSE_PUBLIC_LEN] {
        let mut bytes = [0u8; RESPONSE_PUBLIC_LEN];
        bytes[0] = 2;
        bytes[1..1 + PUBLIC_KEY_LEN].copy_from_slice(public_key);
        bytes[1 + PUBLIC_KEY_LEN..1 + PUBLIC_KEY_LEN + RANDOM_LEN].copy_from_slice(random);
        bytes[1 + PUBLIC_KEY_LEN + RANDOM_LEN..].copy_from_slice(&session_id.into_bytes());
        bytes
    }

    pub fn encode(self) -> Bytes {
        match self {
            Self::Initiation {
                public_key,
                random,
                cookie,
                mac1,
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
                output.extend_from_slice(&mac1);
                output.freeze()
            }
            Self::Response {
                public_key,
                random,
                session_id,
                sealed_proof,
            } => {
                let mut output = BytesMut::with_capacity(RESPONSE_LEN);
                output.put_u8(2);
                output.extend_from_slice(&public_key);
                output.extend_from_slice(&random);
                output.extend_from_slice(&session_id.into_bytes());
                output.extend_from_slice(&sealed_proof);
                output.freeze()
            }
            Self::Finish { sealed_proof } => {
                let mut output = BytesMut::with_capacity(FINISH_LEN);
                output.put_u8(3);
                output.extend_from_slice(&sealed_proof);
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
                let mut mac1 = [0; MAC1_LEN];
                input.copy_to_slice(&mut mac1);
                Ok(Self::Initiation {
                    public_key,
                    random,
                    cookie,
                    mac1,
                })
            }
            2 => {
                if input.remaining() != RESPONSE_LEN {
                    return Err(ProtocolError::InvalidHandshake);
                }
                input.advance(1);
                let mut public_key = [0; PUBLIC_KEY_LEN];
                let mut random = [0; RANDOM_LEN];
                input.copy_to_slice(&mut public_key);
                input.copy_to_slice(&mut random);
                let mut session_id = [0; SessionId::LENGTH];
                input.copy_to_slice(&mut session_id);
                let mut sealed_proof = [0; SEALED_PROOF_LEN];
                input.copy_to_slice(&mut sealed_proof);
                Ok(Self::Response {
                    public_key,
                    random,
                    session_id: SessionId::new(session_id),
                    sealed_proof,
                })
            }
            3 => {
                if input.remaining() != FINISH_LEN {
                    return Err(ProtocolError::InvalidHandshake);
                }
                input.advance(1);
                let mut sealed_proof = [0; SEALED_PROOF_LEN];
                input.copy_to_slice(&mut sealed_proof);
                Ok(Self::Finish { sealed_proof })
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeTranscript {
    initiation: HandshakeMessage,
    response: Option<HandshakeMessage>,
}

impl HandshakeTranscript {
    pub fn new(initiation: HandshakeMessage) -> Result<Self, ProtocolError> {
        if !matches!(initiation, HandshakeMessage::Initiation { .. }) {
            return Err(ProtocolError::InvalidHandshake);
        }
        Ok(Self {
            initiation,
            response: None,
        })
    }

    pub const fn initiation(&self) -> HandshakeMessage {
        self.initiation
    }

    pub fn response(&self) -> Option<HandshakeMessage> {
        self.response
    }

    pub fn server_authentication_input(
        &self,
        public_key: [u8; PUBLIC_KEY_LEN],
        random: [u8; RANDOM_LEN],
        session_id: SessionId,
    ) -> Result<Bytes, ProtocolError> {
        let response_public =
            HandshakeMessage::response_public_bytes(&public_key, &random, session_id);
        Ok(join(
            SERVER_AUTH_DOMAIN,
            &[
                self.initiation.encode(),
                Bytes::copy_from_slice(&response_public),
            ],
        ))
    }

    pub fn set_response(&mut self, response: HandshakeMessage) -> Result<(), ProtocolError> {
        if !matches!(response, HandshakeMessage::Response { .. }) {
            return Err(ProtocolError::InvalidHandshake);
        }
        self.response = Some(response);
        Ok(())
    }

    pub fn client_authentication_input(&self) -> Result<Bytes, ProtocolError> {
        let response = self
            .response
            .as_ref()
            .ok_or(ProtocolError::InvalidHandshake)?;
        Ok(join(
            CLIENT_AUTH_DOMAIN,
            &[self.initiation.encode(), response.encode()],
        ))
    }

    pub fn final_bytes(&self, finish: HandshakeMessage) -> Result<Bytes, ProtocolError> {
        if !matches!(finish, HandshakeMessage::Finish { .. }) {
            return Err(ProtocolError::InvalidHandshake);
        }
        let response = self
            .response
            .as_ref()
            .ok_or(ProtocolError::InvalidHandshake)?;
        Ok(join(
            TRANSCRIPT_DOMAIN,
            &[self.initiation.encode(), response.encode(), finish.encode()],
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

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
            mac1: [3; 16],
        };
        let response = HandshakeMessage::Response {
            public_key: [4; 32],
            random: [5; 32],
            session_id: SessionId::new([6; 16]),
            sealed_proof: [7; SEALED_PROOF_LEN],
        };
        let finish = HandshakeMessage::Finish {
            sealed_proof: [8; SEALED_PROOF_LEN],
        };

        assert_eq!(
            HandshakeMessage::decode(initiation.encode()).unwrap(),
            initiation
        );
        assert!(HandshakeMessage::decode(Bytes::from_static(&[1; 64])).is_err());

        let mut transcript = HandshakeTranscript::new(initiation).unwrap();
        assert!(
            !transcript
                .server_authentication_input([4; 32], [5; 32], SessionId::new([6; 16]))
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
    fn exact_wire_lengths_from_d5() {
        assert_eq!(INITIATION_LEN, 114);
        assert_eq!(RESPONSE_LEN, 274);
        assert_eq!(FINISH_LEN, 194);
        assert_eq!(PROOF_BODY_LEN, 177);
        assert_eq!(SEALED_PROOF_LEN, 193);

        let initiation = HandshakeMessage::Initiation {
            public_key: [1; 32],
            random: [2; 32],
            cookie: None,
            mac1: [3; 16],
        };
        let response = HandshakeMessage::Response {
            public_key: [4; 32],
            random: [5; 32],
            session_id: SessionId::new([6; 16]),
            sealed_proof: [7; SEALED_PROOF_LEN],
        };
        let finish = HandshakeMessage::Finish {
            sealed_proof: [8; SEALED_PROOF_LEN],
        };

        assert_eq!(initiation.encode().len(), 114);
        assert_eq!(response.encode().len(), 274);
        assert_eq!(finish.encode().len(), 194);
    }

    #[test]
    fn proof_body_encode_decode_round_trip() {
        let pinned = AuthProof::PinnedKey([42; SIGNATURE_PROOF_LEN]);
        let body = pinned.encode_body();
        assert_eq!(body.len(), PROOF_BODY_LEN);
        assert_eq!(body[0], 0);
        let decoded_pinned = AuthProof::decode_body(&body).unwrap();
        assert_eq!(decoded_pinned, pinned);

        let cert = AuthProof::Certificate {
            certificate: [7; CERTIFICATE_LEN],
            signature: [9; SIGNATURE_PROOF_LEN],
        };
        let body_cert = cert.encode_body();
        assert_eq!(body_cert.len(), PROOF_BODY_LEN);
        assert_eq!(body_cert[0], 1);
        let decoded_cert = AuthProof::decode_body(&body_cert).unwrap();
        assert_eq!(decoded_cert, cert);
    }
}
