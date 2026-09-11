//! Typed orchestration for RVPN's PSK-authenticated ephemeral handshake.

use crate::{HandshakeMessage, HandshakeTranscript, ProtectedSession, ProtocolError};
use rvpn_core::SessionId;
use rvpn_crypto::{
    CryptoError, EphemeralKeyPair, HandshakePsk, PublicKeyBytes, SessionKeys, SessionRole,
    random_bytes, transcript_hash,
};
use thiserror::Error;

/// Initiator state after emitting an initiation message.
pub struct InitiatorHandshake {
    psk: HandshakePsk,
    key_pair: EphemeralKeyPair,
    initiation: HandshakeMessage,
}

/// Responder state after emitting an authenticated response.
pub struct ResponderHandshake {
    psk: HandshakePsk,
    key_pair: EphemeralKeyPair,
    transcript: HandshakeTranscript,
    session_id: SessionId,
}

impl InitiatorHandshake {
    /// Generates and returns the first handshake message.
    pub fn start(psk: HandshakePsk) -> Result<(Self, HandshakeMessage), HandshakeError> {
        let key_pair = EphemeralKeyPair::generate()?;
        let initiation = HandshakeMessage::Initiation {
            public_key: key_pair.public_key().to_bytes(),
            random: random_bytes()?,
        };
        Ok((
            Self {
                psk,
                key_pair,
                initiation,
            },
            initiation,
        ))
    }

    /// Verifies a server response, then returns the client finish and session.
    pub fn finish(
        self,
        response: HandshakeMessage,
    ) -> Result<(HandshakeMessage, ProtectedSession), HandshakeError> {
        let HandshakeMessage::Response {
            public_key,
            session_id,
            authenticator,
            ..
        } = response
        else {
            return Err(HandshakeError::UnexpectedMessage);
        };
        let mut transcript = HandshakeTranscript::new(self.initiation)?;
        let authentication_input = transcript.server_authentication_input(response)?;
        if !self.psk.verify(&authentication_input, &authenticator) {
            return Err(HandshakeError::AuthenticationFailed);
        }
        transcript.set_response(response)?;
        let finish = HandshakeMessage::Finish {
            authenticator: self
                .psk
                .authenticate(&transcript.client_authentication_input()?),
        };
        let keys = SessionKeys::derive(
            self.key_pair.agree(PublicKeyBytes::new(public_key))?,
            &transcript_hash(&transcript.final_bytes(finish)?),
            SessionRole::Initiator,
        )?;
        Ok((finish, ProtectedSession::new(session_id, 0, keys)))
    }
}

impl ResponderHandshake {
    /// Processes an initiation and returns a PSK-authenticated server response.
    pub fn accept(
        psk: HandshakePsk,
        initiation: HandshakeMessage,
    ) -> Result<(Self, HandshakeMessage), HandshakeError> {
        if !matches!(initiation, HandshakeMessage::Initiation { .. }) {
            return Err(HandshakeError::UnexpectedMessage);
        }
        let key_pair = EphemeralKeyPair::generate()?;
        let session_id = SessionId::new(random_bytes()?);
        let mut transcript = HandshakeTranscript::new(initiation)?;
        let unsigned_response = HandshakeMessage::Response {
            public_key: key_pair.public_key().to_bytes(),
            random: random_bytes()?,
            session_id,
            authenticator: [0; 32],
        };
        let response = match unsigned_response {
            HandshakeMessage::Response {
                public_key,
                random,
                session_id,
                ..
            } => HandshakeMessage::Response {
                public_key,
                random,
                session_id,
                authenticator: psk
                    .authenticate(&transcript.server_authentication_input(unsigned_response)?),
            },
            _ => unreachable!(),
        };
        transcript.set_response(response)?;
        Ok((
            Self {
                psk,
                key_pair,
                transcript,
                session_id,
            },
            response,
        ))
    }

    /// Verifies the client finish and returns the established protected session.
    pub fn finish(self, finish: HandshakeMessage) -> Result<ProtectedSession, HandshakeError> {
        let HandshakeMessage::Finish { authenticator } = finish else {
            return Err(HandshakeError::UnexpectedMessage);
        };
        if !self.psk.verify(
            &self.transcript.client_authentication_input()?,
            &authenticator,
        ) {
            return Err(HandshakeError::AuthenticationFailed);
        }
        let HandshakeMessage::Initiation { public_key, .. } = self.transcript.initiation() else {
            return Err(HandshakeError::UnexpectedMessage);
        };
        let keys = SessionKeys::derive(
            self.key_pair.agree(PublicKeyBytes::new(public_key))?,
            &transcript_hash(&self.transcript.final_bytes(finish)?),
            SessionRole::Responder,
        )?;
        Ok(ProtectedSession::new(self.session_id, 0, keys))
    }
}

/// Authentication and key-establishment failures.
#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("unexpected handshake message for the current role")]
    UnexpectedMessage,
    #[error("handshake PSK authentication failed")]
    AuthenticationFailed,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PacketKind;

    #[test]
    fn mutually_authenticated_peers_establish_compatible_sessions() {
        let psk = [9; 32];
        let (initiator, initiation) =
            InitiatorHandshake::start(HandshakePsk::from_bytes(psk)).unwrap();
        let (responder, response) =
            ResponderHandshake::accept(HandshakePsk::from_bytes(psk), initiation).unwrap();
        let (finish, mut client) = initiator.finish(response).unwrap();
        let mut server = responder.finish(finish).unwrap();
        let packet = client.seal(PacketKind::Data, b"ip bytes").unwrap();
        assert_eq!(server.open(packet).unwrap(), b"ip bytes"[..]);
    }

    #[test]
    fn rejects_response_authenticated_with_another_psk() {
        let (initiator, initiation) =
            InitiatorHandshake::start(HandshakePsk::from_bytes([1; 32])).unwrap();
        let (_, response) =
            ResponderHandshake::accept(HandshakePsk::from_bytes([2; 32]), initiation).unwrap();
        assert!(matches!(
            initiator.finish(response),
            Err(HandshakeError::AuthenticationFailed)
        ));
    }
}
