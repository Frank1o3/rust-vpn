//! Typed orchestration for RVPN's PSK-, pinned-key-, or certificate-authenticated
//! ephemeral handshake.

use crate::{AuthProof, HandshakeMessage, HandshakeTranscript, ProtectedSession, ProtocolError};
use rvpn_core::SessionId;
use rvpn_crypto::{
    AuthIdentity, AuthVerifier, Certificate, CryptoError, EphemeralKeyPair, IdentityPublicKey,
    PublicKeyBytes, SessionKeys, SessionRole, random_bytes, transcript_hash,
};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Initiator state after emitting an initiation message.
pub struct InitiatorHandshake {
    identity: AuthIdentity,
    verifier: AuthVerifier,
    key_pair: EphemeralKeyPair,
    initiation: HandshakeMessage,
}

/// Responder state after emitting an authenticated response.
pub struct ResponderHandshake {
    #[warn(dead_code)]
    identity: AuthIdentity,
    verifier: AuthVerifier,
    key_pair: EphemeralKeyPair,
    transcript: HandshakeTranscript,
    session_id: SessionId,
    key_phase: u32,
}

fn tag_of(identity: &AuthIdentity) -> u8 {
    match identity {
        AuthIdentity::Psk(_) => 0,
        AuthIdentity::PinnedKey(_) => 1,
        AuthIdentity::Certificate { .. } => 2,
    }
}

fn produce_proof(identity: &AuthIdentity, data: &[u8]) -> AuthProof {
    match identity {
        AuthIdentity::Psk(psk) => AuthProof::Psk(psk.authenticate(data)),
        AuthIdentity::PinnedKey(key) => AuthProof::PinnedKey(key.sign(data)),
        AuthIdentity::Certificate {
            local_key,
            certificate,
        } => AuthProof::Certificate {
            certificate: certificate.encode(),
            signature: local_key.sign(data),
        },
    }
}

fn verify_proof(
    verifier: &AuthVerifier,
    data: &[u8],
    proof: &AuthProof,
) -> Result<Option<IdentityPublicKey>, HandshakeError> {
    match (verifier, proof) {
        (AuthVerifier::Psk(psk), AuthProof::Psk(tag)) => {
            if psk.verify(data, tag) {
                Ok(None)
            } else {
                Err(HandshakeError::AuthenticationFailed)
            }
        }
        (AuthVerifier::PinnedKey(expected), AuthProof::PinnedKey(sig)) => {
            if expected.verify(data, sig) {
                Ok(Some(*expected))
            } else {
                Err(HandshakeError::AuthenticationFailed)
            }
        }
        (
            AuthVerifier::Certificate(ca),
            AuthProof::Certificate {
                certificate,
                signature,
            },
        ) => {
            let cert = Certificate::decode(certificate);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if !cert.verify(ca, now) {
                return Err(HandshakeError::AuthenticationFailed);
            }
            if !cert.subject.verify(data, signature) {
                return Err(HandshakeError::AuthenticationFailed);
            }
            Ok(Some(cert.subject))
        }
        _ => Err(HandshakeError::AuthenticationFailed),
    }
}

impl InitiatorHandshake {
    /// Generates and returns the first handshake message.
    pub fn start(
        identity: AuthIdentity,
        verifier: AuthVerifier,
    ) -> Result<(Self, HandshakeMessage), HandshakeError> {
        let key_pair = EphemeralKeyPair::generate()?;
        let initiation = HandshakeMessage::Initiation {
            public_key: key_pair.public_key().to_bytes(),
            random: random_bytes()?,
        };
        Ok((
            Self {
                identity,
                verifier,
                key_pair,
                initiation,
            },
            initiation,
        ))
    }

    /// Verifies a server response, then returns the client finish, the
    /// session, and the server's proven identity (`None` for PSK mode, since
    /// a shared secret doesn't carry an identity of its own).
    pub fn finish(
        self,
        response: HandshakeMessage,
    ) -> Result<
        (
            HandshakeMessage,
            ProtectedSession,
            Option<IdentityPublicKey>,
        ),
        HandshakeError,
    > {
        let session_id = match response {
            HandshakeMessage::Response { session_id, .. } => session_id,
            _ => return Err(HandshakeError::UnexpectedMessage),
        };
        self.finish_for_session(response, session_id, 0)
    }

    /// Checks whether a response is authenticated for this initiator without
    /// consuming the one-use ephemeral key. This lets a client safely ignore
    /// responses intended for other provisioned server identities.
    pub fn authenticates_response(
        &self,
        response: HandshakeMessage,
    ) -> Result<bool, HandshakeError> {
        let HandshakeMessage::Response { proof, .. } = response else {
            return Err(HandshakeError::UnexpectedMessage);
        };
        let transcript = HandshakeTranscript::new(self.initiation)?;
        let data = transcript.server_authentication_input(response)?;
        Ok(verify_proof(&self.verifier, &data, &proof).is_ok())
    }

    /// Completes a fresh exchange for an existing session identity and key phase.
    pub fn finish_for_session(
        self,
        response: HandshakeMessage,
        expected_session_id: SessionId,
        key_phase: u32,
    ) -> Result<
        (
            HandshakeMessage,
            ProtectedSession,
            Option<IdentityPublicKey>,
        ),
        HandshakeError,
    > {
        let HandshakeMessage::Response {
            public_key,
            session_id,
            proof,
            ..
        } = response
        else {
            return Err(HandshakeError::UnexpectedMessage);
        };
        if session_id != expected_session_id {
            return Err(HandshakeError::UnexpectedSession);
        }
        let mut transcript = HandshakeTranscript::new(self.initiation)?;
        let data = transcript.server_authentication_input(response)?;
        let remote_identity = verify_proof(&self.verifier, &data, &proof)?;
        transcript.set_response(response)?;
        let finish_data = transcript.client_authentication_input()?;
        let finish = HandshakeMessage::Finish {
            proof: produce_proof(&self.identity, &finish_data),
        };
        let keys = SessionKeys::derive(
            self.key_pair.agree(PublicKeyBytes::new(public_key))?,
            &transcript_hash(&transcript.final_bytes(finish)?),
            SessionRole::Initiator,
        )?;
        Ok((
            finish,
            ProtectedSession::new(session_id, key_phase, keys),
            remote_identity,
        ))
    }
}

impl ResponderHandshake {
    /// Processes an initiation and returns an authenticated server response.
    pub fn accept(
        identity: AuthIdentity,
        verifier: AuthVerifier,
        initiation: HandshakeMessage,
    ) -> Result<(Self, HandshakeMessage), HandshakeError> {
        Self::accept_for_session(
            identity,
            verifier,
            initiation,
            SessionId::new(random_bytes()?),
            0,
        )
    }

    /// Accepts a rekey exchange for an already-established session.
    pub fn accept_for_session(
        identity: AuthIdentity,
        verifier: AuthVerifier,
        initiation: HandshakeMessage,
        session_id: SessionId,
        key_phase: u32,
    ) -> Result<(Self, HandshakeMessage), HandshakeError> {
        if !matches!(initiation, HandshakeMessage::Initiation { .. }) {
            return Err(HandshakeError::UnexpectedMessage);
        }
        let key_pair = EphemeralKeyPair::generate()?;
        let mut transcript = HandshakeTranscript::new(initiation)?;
        let placeholder = AuthProof::placeholder(tag_of(&identity));
        let unsigned_response = HandshakeMessage::Response {
            public_key: key_pair.public_key().to_bytes(),
            random: random_bytes()?,
            session_id,
            proof: placeholder,
        };
        let data = transcript.server_authentication_input(unsigned_response)?;
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
                proof: produce_proof(&identity, &data),
            },
            _ => unreachable!(),
        };
        transcript.set_response(response)?;
        Ok((
            Self {
                identity,
                verifier,
                key_pair,
                transcript,
                session_id,
                key_phase,
            },
            response,
        ))
    }

    /// Verifies the client finish and returns the established protected
    /// session, plus the client's proven identity (`None` for PSK mode).
    pub fn finish(
        self,
        finish: HandshakeMessage,
    ) -> Result<(ProtectedSession, Option<IdentityPublicKey>), HandshakeError> {
        let HandshakeMessage::Finish { proof } = finish else {
            return Err(HandshakeError::UnexpectedMessage);
        };
        let data = self.transcript.client_authentication_input()?;
        let remote_identity = verify_proof(&self.verifier, &data, &proof)?;
        let HandshakeMessage::Initiation { public_key, .. } = self.transcript.initiation() else {
            return Err(HandshakeError::UnexpectedMessage);
        };
        let keys = SessionKeys::derive(
            self.key_pair.agree(PublicKeyBytes::new(public_key))?,
            &transcript_hash(&self.transcript.final_bytes(finish)?),
            SessionRole::Responder,
        )?;
        Ok((
            ProtectedSession::new(self.session_id, self.key_phase, keys),
            remote_identity,
        ))
    }
}

/// Authentication and key-establishment failures.
#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("unexpected handshake message for the current role")]
    UnexpectedMessage,
    #[error("handshake authentication failed")]
    AuthenticationFailed,
    #[error("handshake response belongs to an unexpected session")]
    UnexpectedSession,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PacketKind;
    use rvpn_crypto::{AuthConfig, IdentityKeyPair};

    #[test]
    fn psk_peers_establish_compatible_sessions() {
        let auth = AuthConfig::Psk([9; 32]);
        let (initiator, initiation) =
            InitiatorHandshake::start(auth.identity(), auth.verifier()).unwrap();
        let (responder, response) =
            ResponderHandshake::accept(auth.identity(), auth.verifier(), initiation).unwrap();
        let (finish, mut client, remote) = initiator.finish(response).unwrap();
        let (mut server, remote2) = responder.finish(finish).unwrap();
        assert!(remote.is_none());
        assert!(remote2.is_none());
        let packet = client.seal(PacketKind::Data, b"ip bytes").unwrap();
        assert_eq!(server.open(packet).unwrap(), b"ip bytes"[..]);
    }

    #[test]
    fn rejects_response_authenticated_with_another_psk() {
        let client_auth = AuthConfig::Psk([1; 32]);
        let server_auth = AuthConfig::Psk([2; 32]);
        let (initiator, initiation) =
            InitiatorHandshake::start(client_auth.identity(), client_auth.verifier()).unwrap();
        let (_, response) =
            ResponderHandshake::accept(server_auth.identity(), server_auth.verifier(), initiation)
                .unwrap();
        assert!(matches!(
            initiator.finish(response),
            Err(HandshakeError::AuthenticationFailed)
        ));
    }

    #[test]
    fn certificate_peers_establish_sessions_and_reveal_subject_identity() {
        let ca = IdentityKeyPair::generate().unwrap();
        let client_key = IdentityKeyPair::generate().unwrap();
        let server_key = IdentityKeyPair::generate().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let client_cert = ca.issue_certificate(client_key.public_key(), now - 60, now + 3600);
        let server_cert = ca.issue_certificate(server_key.public_key(), now - 60, now + 3600);

        let client_auth = AuthConfig::Certificate {
            local_seed: client_key.to_seed_bytes(),
            local_certificate: client_cert.encode(),
            ca_public_key: ca.public_key().to_bytes(),
        };
        let server_auth = AuthConfig::Certificate {
            local_seed: server_key.to_seed_bytes(),
            local_certificate: server_cert.encode(),
            ca_public_key: ca.public_key().to_bytes(),
        };

        let (initiator, initiation) =
            InitiatorHandshake::start(client_auth.identity(), client_auth.verifier()).unwrap();
        let (responder, response) =
            ResponderHandshake::accept(server_auth.identity(), server_auth.verifier(), initiation)
                .unwrap();
        let (finish, mut client, server_identity) = initiator.finish(response).unwrap();
        let (mut server, client_identity) = responder.finish(finish).unwrap();

        assert_eq!(server_identity, Some(server_key.public_key()));
        assert_eq!(client_identity, Some(client_key.public_key()));
        let packet = client
            .seal(PacketKind::Data, b"cert-authenticated")
            .unwrap();
        assert_eq!(server.open(packet).unwrap(), b"cert-authenticated"[..]);
    }

    #[test]
    fn rekey_keeps_session_identity_and_advances_key_phase() {
        let auth = AuthConfig::Psk([3; 32]);
        let session_id = SessionId::new([7; 16]);
        let (initiator, initiation) =
            InitiatorHandshake::start(auth.identity(), auth.verifier()).unwrap();
        let (responder, response) = ResponderHandshake::accept_for_session(
            auth.identity(),
            auth.verifier(),
            initiation,
            session_id,
            1,
        )
        .unwrap();
        let (finish, mut client, _) = initiator
            .finish_for_session(response, session_id, 1)
            .unwrap();
        let (mut server, _) = responder.finish(finish).unwrap();
        assert_eq!(client.session_id(), session_id);
        assert_eq!(client.key_phase(), 1);
        assert_eq!(
            server
                .open(client.seal(PacketKind::Data, b"new keys").unwrap())
                .unwrap(),
            b"new keys"[..]
        );
    }
}
