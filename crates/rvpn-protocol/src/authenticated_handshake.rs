use crate::{
    AuthProof, HandshakeMessage, HandshakeTranscript, ProtectedSession, ProtocolError,
    handshake::{COOKIE_LEN, PROOF_BODY_LEN, SEALED_PROOF_LEN},
};
use rvpn_core::SessionId;
use rvpn_crypto::{
    AuthIdentity, AuthVerifier, Certificate, CryptoError, EphemeralKeyPair, HandshakeKeys,
    IdentityPublicKey, PublicKeyBytes, SessionKeys, SessionRole, handshake_salt, random_bytes,
    transcript_hash,
};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub struct InitiatorHandshake {
    identity: AuthIdentity,
    verifier: AuthVerifier,
    key_pair: EphemeralKeyPair,
    initiation: HandshakeMessage,
}

pub struct ResponderHandshake {
    verifier: AuthVerifier,
    shared_secret: rvpn_crypto::SharedSecret,
    handshake_keys: HandshakeKeys,
    transcript: HandshakeTranscript,
    session_id: SessionId,
    key_phase: u32,
}

fn produce_proof(identity: &AuthIdentity, data: &[u8]) -> AuthProof {
    match identity {
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
    pub fn start(
        identity: AuthIdentity,
        verifier: AuthVerifier,
    ) -> Result<(Self, HandshakeMessage), HandshakeError> {
        let key_pair = EphemeralKeyPair::generate()?;
        let public_key = key_pair.public_key().to_bytes();
        let random = random_bytes()?;
        let mac1 = HandshakeMessage::compute_mac1(&verifier.mac1_key(), &public_key, &random, None);
        let initiation = HandshakeMessage::Initiation {
            public_key,
            random,
            cookie: None,
            mac1,
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

    pub const fn initiation(&self) -> HandshakeMessage {
        self.initiation
    }

    pub fn attach_cookie(&mut self, cookie: [u8; COOKIE_LEN]) {
        if let HandshakeMessage::Initiation {
            public_key, random, ..
        } = self.initiation
        {
            let mac1 = HandshakeMessage::compute_mac1(
                &self.verifier.mac1_key(),
                &public_key,
                &random,
                Some(&cookie),
            );
            self.initiation = HandshakeMessage::Initiation {
                public_key,
                random,
                cookie: Some(cookie),
                mac1,
            };
        }
    }

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

    pub fn authenticates_response(
        &self,
        response: HandshakeMessage,
    ) -> Result<bool, HandshakeError> {
        let HandshakeMessage::Response {
            public_key,
            random,
            session_id,
            sealed_proof,
        } = response
        else {
            return Err(HandshakeError::UnexpectedMessage);
        };
        let Ok(shared_secret) = self.key_pair.agree(PublicKeyBytes::new(public_key)) else {
            return Ok(false);
        };
        let response_public =
            HandshakeMessage::response_public_bytes(&public_key, &random, session_id);
        let salt = handshake_salt(&self.initiation.encode(), &response_public);
        let Ok(handshake_keys) = HandshakeKeys::derive(&shared_secret, &salt) else {
            return Ok(false);
        };
        let Ok(opened) = handshake_keys.open_response(&self.initiation.encode(), &sealed_proof)
        else {
            return Ok(false);
        };
        let Ok(body_arr) = opened.as_ref().try_into() else {
            return Ok(false);
        };
        let Ok(proof) = AuthProof::decode_body(body_arr) else {
            return Ok(false);
        };
        let transcript = HandshakeTranscript::new(self.initiation)?;
        let data = transcript.server_authentication_input(public_key, random, session_id)?;
        Ok(verify_proof(&self.verifier, &data, &proof).is_ok())
    }

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
            random,
            session_id,
            sealed_proof,
        } = response
        else {
            return Err(HandshakeError::UnexpectedMessage);
        };
        if session_id != expected_session_id {
            return Err(HandshakeError::UnexpectedSession);
        }
        let shared_secret = self.key_pair.agree(PublicKeyBytes::new(public_key))?;
        let response_public =
            HandshakeMessage::response_public_bytes(&public_key, &random, session_id);
        let salt = handshake_salt(&self.initiation.encode(), &response_public);
        let handshake_keys = HandshakeKeys::derive(&shared_secret, &salt)?;

        let opened = handshake_keys
            .open_response(&self.initiation.encode(), &sealed_proof)
            .map_err(|_| HandshakeError::AuthenticationFailed)?;
        let body_arr: &[u8; PROOF_BODY_LEN] = opened
            .as_ref()
            .try_into()
            .map_err(|_| HandshakeError::AuthenticationFailed)?;
        let proof = AuthProof::decode_body(body_arr)?;

        let mut transcript = HandshakeTranscript::new(self.initiation)?;
        let data = transcript.server_authentication_input(public_key, random, session_id)?;
        let remote_identity = verify_proof(&self.verifier, &data, &proof)?;
        transcript.set_response(response)?;

        let finish_data = transcript.client_authentication_input()?;
        let client_proof = produce_proof(&self.identity, &finish_data);
        let aad = [&self.initiation.encode()[..], &response.encode()[..]].concat();
        let sealed_finish = handshake_keys.seal_finish(&aad, &client_proof.encode_body())?;
        let mut sealed_finish_array = [0u8; SEALED_PROOF_LEN];
        sealed_finish_array.copy_from_slice(&sealed_finish);
        let finish = HandshakeMessage::Finish {
            sealed_proof: sealed_finish_array,
        };

        let keys = SessionKeys::derive(
            &shared_secret,
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

    pub fn accept_for_session(
        identity: AuthIdentity,
        verifier: AuthVerifier,
        initiation: HandshakeMessage,
        session_id: SessionId,
        key_phase: u32,
    ) -> Result<(Self, HandshakeMessage), HandshakeError> {
        let HandshakeMessage::Initiation { public_key, .. } = initiation else {
            return Err(HandshakeError::UnexpectedMessage);
        };
        let key_pair = EphemeralKeyPair::generate()?;
        let shared_secret = key_pair.agree(PublicKeyBytes::new(public_key))?;
        let eph_pub = key_pair.public_key().to_bytes();
        let random = random_bytes()?;

        let response_public =
            HandshakeMessage::response_public_bytes(&eph_pub, &random, session_id);
        let salt = handshake_salt(&initiation.encode(), &response_public);
        let handshake_keys = HandshakeKeys::derive(&shared_secret, &salt)?;

        let mut transcript = HandshakeTranscript::new(initiation)?;
        let data = transcript.server_authentication_input(eph_pub, random, session_id)?;
        let proof = produce_proof(&identity, &data);

        let sealed = handshake_keys.seal_response(&initiation.encode(), &proof.encode_body())?;
        let mut sealed_proof = [0u8; SEALED_PROOF_LEN];
        sealed_proof.copy_from_slice(&sealed);

        let response = HandshakeMessage::Response {
            public_key: eph_pub,
            random,
            session_id,
            sealed_proof,
        };
        transcript.set_response(response)?;

        Ok((
            Self {
                verifier,
                shared_secret,
                handshake_keys,
                transcript,
                session_id,
                key_phase,
            },
            response,
        ))
    }

    pub fn finish(
        self,
        finish: HandshakeMessage,
    ) -> Result<(ProtectedSession, Option<IdentityPublicKey>), HandshakeError> {
        let HandshakeMessage::Finish { sealed_proof } = finish else {
            return Err(HandshakeError::UnexpectedMessage);
        };
        let response = self
            .transcript
            .response()
            .ok_or(HandshakeError::UnexpectedMessage)?;
        let aad = [
            &self.transcript.initiation().encode()[..],
            &response.encode()[..],
        ]
        .concat();
        let opened = self
            .handshake_keys
            .open_finish(&aad, &sealed_proof)
            .map_err(|_| HandshakeError::AuthenticationFailed)?;
        let body_arr: &[u8; PROOF_BODY_LEN] = opened
            .as_ref()
            .try_into()
            .map_err(|_| HandshakeError::AuthenticationFailed)?;
        let proof = AuthProof::decode_body(body_arr)?;

        let data = self.transcript.client_authentication_input()?;
        let remote_identity = verify_proof(&self.verifier, &data, &proof)?;

        let keys = SessionKeys::derive(
            &self.shared_secret,
            &transcript_hash(&self.transcript.final_bytes(finish)?),
            SessionRole::Responder,
        )?;
        Ok((
            ProtectedSession::new(self.session_id, self.key_phase, keys),
            remote_identity,
        ))
    }
}

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("unexpected handshake message")]
    UnexpectedMessage,
    #[error("unexpected session id")]
    UnexpectedSession,
    #[error("handshake authentication failed")]
    AuthenticationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PacketKind;
    use crate::handshake::{FINISH_LEN, INITIATION_LEN, RESPONSE_LEN};
    use rvpn_crypto::{AuthConfig, IdentityKeyPair, Mac1Key};

    #[test]
    fn certificate_and_pinned_key_round_trips_through_sealing() {
        // Pinned key round trip
        let client_key = IdentityKeyPair::generate().unwrap();
        let server_key = IdentityKeyPair::generate().unwrap();
        let client_auth = AuthConfig::PinnedKey {
            local_seed: client_key.to_seed_bytes(),
            peer_public_key: server_key.public_key().to_bytes(),
        };
        let server_auth = AuthConfig::PinnedKey {
            local_seed: server_key.to_seed_bytes(),
            peer_public_key: client_key.public_key().to_bytes(),
        };

        let (initiator, initiation) =
            InitiatorHandshake::start(client_auth.identity(), client_auth.verifier()).unwrap();
        assert!(initiation.verify_mac1(&server_auth.responder_mac1_key()));

        let (responder, response) =
            ResponderHandshake::accept(server_auth.identity(), server_auth.verifier(), initiation)
                .unwrap();
        assert!(initiator.authenticates_response(response).unwrap());

        let (finish, mut client, server_id) = initiator.finish(response).unwrap();
        let (mut server, client_id) = responder.finish(finish).unwrap();

        assert_eq!(server_id, Some(server_key.public_key()));
        assert_eq!(client_id, Some(client_key.public_key()));

        let pkt = client
            .seal(PacketKind::Data, b"pinned-secret-data")
            .unwrap();
        assert_eq!(server.open(pkt).unwrap(), b"pinned-secret-data"[..]);

        // Certificate round trip
        let ca = IdentityKeyPair::generate().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let client_cert = ca.issue_certificate(client_key.public_key(), now - 60, now + 3600);
        let server_cert = ca.issue_certificate(server_key.public_key(), now - 60, now + 3600);

        let cert_client_auth = AuthConfig::Certificate {
            local_seed: client_key.to_seed_bytes(),
            local_certificate: client_cert.encode(),
            ca_public_key: ca.public_key().to_bytes(),
        };
        let cert_server_auth = AuthConfig::Certificate {
            local_seed: server_key.to_seed_bytes(),
            local_certificate: server_cert.encode(),
            ca_public_key: ca.public_key().to_bytes(),
        };

        let (initiator, initiation) =
            InitiatorHandshake::start(cert_client_auth.identity(), cert_client_auth.verifier())
                .unwrap();
        assert!(initiation.verify_mac1(&cert_server_auth.responder_mac1_key()));

        let (responder, response) = ResponderHandshake::accept(
            cert_server_auth.identity(),
            cert_server_auth.verifier(),
            initiation,
        )
        .unwrap();
        assert!(initiator.authenticates_response(response).unwrap());

        let (finish, mut client, server_id) = initiator.finish(response).unwrap();
        let (mut server, client_id) = responder.finish(finish).unwrap();

        assert_eq!(server_id, Some(server_key.public_key()));
        assert_eq!(client_id, Some(client_key.public_key()));

        let pkt = client.seal(PacketKind::Data, b"cert-secret-data").unwrap();
        assert_eq!(server.open(pkt).unwrap(), b"cert-secret-data"[..]);
    }

    #[test]
    fn exact_wire_lengths_from_d5_for_both_modes() {
        // Pinned key wire lengths
        let client_key = IdentityKeyPair::generate().unwrap();
        let server_key = IdentityKeyPair::generate().unwrap();
        let client_auth = AuthConfig::PinnedKey {
            local_seed: client_key.to_seed_bytes(),
            peer_public_key: server_key.public_key().to_bytes(),
        };
        let server_auth = AuthConfig::PinnedKey {
            local_seed: server_key.to_seed_bytes(),
            peer_public_key: client_key.public_key().to_bytes(),
        };

        let (initiator, initiation) =
            InitiatorHandshake::start(client_auth.identity(), client_auth.verifier()).unwrap();
        let (_responder, response) =
            ResponderHandshake::accept(server_auth.identity(), server_auth.verifier(), initiation)
                .unwrap();
        let (finish, _, _) = initiator.finish(response).unwrap();

        assert_eq!(initiation.encode().len(), INITIATION_LEN);
        assert_eq!(initiation.encode().len(), 114);
        assert_eq!(response.encode().len(), RESPONSE_LEN);
        assert_eq!(response.encode().len(), 274);
        assert_eq!(finish.encode().len(), FINISH_LEN);
        assert_eq!(finish.encode().len(), 194);

        // Certificate wire lengths
        let ca = IdentityKeyPair::generate().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let client_cert = ca.issue_certificate(client_key.public_key(), now - 60, now + 3600);
        let server_cert = ca.issue_certificate(server_key.public_key(), now - 60, now + 3600);
        let cert_client_auth = AuthConfig::Certificate {
            local_seed: client_key.to_seed_bytes(),
            local_certificate: client_cert.encode(),
            ca_public_key: ca.public_key().to_bytes(),
        };
        let cert_server_auth = AuthConfig::Certificate {
            local_seed: server_key.to_seed_bytes(),
            local_certificate: server_cert.encode(),
            ca_public_key: ca.public_key().to_bytes(),
        };

        let (initiator, initiation) =
            InitiatorHandshake::start(cert_client_auth.identity(), cert_client_auth.verifier())
                .unwrap();
        let (_responder, response) = ResponderHandshake::accept(
            cert_server_auth.identity(),
            cert_server_auth.verifier(),
            initiation,
        )
        .unwrap();
        let (finish, _, _) = initiator.finish(response).unwrap();

        assert_eq!(initiation.encode().len(), 114);
        assert_eq!(response.encode().len(), 274);
        assert_eq!(finish.encode().len(), 194);
    }

    #[test]
    fn tampered_sealed_proof_rejected() {
        let client_key = IdentityKeyPair::generate().unwrap();
        let server_key = IdentityKeyPair::generate().unwrap();
        let client_auth = AuthConfig::PinnedKey {
            local_seed: client_key.to_seed_bytes(),
            peer_public_key: server_key.public_key().to_bytes(),
        };
        let server_auth = AuthConfig::PinnedKey {
            local_seed: server_key.to_seed_bytes(),
            peer_public_key: client_key.public_key().to_bytes(),
        };

        // Tampered Response proof
        let (initiator, initiation) =
            InitiatorHandshake::start(client_auth.identity(), client_auth.verifier()).unwrap();
        let (_responder, response) =
            ResponderHandshake::accept(server_auth.identity(), server_auth.verifier(), initiation)
                .unwrap();

        let HandshakeMessage::Response {
            public_key,
            random,
            session_id,
            mut sealed_proof,
        } = response
        else {
            panic!("expected response");
        };
        sealed_proof[0] ^= 0x01;
        let tampered_response = HandshakeMessage::Response {
            public_key,
            random,
            session_id,
            sealed_proof,
        };

        assert!(!initiator.authenticates_response(tampered_response).unwrap());
        assert!(matches!(
            initiator.finish(tampered_response),
            Err(HandshakeError::AuthenticationFailed)
        ));

        // Tampered Finish proof
        let (initiator2, initiation2) =
            InitiatorHandshake::start(client_auth.identity(), client_auth.verifier()).unwrap();
        let (responder2, response2) =
            ResponderHandshake::accept(server_auth.identity(), server_auth.verifier(), initiation2)
                .unwrap();
        let (finish2, _, _) = initiator2.finish(response2).unwrap();

        let HandshakeMessage::Finish { mut sealed_proof } = finish2 else {
            panic!("expected finish");
        };
        sealed_proof[10] ^= 0x01;
        let tampered_finish = HandshakeMessage::Finish { sealed_proof };

        assert!(matches!(
            responder2.finish(tampered_finish),
            Err(HandshakeError::AuthenticationFailed)
        ));
    }

    #[test]
    fn wrong_mac1_detected() {
        let client_key = IdentityKeyPair::generate().unwrap();
        let server_key = IdentityKeyPair::generate().unwrap();
        let client_auth = AuthConfig::PinnedKey {
            local_seed: client_key.to_seed_bytes(),
            peer_public_key: server_key.public_key().to_bytes(),
        };
        let server_auth = AuthConfig::PinnedKey {
            local_seed: server_key.to_seed_bytes(),
            peer_public_key: client_key.public_key().to_bytes(),
        };

        let (mut initiator, initiation) =
            InitiatorHandshake::start(client_auth.identity(), client_auth.verifier()).unwrap();
        let correct_mac1_key = server_auth.responder_mac1_key();
        let wrong_mac1_key = Mac1Key::from_key_material(&[99; 32]);

        assert!(initiation.verify_mac1(&correct_mac1_key));
        assert!(!initiation.verify_mac1(&wrong_mac1_key));

        // Tampered mac1 in initiation
        let HandshakeMessage::Initiation {
            public_key,
            random,
            cookie,
            mut mac1,
        } = initiation
        else {
            panic!("expected initiation");
        };
        mac1[0] ^= 0x01;
        let tampered_initiation = HandshakeMessage::Initiation {
            public_key,
            random,
            cookie,
            mac1,
        };
        assert!(!tampered_initiation.verify_mac1(&correct_mac1_key));

        // Attaching a cookie recomputes mac1
        initiator.attach_cookie([7; 32]);
        let cookie_initiation = initiator.initiation();
        assert!(cookie_initiation.verify_mac1(&correct_mac1_key));
        assert!(!cookie_initiation.verify_mac1(&wrong_mac1_key));
    }

    #[test]
    fn rekey_path_still_works() {
        let client_key = IdentityKeyPair::generate().unwrap();
        let server_key = IdentityKeyPair::generate().unwrap();
        let client_auth = AuthConfig::PinnedKey {
            local_seed: client_key.to_seed_bytes(),
            peer_public_key: server_key.public_key().to_bytes(),
        };
        let server_auth = AuthConfig::PinnedKey {
            local_seed: server_key.to_seed_bytes(),
            peer_public_key: client_key.public_key().to_bytes(),
        };

        let session_id = SessionId::new([7; 16]);
        let (initiator, initiation) =
            InitiatorHandshake::start(client_auth.identity(), client_auth.verifier()).unwrap();
        let (responder, response) = ResponderHandshake::accept_for_session(
            server_auth.identity(),
            server_auth.verifier(),
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
