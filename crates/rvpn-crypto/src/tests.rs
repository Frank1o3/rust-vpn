use crate::*;

use super::*;

    #[test]
    fn peers_derive_opposite_directional_keys_and_round_trip() {
        let initiator = EphemeralKeyPair::generate().unwrap();
        let responder = EphemeralKeyPair::generate().unwrap();
        let initiator_public = initiator.public_key();
        let responder_public = responder.public_key();
        let initiator_secret = initiator.agree(responder_public).unwrap();
        let responder_secret = responder.agree(initiator_public).unwrap();
        let send = SessionKeys::derive(initiator_secret, &[7; 32], SessionRole::Initiator).unwrap();
        let receive =
            SessionKeys::derive(responder_secret, &[7; 32], SessionRole::Responder).unwrap();
        let nonce = PacketNonce::from_sequence(0, 1);
        let encrypted = send.seal(nonce, b"header", b"message").unwrap();
        assert_eq!(
            receive.open(nonce, b"header", &encrypted).unwrap(),
            b"message"[..]
        );
    }

    #[test]
    fn authentication_binds_header_and_nonce_inputs_differ() {
        let initiator = EphemeralKeyPair::generate().unwrap();
        let responder = EphemeralKeyPair::generate().unwrap();
        let initiator_public = initiator.public_key();
        let responder_public = responder.public_key();
        let send = SessionKeys::derive(
            initiator.agree(responder_public).unwrap(),
            &[3; 32],
            SessionRole::Initiator,
        )
        .unwrap();
        let receive = SessionKeys::derive(
            responder.agree(initiator_public).unwrap(),
            &[3; 32],
            SessionRole::Responder,
        )
        .unwrap();
        let ciphertext = send
            .seal(PacketNonce::from_sequence(1, 9), b"a", b"message")
            .unwrap();
        assert!(matches!(
            receive.open(PacketNonce::from_sequence(1, 9), b"b", &ciphertext),
            Err(CryptoError::AuthenticationFailed)
        ));
        assert_ne!(
            PacketNonce::from_sequence(1, 9),
            PacketNonce::from_sequence(1, 10)
        );
    }
