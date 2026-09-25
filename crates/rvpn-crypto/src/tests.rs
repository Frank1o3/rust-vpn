use crate::*;

#[test]
fn peers_derive_opposite_directional_keys_and_round_trip() {
    let initiator = EphemeralKeyPair::generate().unwrap();
    let responder = EphemeralKeyPair::generate().unwrap();
    let initiator_public = initiator.public_key();
    let responder_public = responder.public_key();
    let initiator_secret = initiator.agree(responder_public).unwrap();
    let responder_secret = responder.agree(initiator_public).unwrap();
    let send = SessionKeys::derive(&initiator_secret, &[7; 32], SessionRole::Initiator).unwrap();
    let receive = SessionKeys::derive(&responder_secret, &[7; 32], SessionRole::Responder).unwrap();
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
    let initiator_secret = initiator.agree(responder_public).unwrap();
    let responder_secret = responder.agree(initiator_public).unwrap();
    let send = SessionKeys::derive(&initiator_secret, &[3; 32], SessionRole::Initiator).unwrap();
    let receive = SessionKeys::derive(&responder_secret, &[3; 32], SessionRole::Responder).unwrap();
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

#[test]
fn mac1_compute_and_verify() {
    let key_material = [42u8; 32];
    let key = Mac1Key::from_key_material(&key_material);
    let data = b"handshake initiation data payload";
    let mac = key.compute(data);
    assert!(key.verify(data, &mac));
}

#[test]
fn mac1_rejects_wrong_key_or_tampered_field() {
    let key_material = [42u8; 32];
    let key = Mac1Key::from_key_material(&key_material);
    let data = b"handshake initiation data payload";
    let mac = key.compute(data);

    // Wrong key
    let wrong_key = Mac1Key::from_key_material(&[99u8; 32]);
    assert!(!wrong_key.verify(data, &mac));

    // Tampered data
    let mut tampered_data = data.to_vec();
    tampered_data[0] ^= 0xff;
    assert!(!key.verify(&tampered_data, &mac));

    // Tampered tag
    let mut tampered_mac = mac;
    tampered_mac[0] ^= 0x01;
    assert!(!key.verify(data, &tampered_mac));
}

#[test]
fn handshake_keys_are_direction_separated() {
    let initiator = EphemeralKeyPair::generate().unwrap();
    let responder = EphemeralKeyPair::generate().unwrap();
    let initiator_secret = initiator.agree(responder.public_key()).unwrap();
    let responder_secret = responder.agree(initiator.public_key()).unwrap();

    let salt = handshake_salt(b"initiation_msg", b"resp_pub");
    let init_keys = HandshakeKeys::derive(&initiator_secret, &salt).unwrap();
    let resp_keys = HandshakeKeys::derive(&responder_secret, &salt).unwrap();

    // Direction separation: r2i and i2r keys are different
    assert_ne!(init_keys.r2i_key(), init_keys.i2r_key());
    assert_eq!(init_keys.r2i_key(), resp_keys.r2i_key());
    assert_eq!(init_keys.i2r_key(), resp_keys.i2r_key());

    // Sealing response under r2i and opening
    let aad_resp = b"response aad prefix";
    let sealed_resp = resp_keys
        .seal_response(aad_resp, b"secret server proof")
        .unwrap();
    let opened_resp = init_keys.open_response(aad_resp, &sealed_resp).unwrap();
    assert_eq!(opened_resp, b"secret server proof"[..]);

    // Cannot decrypt response ciphertext under finish (i2r)
    assert!(matches!(
        init_keys.open_finish(aad_resp, &sealed_resp),
        Err(CryptoError::AuthenticationFailed)
    ));

    // Sealing finish under i2r and opening
    let aad_finish = b"finish aad prefix";
    let sealed_finish = init_keys
        .seal_finish(aad_finish, b"secret client proof")
        .unwrap();
    let opened_finish = resp_keys.open_finish(aad_finish, &sealed_finish).unwrap();
    assert_eq!(opened_finish, b"secret client proof"[..]);

    // Cannot decrypt finish ciphertext under response (r2i)
    assert!(matches!(
        resp_keys.open_response(aad_finish, &sealed_finish),
        Err(CryptoError::AuthenticationFailed)
    ));
}

#[test]
fn independent_handshake_attempts_derive_independent_handshake_keys() {
    // Regression test for the nonce-reuse invariant documented on
    // `HandshakeKeys`: two different handshake attempts (fresh ephemeral
    // DH each time) must not derive colliding r2i/i2r keys, since both
    // use nonce 0 under crypt_fixed_nonce.
    fn derive_once() -> HandshakeKeys {
        let initiator = EphemeralKeyPair::generate().unwrap();
        let responder = EphemeralKeyPair::generate().unwrap();
        let shared = initiator.agree(responder.public_key()).unwrap();
        let salt = handshake_salt(b"initiation", b"response-public");
        HandshakeKeys::derive(&shared, &salt).unwrap()
    }

    let a = derive_once();
    let b = derive_once();
    assert_ne!(a.r2i_key(), b.r2i_key());
    assert_ne!(a.i2r_key(), b.i2r_key());
}

#[test]
fn seal_response_and_seal_finish_use_independent_keys_so_nonce_zero_does_not_collide() {
    let initiator = EphemeralKeyPair::generate().unwrap();
    let responder = EphemeralKeyPair::generate().unwrap();
    let shared = initiator.agree(responder.public_key()).unwrap();
    let salt = handshake_salt(b"initiation", b"response-public");
    let keys = HandshakeKeys::derive(&shared, &salt).unwrap();

    // Same nonce (0) under r2i and i2r for different plaintexts must not
    // decrypt cross-key: each direction's single use is isolated.
    let sealed_response = keys.seal_response(b"aad-response", b"response-proof").unwrap();
    let sealed_finish = keys.seal_finish(b"aad-finish", b"finish-proof").unwrap();

    assert_eq!(
        keys.open_response(b"aad-response", &sealed_response).unwrap(),
        b"response-proof"[..]
    );
    assert_eq!(
        keys.open_finish(b"aad-finish", &sealed_finish).unwrap(),
        b"finish-proof"[..]
    );
    // Wrong-direction key must fail even with matching AAD/nonce.
    assert!(keys.open_finish(b"aad-response", &sealed_response).is_err());
    assert!(keys.open_response(b"aad-finish", &sealed_finish).is_err());
}