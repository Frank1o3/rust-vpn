#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rvpn_crypto::{
    EphemeralKeyPair, PacketNonce, SessionKeys, SessionRole, handshake_salt,
};

static KEYS: OnceLock<SessionKeys> = OnceLock::new();

fn session_keys() -> &'static SessionKeys {
    KEYS.get_or_init(|| {
        let initiator = EphemeralKeyPair::generate().expect("OS randomness available");
        let responder = EphemeralKeyPair::generate().expect("OS randomness available");
        let shared = initiator
            .agree(responder.public_key())
            .expect("fixed generated keys must agree");
        let salt = handshake_salt(b"rvpn-fuzz-initiation", b"rvpn-fuzz-response");
        SessionKeys::derive(&shared, &salt, SessionRole::Responder)
            .expect("fixed fuzzing derivation inputs are valid")
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 16384 {
        return;
    }

    let mut key_phase = [0u8; 4];
    let mut sequence = [0u8; 8];

    if data.len() < 12 {
        return;
    }

    key_phase.copy_from_slice(&data[..4]);
    sequence.copy_from_slice(&data[4..12]);

    let nonce = PacketNonce::from_sequence(
        u32::from_be_bytes(key_phase),
        u64::from_be_bytes(sequence),
    );

    let split = 12 + (data[12..].len() / 2);
    let aad = &data[12..split];
    let ciphertext = &data[split..];

    let _ = session_keys().open(nonce, aad, ciphertext);
});
