#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rvpn_crypto::{AuthConfig, IdentityKeyPair};
use rvpn_protocol::{HandshakeMessage, ResponderHandshake};

fuzz_target!(|data: &[u8]| {
    let Ok(message) = HandshakeMessage::decode(Bytes::copy_from_slice(data)) else {
        return;
    };

    let HandshakeMessage::Initiation { .. } = message else {
        return;
    };

    let server_key = IdentityKeyPair::from_seed([0x42; 32]);
    let client_key = IdentityKeyPair::from_seed([0x24; 32]);

    let server_auth = AuthConfig::PinnedKey {
        local_seed: server_key.to_seed_bytes(),
        peer_public_key: client_key.public_key().to_bytes(),
    };

    let _ = ResponderHandshake::accept(
        server_auth.identity(),
        server_auth.verifier(),
        message,
    );
});
