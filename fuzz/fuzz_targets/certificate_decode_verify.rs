#![no_main]

use libfuzzer_sys::fuzz_target;
use rvpn_crypto::{Certificate, IdentityKeyPair};

const CERTIFICATE_LEN: usize = 112;

fuzz_target!(|data: &[u8]| {
    if data.len() != CERTIFICATE_LEN {
        return;
    }

    let mut encoded = [0u8; CERTIFICATE_LEN];
    encoded.copy_from_slice(data);

    let certificate = Certificate::decode(&encoded);
    let ca = IdentityKeyPair::from_seed([0x11; 32]).public_key();
    let now = u64::from_be_bytes(
        encoded[32..40]
            .try_into()
            .expect("certificate width is fixed"),
    );

    let _ = certificate.verify(&ca, now);
});
