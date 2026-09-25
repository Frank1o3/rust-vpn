#![no_main]

use libfuzzer_sys::fuzz_target;
use rvpn_crypto::ObfuscationKey;

fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }

    let key = ObfuscationKey::from_bytes([0xA5; 32]);
    let _ = key.unwrap(data);
});
