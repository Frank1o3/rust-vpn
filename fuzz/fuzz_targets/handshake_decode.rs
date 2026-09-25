#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rvpn_protocol::HandshakeMessage;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 {
        return;
    }

    let _ = HandshakeMessage::decode(Bytes::copy_from_slice(data));
});
