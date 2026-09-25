#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rvpn_protocol::Packet;

fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }

    let _ = Packet::decode(Bytes::copy_from_slice(data));
});
