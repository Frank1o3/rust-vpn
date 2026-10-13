#![no_main]

use libfuzzer_sys::fuzz_target;
use rvpn_core::SessionId;
use rvpn_routing::{Links, Router, packet};

fuzz_target!(|data: &[u8]| {
    let _ = packet::packet_source(data);
    let _ = packet::packet_destination(data);
    let _ = packet::ethernet_payload_ip(data, false);
    let _ = packet::ethernet_payload_ip(data, true);

    let mut router = Router::new(Links::default());
    router.register(SessionId::new([1; 16]), "fuzz", vec![]);
    let _ = router.route_ip(SessionId::new([1; 16]), data);
    let _ = router.route_frame(SessionId::new([1; 16]), data);
});
