use std::net::IpAddr;

pub const ETHERNET_HEADER_LEN: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;

pub type Mac = [u8; 6];

pub fn packet_source(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= IPV4_MIN_HEADER => {
            Some(IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?))
        }
        6 if packet.len() >= IPV6_HEADER => {
            Some(IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?))
        }
        _ => None,
    }
}

pub fn packet_destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= IPV4_MIN_HEADER => {
            Some(IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?))
        }
        6 if packet.len() >= IPV6_HEADER => {
            Some(IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?))
        }
        _ => None,
    }
}

pub fn ethernet_dst_mac(frame: &[u8]) -> Option<Mac> {
    frame.get(0..6)?.try_into().ok()
}

pub fn ethernet_src_mac(frame: &[u8]) -> Option<Mac> {
    frame.get(6..12)?.try_into().ok()
}

pub fn ethertype(frame: &[u8]) -> Option<u16> {
    let bytes = frame.get(12..14)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub fn is_broadcast_or_multicast_mac(mac: &Mac) -> bool {
    mac[0] & 1 == 1
}

pub fn ethernet_payload_ip(frame: &[u8], is_dest: bool) -> Option<IpAddr> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return None;
    }
    let payload = &frame[ETHERNET_HEADER_LEN..];
    match ethertype(frame)? {
        ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => {
            if is_dest {
                packet_destination(payload)
            } else {
                packet_source(payload)
            }
        }
        ETHERTYPE_ARP => {
            if payload.len() < 28 {
                return None;
            }
            let offset = if is_dest { 24 } else { 14 };
            let bytes: [u8; 4] = payload[offset..offset + 4].try_into().ok()?;
            Some(IpAddr::from(bytes))
        }
        _ => None,
    }
}

pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        let word = match chunk {
            [a, b] => u16::from_be_bytes([*a, *b]),
            [a] => u16::from_be_bytes([*a, 0]),
            _ => 0,
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn decrement_hop_limit(packet: &mut [u8]) -> bool {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => {
            if packet.len() < IPV4_MIN_HEADER {
                return false;
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            if header_len < IPV4_MIN_HEADER || packet.len() < header_len {
                return false;
            }
            if packet[8] <= 1 {
                return false;
            }
            packet[8] -= 1;
            packet[10] = 0;
            packet[11] = 0;
            let checksum = ipv4_header_checksum(&packet[..header_len]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            true
        }
        Some(6) => {
            if packet.len() < IPV6_HEADER || packet[7] <= 1 {
                return false;
            }
            packet[7] -= 1;
            true
        }
        _ => false,
    }
}

pub fn prepare_forward(packet: &[u8]) -> Option<Vec<u8>> {
    let mut copy = packet.to_vec();
    decrement_hop_limit(&mut copy).then_some(copy)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn ipv4(src: [u8; 4], dst: [u8; 4], ttl: u8) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[8] = ttl;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        let checksum = ipv4_header_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    #[test]
    fn parses_ipv4_and_ipv6_addresses() {
        let v4 = ipv4([10, 42, 0, 2], [10, 42, 0, 3], 64);
        assert_eq!(packet_source(&v4), Some("10.42.0.2".parse().unwrap()));
        assert_eq!(packet_destination(&v4), Some("10.42.0.3".parse().unwrap()));

        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        v6[8..24].copy_from_slice(&"fd42::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
        v6[24..40].copy_from_slice(&"fd42::3".parse::<std::net::Ipv6Addr>().unwrap().octets());
        assert_eq!(packet_source(&v6), Some("fd42::2".parse().unwrap()));
        assert_eq!(packet_destination(&v6), Some("fd42::3".parse().unwrap()));
    }

    #[test]
    fn rejects_short_or_unknown_packets() {
        assert_eq!(packet_source(&[]), None);
        assert_eq!(packet_source(&[0x45; 10]), None);
        assert_eq!(packet_destination(&[0x10; 40]), None);
    }

    #[test]
    fn ttl_decrement_keeps_checksum_valid() {
        let mut packet = ipv4([10, 42, 0, 2], [10, 42, 0, 3], 64);
        assert_eq!(ipv4_header_checksum(&packet[..20]), 0);
        assert!(decrement_hop_limit(&mut packet));
        assert_eq!(packet[8], 63);
        assert_eq!(ipv4_header_checksum(&packet[..20]), 0);
    }

    #[test]
    fn expiring_ttl_is_refused() {
        let mut packet = ipv4([10, 42, 0, 2], [10, 42, 0, 3], 1);
        let before = packet.clone();
        assert!(!decrement_hop_limit(&mut packet));
        assert_eq!(packet, before);
        assert!(prepare_forward(&before).is_none());
    }

    #[test]
    fn ipv6_hop_limit_is_decremented() {
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        v6[7] = 5;
        assert!(decrement_hop_limit(&mut v6));
        assert_eq!(v6[7], 4);
        v6[7] = 1;
        assert!(!decrement_hop_limit(&mut v6));
    }

    #[test]
    fn arp_addresses_use_sender_and_target_fields() {
        let mut frame = vec![0u8; 14 + 28];
        frame[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        frame[14 + 14..14 + 18].copy_from_slice(&[10, 42, 0, 2]);
        frame[14 + 24..14 + 28].copy_from_slice(&[10, 42, 0, 3]);
        assert_eq!(
            ethernet_payload_ip(&frame, false),
            Some("10.42.0.2".parse().unwrap())
        );
        assert_eq!(
            ethernet_payload_ip(&frame, true),
            Some("10.42.0.3".parse().unwrap())
        );
    }
}
