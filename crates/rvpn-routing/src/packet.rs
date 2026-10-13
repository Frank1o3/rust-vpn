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
        4 if valid_ipv4(packet) => Some(IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?)),
        6 if valid_ipv6(packet) => Some(IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?)),
        _ => None,
    }
}

pub fn packet_destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if valid_ipv4(packet) => Some(IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?)),
        6 if valid_ipv6(packet) => Some(IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?)),
        _ => None,
    }
}

fn valid_ipv4(packet: &[u8]) -> bool {
    if packet.len() < IPV4_MIN_HEADER || packet[0] >> 4 != 4 {
        return false;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    header_len >= IPV4_MIN_HEADER
        && header_len <= total_len
        && total_len <= packet.len()
        && ipv4_header_checksum(&packet[..header_len]) == 0
}

fn valid_ipv6(packet: &[u8]) -> bool {
    if packet.len() < IPV6_HEADER || packet[0] >> 4 != 6 {
        return false;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let end = IPV6_HEADER + payload_len;
    if end > packet.len() {
        return false;
    }

    // Validate extension-header lengths before accepting the base addresses.
    let mut next = packet[6];
    let mut offset = IPV6_HEADER;
    for _ in 0..8 {
        let length = match next {
            0 | 43 | 60 => {
                if offset + 2 > end {
                    return false;
                }
                (usize::from(packet[offset + 1]) + 1) * 8
            }
            44 => 8, // Fragment header
            51 => {
                if offset + 2 > end {
                    return false;
                }
                (usize::from(packet[offset + 1]) + 2) * 4
            }
            _ => return true,
        };
        if offset + length > end {
            return false;
        }
        next = packet[offset];
        offset += length;
    }
    // A chain longer than the parser's bounded traversal is rejected.
    !matches!(next, 0 | 43 | 44 | 51 | 60)
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
        ETHERTYPE_IPV4 if payload.first().is_some_and(|byte| byte >> 4 == 4) => {
            if is_dest {
                packet_destination(payload)
            } else {
                packet_source(payload)
            }
        }
        ETHERTYPE_IPV6 if payload.first().is_some_and(|byte| byte >> 4 == 6) => {
            if is_dest {
                packet_destination(payload)
            } else {
                packet_source(payload)
            }
        }
        ETHERTYPE_ARP => {
            if payload.len() < 28
                || payload[0..2] != [0, 1]
                || payload[2..4] != ETHERTYPE_IPV4.to_be_bytes()
                || payload[4] != 6
                || payload[5] != 4
                || !matches!(u16::from_be_bytes([payload[6], payload[7]]), 1 | 2)
                || frame[6..12] != payload[8..14]
            {
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
        v6[6] = 59; // No next header; valid with an empty payload.
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
    fn rejects_inconsistent_lengths_checksums_and_ether_types() {
        let mut invalid_length = ipv4([10, 42, 0, 2], [10, 42, 0, 3], 64);
        invalid_length[2..4].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(packet_source(&invalid_length), None);

        let mut invalid_checksum = ipv4([10, 42, 0, 2], [10, 42, 0, 3], 64);
        invalid_checksum[10] ^= 1;
        assert_eq!(packet_destination(&invalid_checksum), None);

        let mut mismatched = vec![0u8; ETHERNET_HEADER_LEN];
        mismatched[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        mismatched.extend_from_slice(&[0x60; IPV6_HEADER]);
        assert_eq!(ethernet_payload_ip(&mismatched, false), None);
    }

    #[test]
    fn validates_ipv6_extension_header_bounds() {
        let mut packet = vec![0u8; IPV6_HEADER + 8];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8u16.to_be_bytes());
        packet[6] = 0; // Hop-by-hop options header
        packet[8..24].copy_from_slice(&"fd42::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"fd42::3".parse::<std::net::Ipv6Addr>().unwrap().octets());
        packet[40] = 59; // No next header
        packet[41] = 0; // One 8-byte extension header
        assert_eq!(packet_source(&packet), Some("fd42::2".parse().unwrap()));

        packet[41] = 1; // Claims 16 bytes, beyond the payload
        assert_eq!(packet_source(&packet), None);
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
        frame[14..16].copy_from_slice(&1u16.to_be_bytes());
        frame[16..18].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame[18] = 6;
        frame[19] = 4;
        frame[20..22].copy_from_slice(&1u16.to_be_bytes());
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
