pub mod packet;

use ipnet::IpNet;
use packet::{
    ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, Mac, ethernet_dst_mac, ethernet_payload_ip,
    ethernet_src_mac, ethertype, is_broadcast_or_multicast_mac, packet_destination, packet_source,
};
use rvpn_core::SessionId;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

pub const MAX_MACS_PER_PEER: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DropReason {
    Malformed,
    UnsupportedEthertype,
    SourceNotAllowed,
    InvalidSourceMac,
    MacConflict,
    TooManyMacs,
    NoLink,
    Hairpin,
    UnknownSession,
}

impl DropReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed packet",
            Self::UnsupportedEthertype => "unsupported ethertype",
            Self::SourceNotAllowed => "unauthorized source address",
            Self::InvalidSourceMac => "invalid source MAC",
            Self::MacConflict => "source MAC belongs to another peer",
            Self::TooManyMacs => "too many source MACs for one peer",
            Self::NoLink => "no link between source and destination peers",
            Self::Hairpin => "destination is the sending peer",
            Self::UnknownSession => "unknown session",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delivery {
    pub local: bool,
    pub peers: Vec<SessionId>,
}

impl Delivery {
    pub fn local() -> Self {
        Self {
            local: true,
            peers: Vec::new(),
        }
    }

    pub fn to_peer(session: SessionId) -> Self {
        Self {
            local: false,
            peers: vec![session],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    Drop(DropReason),
    Forward(Delivery),
}

#[derive(Clone, Debug, Default)]
pub struct Links {
    pairs: HashSet<(String, String)>,
}

impl Links {
    pub fn from_groups<'a>(groups: impl IntoIterator<Item = &'a [String]>) -> Self {
        let mut pairs = HashSet::new();
        for group in groups {
            for (index, a) in group.iter().enumerate() {
                for b in &group[index + 1..] {
                    if a != b {
                        pairs.insert(Self::key(a, b));
                    }
                }
            }
        }
        Self { pairs }
    }

    fn key(a: &str, b: &str) -> (String, String) {
        if a <= b {
            (a.to_owned(), b.to_owned())
        } else {
            (b.to_owned(), a.to_owned())
        }
    }

    pub fn linked(&self, a: &str, b: &str) -> bool {
        a != b && self.pairs.contains(&Self::key(a, b))
    }

    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }
}

#[derive(Debug)]
struct PeerEntry {
    name: String,
    allowed_ips: Vec<IpNet>,
    linked: HashSet<SessionId>,
    macs: HashSet<Mac>,
}

impl PeerEntry {
    fn source_allowed(&self, source: IpAddr) -> bool {
        self.allowed_ips.is_empty() || self.allowed_ips.iter().any(|net| net.contains(&source))
    }
}

#[derive(Debug, Default)]
pub struct Router {
    links: Links,
    peers: HashMap<SessionId, PeerEntry>,
    table: Vec<(IpNet, SessionId)>,
    macs: HashMap<Mac, SessionId>,
}

impl Router {
    pub fn new(links: Links) -> Self {
        Self {
            links,
            ..Self::default()
        }
    }

    pub fn register(
        &mut self,
        session: SessionId,
        name: impl Into<String>,
        allowed_ips: Vec<IpNet>,
    ) {
        self.unregister(session);
        let name = name.into();
        let mut linked = HashSet::new();
        for (id, other) in self.peers.iter_mut() {
            if self.links.linked(&name, &other.name) {
                other.linked.insert(session);
                linked.insert(*id);
            }
        }
        self.peers.insert(
            session,
            PeerEntry {
                name,
                allowed_ips,
                linked,
                macs: HashSet::new(),
            },
        );
        self.rebuild_table();
    }

    pub fn unregister(&mut self, session: SessionId) {
        let Some(peer) = self.peers.remove(&session) else {
            return;
        };
        for mac in &peer.macs {
            if self.macs.get(mac) == Some(&session) {
                self.macs.remove(mac);
            }
        }
        for other in self.peers.values_mut() {
            other.linked.remove(&session);
        }
        self.rebuild_table();
    }

    pub fn contains(&self, session: SessionId) -> bool {
        self.peers.contains_key(&session)
    }

    pub fn name(&self, session: SessionId) -> Option<&str> {
        self.peers.get(&session).map(|peer| peer.name.as_str())
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    fn rebuild_table(&mut self) {
        let mut table: Vec<(IpNet, SessionId)> = self
            .peers
            .iter()
            .flat_map(|(id, peer)| peer.allowed_ips.iter().map(move |net| (*net, *id)))
            .collect();
        table.sort_by(|a, b| {
            b.0.prefix_len()
                .cmp(&a.0.prefix_len())
                .then_with(|| a.1.into_bytes().cmp(&b.1.into_bytes()))
        });
        self.table = table;
    }

    fn owner(&self, address: IpAddr) -> Option<SessionId> {
        self.table
            .iter()
            .find(|(net, _)| net.contains(&address))
            .map(|(_, id)| *id)
    }

    pub fn route_ip(&self, from: SessionId, packet: &[u8]) -> Verdict {
        let Some(peer) = self.peers.get(&from) else {
            return Verdict::Drop(DropReason::UnknownSession);
        };
        let (Some(source), Some(destination)) = (packet_source(packet), packet_destination(packet))
        else {
            return Verdict::Drop(DropReason::Malformed);
        };
        if !peer.source_allowed(source) {
            return Verdict::Drop(DropReason::SourceNotAllowed);
        }
        match self.owner(destination) {
            None => Verdict::Forward(Delivery::local()),
            Some(target) if target == from => Verdict::Drop(DropReason::Hairpin),
            Some(target) if peer.linked.contains(&target) => {
                Verdict::Forward(Delivery::to_peer(target))
            }
            Some(_) => Verdict::Drop(DropReason::NoLink),
        }
    }

    pub fn route_frame(&mut self, from: SessionId, frame: &[u8]) -> Verdict {
        if !self.peers.contains_key(&from) {
            return Verdict::Drop(DropReason::UnknownSession);
        }
        let (Some(dst_mac), Some(src_mac), Some(kind)) =
            (ethernet_dst_mac(frame), ethernet_src_mac(frame), ethertype(frame))
        else {
            return Verdict::Drop(DropReason::Malformed);
        };
        if is_broadcast_or_multicast_mac(&src_mac) {
            return Verdict::Drop(DropReason::InvalidSourceMac);
        }
        if !matches!(kind, ETHERTYPE_IPV4 | ETHERTYPE_IPV6 | ETHERTYPE_ARP) {
            return Verdict::Drop(DropReason::UnsupportedEthertype);
        }
        let Some(source_ip) = ethernet_payload_ip(frame, false) else {
            return Verdict::Drop(DropReason::Malformed);
        };
        if !self.peers[&from].source_allowed(source_ip) {
            return Verdict::Drop(DropReason::SourceNotAllowed);
        }

        let existing = self.macs.get(&src_mac).copied();
        match existing {
            Some(owner) if owner != from => return Verdict::Drop(DropReason::MacConflict),
            Some(_) => {}
            None => {
                let peer = self.peers.get_mut(&from).expect("presence checked above");
                if peer.macs.len() >= MAX_MACS_PER_PEER {
                    return Verdict::Drop(DropReason::TooManyMacs);
                }
                peer.macs.insert(src_mac);
                self.macs.insert(src_mac, from);
            }
        }

        let sender = &self.peers[&from];
        if is_broadcast_or_multicast_mac(&dst_mac) {
            let peers = self
                .peers
                .keys()
                .filter(|id| **id != from && sender.linked.contains(id))
                .copied()
                .collect();
            return Verdict::Forward(Delivery { local: true, peers });
        }
        match self.macs.get(&dst_mac).copied() {
            Some(target) if target == from => Verdict::Drop(DropReason::Hairpin),
            Some(target) if sender.linked.contains(&target) => {
                Verdict::Forward(Delivery::to_peer(target))
            }
            Some(_) => Verdict::Drop(DropReason::NoLink),
            None => Verdict::Forward(Delivery::local()),
        }
    }

    pub fn route_from_local_ip(&self, packet: &[u8]) -> Option<SessionId> {
        self.owner(packet_destination(packet)?)
    }

    pub fn route_from_local_frame(&self, frame: &[u8]) -> Vec<SessionId> {
        let everyone = || self.peers.keys().copied().collect::<Vec<_>>();
        let Some(dst_mac) = ethernet_dst_mac(frame) else {
            return Vec::new();
        };
        if is_broadcast_or_multicast_mac(&dst_mac) {
            return everyone();
        }
        if let Some(target) = self.macs.get(&dst_mac) {
            return vec![*target];
        }
        match ethernet_payload_ip(frame, true).and_then(|ip| self.owner(ip)) {
            Some(target) => vec![target],
            None => everyone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet::{ipv4_header_checksum, prepare_forward};

    fn sid(n: u8) -> SessionId {
        SessionId::new([n; 16])
    }

    fn ipv4(src: [u8; 4], dst: [u8; 4], ttl: u8) -> Vec<u8> {
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

    fn frame(dst_mac: Mac, src_mac: Mac, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(dst_mac);
        out.extend(src_mac);
        out.extend(ETHERTYPE_IPV4.to_be_bytes());
        out.extend(ipv4(src, dst, 64));
        out
    }

    const MAC_A: Mac = [0x02, 0, 0, 0, 0, 0xa1];
    const MAC_B: Mac = [0x02, 0, 0, 0, 0, 0xb2];
    const BROADCAST: Mac = [0xff; 6];

    /// laptop = session 1 (10.42.0.2), phone = 2 (.3), tablet = 3 (.4).
    fn router(links: &[&[&str]]) -> Router {
        let groups: Vec<Vec<String>> = links
            .iter()
            .map(|group| group.iter().map(|name| name.to_string()).collect())
            .collect();
        let mut router = Router::new(Links::from_groups(groups.iter().map(Vec::as_slice)));
        router.register(sid(1), "laptop", vec!["10.42.0.2/32".parse().unwrap()]);
        router.register(sid(2), "phone", vec!["10.42.0.3/32".parse().unwrap()]);
        router.register(sid(3), "tablet", vec!["10.42.0.4/32".parse().unwrap()]);
        router
    }

    #[test]
    fn peers_are_isolated_without_a_link() {
        let router = router(&[]);
        let packet = ipv4([10, 42, 0, 2], [10, 42, 0, 3], 64);
        assert_eq!(
            router.route_ip(sid(1), &packet),
            Verdict::Drop(DropReason::NoLink)
        );
    }

    #[test]
    fn a_link_is_symmetric_and_does_not_extend_to_third_peers() {
        let router = router(&[&["laptop", "phone"]]);
        let forward = ipv4([10, 42, 0, 2], [10, 42, 0, 3], 64);
        let reverse = ipv4([10, 42, 0, 3], [10, 42, 0, 2], 64);
        let to_tablet = ipv4([10, 42, 0, 2], [10, 42, 0, 4], 64);
        assert_eq!(
            router.route_ip(sid(1), &forward),
            Verdict::Forward(Delivery::to_peer(sid(2)))
        );
        assert_eq!(
            router.route_ip(sid(2), &reverse),
            Verdict::Forward(Delivery::to_peer(sid(1)))
        );
        assert_eq!(
            router.route_ip(sid(1), &to_tablet),
            Verdict::Drop(DropReason::NoLink)
        );
    }

    #[test]
    fn groups_of_three_form_a_full_mesh() {
        let router = router(&[&["laptop", "phone", "tablet"]]);
        for (from, src, dst, target) in [
            (1, [10, 42, 0, 2], [10, 42, 0, 4], 3),
            (3, [10, 42, 0, 4], [10, 42, 0, 3], 2),
            (2, [10, 42, 0, 3], [10, 42, 0, 2], 1),
        ] {
            assert_eq!(
                router.route_ip(sid(from), &ipv4(src, dst, 64)),
                Verdict::Forward(Delivery::to_peer(sid(target)))
            );
        }
    }

    #[test]
    fn spoofed_sources_are_dropped() {
        let router = router(&[&["laptop", "phone"]]);
        let packet = ipv4([10, 42, 0, 9], [10, 42, 0, 3], 64);
        assert_eq!(
            router.route_ip(sid(1), &packet),
            Verdict::Drop(DropReason::SourceNotAllowed)
        );
    }

    #[test]
    fn unowned_destinations_go_to_the_local_device() {
        let router = router(&[]);
        let packet = ipv4([10, 42, 0, 2], [1, 1, 1, 1], 64);
        assert_eq!(
            router.route_ip(sid(1), &packet),
            Verdict::Forward(Delivery::local())
        );
        let to_server = ipv4([10, 42, 0, 2], [10, 42, 0, 1], 64);
        assert_eq!(
            router.route_ip(sid(1), &to_server),
            Verdict::Forward(Delivery::local())
        );
    }

    #[test]
    fn packets_to_the_senders_own_address_are_dropped() {
        let router = router(&[]);
        let packet = ipv4([10, 42, 0, 2], [10, 42, 0, 2], 64);
        assert_eq!(
            router.route_ip(sid(1), &packet),
            Verdict::Drop(DropReason::Hairpin)
        );
    }

    #[test]
    fn longest_prefix_wins() {
        let mut router = router(&[&["laptop", "phone"]]);
        router.register(sid(4), "lan", vec!["10.42.0.0/24".parse().unwrap()]);
        let packet = ipv4([10, 42, 0, 2], [10, 42, 0, 3], 64);
        assert_eq!(
            router.route_ip(sid(1), &packet),
            Verdict::Forward(Delivery::to_peer(sid(2)))
        );
    }

    #[test]
    fn unknown_sessions_are_refused() {
        let router = router(&[]);
        let packet = ipv4([10, 42, 0, 2], [1, 1, 1, 1], 64);
        assert_eq!(
            router.route_ip(sid(9), &packet),
            Verdict::Drop(DropReason::UnknownSession)
        );
    }

    #[test]
    fn forwarded_packets_lose_one_ttl_and_keep_a_valid_checksum() {
        let packet = ipv4([10, 42, 0, 2], [10, 42, 0, 3], 64);
        let forwarded = prepare_forward(&packet).unwrap();
        assert_eq!(forwarded[8], 63);
        assert_eq!(ipv4_header_checksum(&forwarded[..20]), 0);
        assert!(prepare_forward(&ipv4([10, 42, 0, 2], [10, 42, 0, 3], 1)).is_none());
    }

    #[test]
    fn unregistering_removes_ownership() {
        let mut router = router(&[&["laptop", "phone"]]);
        router.unregister(sid(2));
        let packet = ipv4([10, 42, 0, 2], [10, 42, 0, 3], 64);
        assert_eq!(
            router.route_ip(sid(1), &packet),
            Verdict::Forward(Delivery::local())
        );
    }

    #[test]
    fn a_reconnecting_peer_is_relinked() {
        let mut router = router(&[&["laptop", "phone"]]);
        router.unregister(sid(2));
        router.register(sid(7), "phone", vec!["10.42.0.3/32".parse().unwrap()]);
        let packet = ipv4([10, 42, 0, 2], [10, 42, 0, 3], 64);
        assert_eq!(
            router.route_ip(sid(1), &packet),
            Verdict::Forward(Delivery::to_peer(sid(7)))
        );
    }

    #[test]
    fn local_traffic_is_routed_by_destination_owner() {
        let router = router(&[]);
        let packet = ipv4([10, 42, 0, 1], [10, 42, 0, 4], 64);
        assert_eq!(router.route_from_local_ip(&packet), Some(sid(3)));
        assert_eq!(
            router.route_from_local_ip(&ipv4([10, 42, 0, 1], [8, 8, 8, 8], 64)),
            None
        );
    }

    // ---- TAP mode ------------------------------------------------------

    #[test]
    fn a_mac_belongs_to_the_first_session_that_claims_it() {
        let mut router = router(&[&["laptop", "phone"]]);
        let first = frame(MAC_B, MAC_A, [10, 42, 0, 2], [10, 42, 0, 3]);
        assert_eq!(
            router.route_frame(sid(1), &first),
            Verdict::Forward(Delivery::local())
        );
        let stolen = frame(MAC_B, MAC_A, [10, 42, 0, 3], [10, 42, 0, 2]);
        assert_eq!(
            router.route_frame(sid(2), &stolen),
            Verdict::Drop(DropReason::MacConflict)
        );
    }

    #[test]
    fn a_spoofed_source_does_not_poison_the_mac_table() {
        let mut router = router(&[&["laptop", "phone"]]);
        let spoofed = frame(MAC_B, MAC_A, [10, 42, 0, 99], [10, 42, 0, 3]);
        assert_eq!(
            router.route_frame(sid(1), &spoofed),
            Verdict::Drop(DropReason::SourceNotAllowed)
        );
        let legit = frame(MAC_B, MAC_A, [10, 42, 0, 3], [10, 42, 0, 2]);
        assert_ne!(
            router.route_frame(sid(2), &legit),
            Verdict::Drop(DropReason::MacConflict)
        );
    }

    #[test]
    fn unicast_frames_follow_learned_macs_and_links() {
        let mut router = router(&[&["laptop", "phone"]]);
        let hello = frame(BROADCAST, MAC_B, [10, 42, 0, 3], [10, 42, 0, 2]);
        router.route_frame(sid(2), &hello);
        let data = frame(MAC_B, MAC_A, [10, 42, 0, 2], [10, 42, 0, 3]);
        assert_eq!(
            router.route_frame(sid(1), &data),
            Verdict::Forward(Delivery::to_peer(sid(2)))
        );

        let mut unlinked = self::router(&[]);
        unlinked.route_frame(sid(2), &hello);
        assert_eq!(
            unlinked.route_frame(sid(1), &data),
            Verdict::Drop(DropReason::NoLink)
        );
    }

    #[test]
    fn broadcasts_reach_only_linked_peers_and_the_local_device() {
        let mut router = router(&[&["laptop", "phone"]]);
        let arp_like = frame(BROADCAST, MAC_A, [10, 42, 0, 2], [10, 42, 0, 255]);
        assert_eq!(
            router.route_frame(sid(1), &arp_like),
            Verdict::Forward(Delivery {
                local: true,
                peers: vec![sid(2)],
            })
        );
    }

    #[test]
    fn unsupported_ethertypes_and_group_source_macs_are_dropped() {
        let mut router = router(&[]);
        let mut odd = frame(MAC_B, MAC_A, [10, 42, 0, 2], [10, 42, 0, 3]);
        odd[12..14].copy_from_slice(&0x88ccu16.to_be_bytes());
        assert_eq!(
            router.route_frame(sid(1), &odd),
            Verdict::Drop(DropReason::UnsupportedEthertype)
        );
        let bad_src = frame(MAC_B, BROADCAST, [10, 42, 0, 2], [10, 42, 0, 3]);
        assert_eq!(
            router.route_frame(sid(1), &bad_src),
            Verdict::Drop(DropReason::InvalidSourceMac)
        );
    }

    #[test]
    fn a_peer_cannot_claim_unbounded_macs() {
        let mut router = router(&[]);
        let mut last = Verdict::Forward(Delivery::local());
        for index in 0..=MAX_MACS_PER_PEER as u8 {
            let mac = [0x02, 0, 0, 0, 1, index];
            last = router.route_frame(sid(1), &frame(MAC_B, mac, [10, 42, 0, 2], [10, 42, 0, 3]));
        }
        assert_eq!(last, Verdict::Drop(DropReason::TooManyMacs));
    }

    #[test]
    fn unregistering_releases_macs() {
        let mut router = router(&[&["laptop", "phone"]]);
        router.route_frame(
            sid(2),
            &frame(BROADCAST, MAC_B, [10, 42, 0, 3], [10, 42, 0, 2]),
        );
        router.unregister(sid(2));
        let data = frame(MAC_B, MAC_A, [10, 42, 0, 2], [10, 42, 0, 3]);
        assert_eq!(
            router.route_frame(sid(1), &data),
            Verdict::Forward(Delivery::local())
        );
    }

    #[test]
    fn local_frames_use_the_mac_table_then_ip_ownership_then_flood() {
        let mut router = router(&[]);
        router.route_frame(
            sid(2),
            &frame(BROADCAST, MAC_B, [10, 42, 0, 3], [10, 42, 0, 1]),
        );
        let to_phone = frame(MAC_B, MAC_A, [10, 42, 0, 1], [10, 42, 0, 3]);
        assert_eq!(router.route_from_local_frame(&to_phone), vec![sid(2)]);

        let by_ip = frame([0x02, 0, 0, 0, 9, 9], MAC_A, [10, 42, 0, 1], [10, 42, 0, 4]);
        assert_eq!(router.route_from_local_frame(&by_ip), vec![sid(3)]);

        let unknown = frame([0x02, 0, 0, 0, 9, 9], MAC_A, [10, 42, 0, 1], [8, 8, 8, 8]);
        assert_eq!(router.route_from_local_frame(&unknown).len(), 3);
    }
}