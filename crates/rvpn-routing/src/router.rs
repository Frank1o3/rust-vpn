use ipnet::IpNet;
use crate::packet::{
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

