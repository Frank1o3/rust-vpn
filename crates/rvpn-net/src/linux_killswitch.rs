use crate::{KillSwitchSpec, NetError};
use nftnl::{Batch, Chain, ChainType, Policy, ProtoFamily, Rule, Table, nft_expr};
use std::{ffi::CStr, net::SocketAddr};

const CHAIN_NAME: &CStr = c"output";
const OUTPUT_HOOK_PRIORITY: i32 = -100;

#[derive(Clone, Debug, Eq, PartialEq)]
enum OutputRule {
    AcceptInterface {
        uid: u32,
        name: String,
    },
    AcceptEndpoint {
        uid: u32,
        endpoint: SocketAddr,
    },
    DropDns {
        protocol: u8,
        tunnel_interface: String,
    },
    DropUid {
        uid: u32,
    },
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct OutputPacket<'a> {
    uid: u32,
    interface: &'a str,
    protocol: u8,
    destination: Option<SocketAddr>,
}

#[cfg(test)]
fn policy_allows(rules: &[OutputRule], packet: OutputPacket<'_>) -> bool {
    for rule in rules {
        match rule {
            OutputRule::AcceptInterface { uid, name }
                if packet.uid == *uid && packet.interface == name =>
            {
                return true;
            }
            OutputRule::AcceptEndpoint { uid, endpoint }
                if packet.uid == *uid
                    && packet.protocol == 17
                    && packet.destination == Some(*endpoint) =>
            {
                return true;
            }
            OutputRule::DropDns {
                protocol,
                tunnel_interface,
            } if packet.protocol == *protocol
                && packet
                    .destination
                    .is_some_and(|endpoint| endpoint.port() == 53)
                && packet.interface != "lo"
                && packet.interface != tunnel_interface =>
            {
                return false;
            }
            OutputRule::DropUid { uid } if packet.uid == *uid => return false,
            _ => {}
        }
    }
    true
}

fn output_rules(spec: &KillSwitchSpec) -> [OutputRule; 6] {
    [
        OutputRule::AcceptInterface {
            uid: spec.uid,
            name: "lo".to_owned(),
        },
        OutputRule::AcceptInterface {
            uid: spec.uid,
            name: spec.tunnel_interface.clone(),
        },
        OutputRule::AcceptEndpoint {
            uid: spec.uid,
            endpoint: spec.endpoint,
        },
        OutputRule::DropDns {
            protocol: 17,
            tunnel_interface: spec.tunnel_interface.clone(),
        },
        OutputRule::DropDns {
            protocol: 6,
            tunnel_interface: spec.tunnel_interface.clone(),
        },
        OutputRule::DropUid { uid: spec.uid },
    ]
}

fn table_name(uid: u32) -> String {
    format!("rvpn_ks_{uid}")
}

pub fn install(spec: &KillSwitchSpec) -> Result<(), NetError> {
    match send_batch(build_batch(spec, true)?) {
        Ok(()) => {}
        Err(error) if is_missing_table_error(&error) => {
            // First installation has nothing to replace. The replacement path
            // is a single nftables transaction, so a failed update leaves the
            // previous policy installed.
            send_batch(build_batch(spec, false)?)?;
        }
        Err(error) => return Err(error),
    }
    tracing::info!(uid = spec.uid, endpoint = %spec.endpoint, tunnel = %spec.tunnel_interface, "installed persistent RVPN kill switch");
    Ok(())
}

fn build_batch(spec: &KillSwitchSpec, replace: bool) -> Result<Batch, NetError> {
    let table_name = table_name(spec.uid);
    let table_c = std::ffi::CString::new(table_name.clone())
        .map_err(|_| NetError::Operation("invalid nftables table name".into()))?;
    std::ffi::CString::new(spec.tunnel_interface.clone())
        .map_err(|_| NetError::Operation("invalid tunnel interface name".into()))?;

    let mut batch = Batch::new();
    let table = Table::new(table_c.as_c_str(), ProtoFamily::Inet);
    if replace {
        batch.add(&table, nftnl::MsgType::Del);
    }
    batch.add(&table, nftnl::MsgType::Add);

    let mut chain = Chain::new(CHAIN_NAME, &table);
    chain.set_type(ChainType::Filter);
    chain.set_hook(nftnl::Hook::Out, OUTPUT_HOOK_PRIORITY);
    chain.set_policy(Policy::Accept);
    batch.add(&chain, nftnl::MsgType::Add);

    for rule in output_rules(spec) {
        match rule {
            OutputRule::AcceptInterface { uid, name } => {
                add_interface_accept(&mut batch, &chain, uid, name.as_bytes())?;
            }
            OutputRule::AcceptEndpoint { uid, endpoint } => {
                add_endpoint_accept(&mut batch, &chain, uid, endpoint)?;
            }
            OutputRule::DropDns {
                protocol,
                tunnel_interface,
            } => add_dns_drop(&mut batch, &chain, &tunnel_interface, protocol),
            OutputRule::DropUid { uid } => add_uid_drop(&mut batch, &chain, uid),
        }
    }

    Ok(batch)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(endpoint: &str) -> KillSwitchSpec {
        KillSwitchSpec {
            endpoint: endpoint.parse().unwrap(),
            tunnel_interface: "rvpn0".into(),
            uid: 1001,
        }
    }

    #[test]
    fn uid_rules_only_allow_loopback_tunnel_and_the_exact_udp_endpoint() {
        let rules = output_rules(&spec("198.51.100.9:51820"));
        assert_eq!(
            rules,
            [
                OutputRule::AcceptInterface {
                    uid: 1001,
                    name: "lo".into()
                },
                OutputRule::AcceptInterface {
                    uid: 1001,
                    name: "rvpn0".into()
                },
                OutputRule::AcceptEndpoint {
                    uid: 1001,
                    endpoint: "198.51.100.9:51820".parse().unwrap()
                },
                OutputRule::DropDns {
                    protocol: 17,
                    tunnel_interface: "rvpn0".into()
                },
                OutputRule::DropDns {
                    protocol: 6,
                    tunnel_interface: "rvpn0".into()
                },
                OutputRule::DropUid { uid: 1001 }
            ]
        );
    }

    #[test]
    fn endpoint_rule_preserves_ipv6_address_and_port() {
        assert_eq!(
            output_rules(&spec("[2001:db8::9]:51820")).get(2),
            Some(&OutputRule::AcceptEndpoint {
                uid: 1001,
                endpoint: "[2001:db8::9]:51820".parse().unwrap()
            })
        );
    }

    #[test]
    fn policy_fails_closed_for_other_protocols_addresses_and_dns() {
        let rules = output_rules(&spec("[2001:db8::9]:51820"));
        let packet = |protocol, destination| OutputPacket {
            uid: 1001,
            interface: "eth0",
            protocol,
            destination,
        };

        assert!(policy_allows(
            &rules,
            packet(17, Some("[2001:db8::9]:51820".parse().unwrap()))
        ));
        assert!(policy_allows(
            &rules,
            OutputPacket {
                uid: 1001,
                interface: "lo",
                protocol: 6,
                destination: None,
            }
        ));
        assert!(policy_allows(
            &rules,
            OutputPacket {
                uid: 1001,
                interface: "rvpn0",
                protocol: 17,
                destination: None,
            }
        ));
        assert!(!policy_allows(&rules, packet(17, None)));
        assert!(!policy_allows(
            &rules,
            packet(17, Some("[2001:db8::9]:53".parse().unwrap()))
        ));
        assert!(!policy_allows(
            &rules,
            packet(17, Some("192.0.2.53:53".parse().unwrap()))
        ));
        assert!(!policy_allows(
            &rules,
            packet(6, Some("[2001:db8::9]:51820".parse().unwrap()))
        ));
        assert!(!policy_allows(
            &rules,
            packet(17, Some("[2001:db8::10]:51820".parse().unwrap()))
        ));
        assert!(policy_allows(
            &rules,
            OutputPacket {
                uid: 2002,
                interface: "lo",
                protocol: 17,
                destination: Some("192.0.2.53:53".parse().unwrap()),
            }
        ));
        assert!(policy_allows(
            &rules,
            OutputPacket {
                uid: 2002,
                interface: "rvpn0",
                protocol: 17,
                destination: Some("192.0.2.53:53".parse().unwrap()),
            }
        ));
        assert!(!policy_allows(
            &rules,
            OutputPacket {
                uid: 2002,
                interface: "eth0",
                protocol: 17,
                destination: Some("192.0.2.53:53".parse().unwrap()),
            }
        ));
        assert!(!policy_allows(
            &rules,
            OutputPacket {
                uid: 2002,
                interface: "eth0",
                protocol: 6,
                destination: Some("[2001:db8::53]:53".parse().unwrap()),
            }
        ));
    }

    #[test]
    fn replacement_batch_contains_atomic_delete_and_reinstall() {
        let spec = spec("192.0.2.1:51820");
        let replacement = build_batch(&spec, true).unwrap().finalize();
        let first_install = build_batch(&spec, false).unwrap().finalize();
        assert_eq!(
            replacement.sequence_numbers().len(),
            first_install.sequence_numbers().len() + 1
        );
    }
}

pub fn remove(uid: u32) -> Result<(), NetError> {
    delete_table(uid)
}

fn add_interface_accept(
    batch: &mut Batch,
    chain: &Chain,
    uid: u32,
    interface: &[u8],
) -> Result<(), NetError> {
    let mut rule = Rule::new(chain);
    rule.add_expr(&nft_expr!(meta skuid));
    rule.add_expr(&nft_expr!(cmp == uid));
    rule.add_expr(&nft_expr!(meta oifname));
    rule.add_expr(&nft_expr!(cmp == interface));
    rule.add_expr(&nft_expr!(verdict accept));
    batch.add(&rule, nftnl::MsgType::Add);
    Ok(())
}

fn add_endpoint_accept(
    batch: &mut Batch,
    chain: &Chain,
    uid: u32,
    endpoint: SocketAddr,
) -> Result<(), NetError> {
    let mut rule = Rule::new(chain);
    rule.add_expr(&nft_expr!(meta skuid));
    rule.add_expr(&nft_expr!(cmp == uid));
    rule.add_expr(&nft_expr!(meta l4proto));
    rule.add_expr(&nft_expr!(cmp == 17_u8));

    match endpoint.ip() {
        std::net::IpAddr::V4(ip) => {
            rule.add_expr(&nft_expr!(meta nfproto));
            rule.add_expr(&nft_expr!(cmp == 2_u8));
            rule.add_expr(&nft_expr!(payload ipv4 daddr));
            rule.add_expr(&nft_expr!(cmp == ip));
        }
        std::net::IpAddr::V6(ip) => {
            rule.add_expr(&nft_expr!(meta nfproto));
            rule.add_expr(&nft_expr!(cmp == 10_u8));
            rule.add_expr(&nft_expr!(payload ipv6 daddr));
            rule.add_expr(&nft_expr!(cmp == ip));
        }
    }

    rule.add_expr(&nft_expr!(payload udp dport));
    rule.add_expr(&nft_expr!(cmp == endpoint.port().to_be()));
    rule.add_expr(&nft_expr!(verdict accept));
    batch.add(&rule, nftnl::MsgType::Add);
    Ok(())
}

fn add_uid_drop(batch: &mut Batch, chain: &Chain, uid: u32) {
    let mut rule = Rule::new(chain);
    rule.add_expr(&nft_expr!(meta skuid));
    rule.add_expr(&nft_expr!(cmp == uid));
    rule.add_expr(&nft_expr!(verdict drop));
    batch.add(&rule, nftnl::MsgType::Add);
}

fn add_dns_drop(batch: &mut Batch, chain: &Chain, tunnel_interface: &str, protocol: u8) {
    let mut rule = Rule::new(chain);
    rule.add_expr(&nft_expr!(meta oifname));
    rule.add_expr(&nft_expr!(cmp != &b"lo"[..]));
    rule.add_expr(&nft_expr!(meta oifname));
    rule.add_expr(&nft_expr!(cmp != tunnel_interface.as_bytes()));
    rule.add_expr(&nft_expr!(meta l4proto));
    rule.add_expr(&nft_expr!(cmp == protocol));
    if protocol == 17 {
        rule.add_expr(&nft_expr!(payload udp dport));
    } else {
        rule.add_expr(&nft_expr!(payload tcp dport));
    }
    rule.add_expr(&nft_expr!(cmp == 53_u16.to_be()));
    rule.add_expr(&nft_expr!(verdict drop));
    batch.add(&rule, nftnl::MsgType::Add);
}

fn delete_table(uid: u32) -> Result<(), NetError> {
    let table_name = table_name(uid);
    let table_c = std::ffi::CString::new(table_name)
        .map_err(|_| NetError::Operation("invalid nftables table name".into()))?;
    let mut batch = Batch::new();
    let table = Table::new(table_c.as_c_str(), ProtoFamily::Inet);
    batch.add(&table, nftnl::MsgType::Del);
    match send_batch(batch) {
        Ok(()) => Ok(()),
        Err(error) => {
            // The table not existing is safe during startup/teardown. Preserve other errors.
            let message = error.to_string();
            if message.contains("No such file")
                || message.contains("No such file or directory")
                || message.contains("ENOENT")
            {
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

fn is_missing_table_error(error: &NetError) -> bool {
    let message = error.to_string();
    message.contains("No such file")
        || message.contains("No such file or directory")
        || message.contains("ENOENT")
}

fn send_batch(batch: Batch) -> Result<(), NetError> {
    let finalized = batch.finalize();
    let socket =
        mnl::Socket::new(mnl::Bus::Netfilter).map_err(|e| NetError::Operation(e.to_string()))?;
    let portid = socket.portid();

    socket
        .send_all(&finalized)
        .map_err(|e| NetError::Operation(e.to_string()))?;

    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let mut expected = finalized.sequence_numbers();

    while !expected.is_empty() {
        for message in socket
            .recv(&mut buffer)
            .map_err(|e| NetError::Operation(e.to_string()))?
        {
            let message = message.map_err(|e| NetError::Operation(e.to_string()))?;
            let seq = expected
                .next()
                .ok_or_else(|| NetError::Operation("unexpected nftables ACK".into()))?;
            mnl::cb_run(message, seq, portid).map_err(|e| NetError::Operation(e.to_string()))?;
        }
    }
    Ok(())
}
