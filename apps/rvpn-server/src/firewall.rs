//! Linux IP forwarding, firewall NAT rules (nftables and iptables), and teardown guards.

use anyhow::{Context, Result};
use rvpn_config::{FirewallBackend, ForwardingConfig};
use std::fs;
use tokio::process::Command;

use crate::network::run;

pub enum FirewallMethod {
    Nftables,
    Iptables {
        rules: Vec<(&'static str, Vec<String>)>,
    },
}

pub struct ForwardingGuard {
    previous_ipv4_forward: Option<String>,
    previous_ipv6_forward: Option<String>,
    method: Option<FirewallMethod>,
}

impl ForwardingGuard {
    pub async fn install(config: &ForwardingConfig, tunnel: &str) -> Result<Self> {
        if !config.enabled {
            return Ok(Self {
                previous_ipv4_forward: None,
                previous_ipv6_forward: None,
                method: None,
            });
        }
        let previous_ipv4_forward = if config.tunnel_cidr.is_some() {
            let previous = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
                .context("reading IPv4 forwarding state")?;
            fs::write("/proc/sys/net/ipv4/ip_forward", "1\n")
                .context("enabling IPv4 forwarding")?;
            Some(previous)
        } else {
            None
        };
        let previous_ipv6_forward = if config.tunnel_cidr_v6.is_some() {
            let previous = fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding")
                .context("reading IPv6 forwarding state")?;
            fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1\n")
                .context("enabling IPv6 forwarding")?;
            Some(previous)
        } else {
            None
        };
        let external = config.external_interface.as_deref().expect("validated");
        let use_nft = match config.backend {
            FirewallBackend::Nftables => true,
            FirewallBackend::Iptables => false,
            FirewallBackend::Auto => {
                Command::new("nft")
                    .arg("--version")
                    .output()
                    .await
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            }
        };

        if use_nft {
            run("nft", ["add", "table", "inet", "rvpn"]).await?;
            run(
                "nft",
                [
                    "add", "chain", "inet", "rvpn", "forward", "{", "type", "filter", "hook",
                    "forward", "priority", "filter;", "policy", "drop;", "}",
                ],
            )
            .await?;
            run(
                "nft",
                [
                    "add", "rule", "inet", "rvpn", "forward", "iifname", tunnel, "oifname", external,
                    "accept",
                ],
            )
            .await?;
            run(
                "nft",
                [
                    "add",
                    "rule",
                    "inet",
                    "rvpn",
                    "forward",
                    "iifname",
                    external,
                    "oifname",
                    tunnel,
                    "ct",
                    "state",
                    "established,related",
                    "accept",
                ],
            )
            .await?;
            run(
                "nft",
                [
                    "add",
                    "chain",
                    "inet",
                    "rvpn",
                    "postrouting",
                    "{",
                    "type",
                    "nat",
                    "hook",
                    "postrouting",
                    "priority",
                    "srcnat;",
                    "}",
                ],
            )
            .await?;
            if let Some(cidr) = &config.tunnel_cidr {
                run(
                    "nft",
                    [
                        "add",
                        "rule",
                        "inet",
                        "rvpn",
                        "postrouting",
                        "ip",
                        "saddr",
                        cidr,
                        "oifname",
                        external,
                        "masquerade",
                    ],
                )
                .await?;
            }
            if let Some(cidr) = &config.tunnel_cidr_v6 {
                run(
                    "nft",
                    [
                        "add",
                        "rule",
                        "inet",
                        "rvpn",
                        "postrouting",
                        "ip6",
                        "saddr",
                        cidr,
                        "oifname",
                        external,
                        "masquerade",
                    ],
                )
                .await?;
            }
            tracing::info!(backend = "nftables", "installed RVPN firewall rules");
            Ok(Self {
                previous_ipv4_forward,
                previous_ipv6_forward,
                method: Some(FirewallMethod::Nftables),
            })
        } else {
            let mut cleanup_rules = Vec::new();
            if config.tunnel_cidr.is_some() {
                run(
                    "iptables",
                    ["-I", "FORWARD", "1", "-i", tunnel, "-o", external, "-j", "ACCEPT"],
                )
                .await?;
                cleanup_rules.push((
                    "iptables",
                    vec![
                        "-D".into(),
                        "FORWARD".into(),
                        "-i".into(),
                        tunnel.into(),
                        "-o".into(),
                        external.into(),
                        "-j".into(),
                        "ACCEPT".into(),
                    ],
                ));

                run(
                    "iptables",
                    [
                        "-I",
                        "FORWARD",
                        "1",
                        "-i",
                        external,
                        "-o",
                        tunnel,
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "ESTABLISHED,RELATED",
                        "-j",
                        "ACCEPT",
                    ],
                )
                .await?;
                cleanup_rules.push((
                    "iptables",
                    vec![
                        "-D".into(),
                        "FORWARD".into(),
                        "-i".into(),
                        external.into(),
                        "-o".into(),
                        tunnel.into(),
                        "-m".into(),
                        "conntrack".into(),
                        "--ctstate".into(),
                        "ESTABLISHED,RELATED".into(),
                        "-j".into(),
                        "ACCEPT".into(),
                    ],
                ));

                if let Some(cidr) = &config.tunnel_cidr {
                    run(
                        "iptables",
                        ["-t", "nat", "-I", "POSTROUTING", "1", "-s", cidr, "-o", external, "-j", "MASQUERADE"],
                    )
                    .await?;
                    cleanup_rules.push((
                        "iptables",
                        vec![
                            "-t".into(),
                            "nat".into(),
                            "-D".into(),
                            "POSTROUTING".into(),
                            "-s".into(),
                            cidr.clone(),
                            "-o".into(),
                            external.into(),
                            "-j".into(),
                            "MASQUERADE".into(),
                        ],
                    ));
                }
            }
            if config.tunnel_cidr_v6.is_some() {
                run(
                    "ip6tables",
                    ["-I", "FORWARD", "1", "-i", tunnel, "-o", external, "-j", "ACCEPT"],
                )
                .await?;
                cleanup_rules.push((
                    "ip6tables",
                    vec![
                        "-D".into(),
                        "FORWARD".into(),
                        "-i".into(),
                        tunnel.into(),
                        "-o".into(),
                        external.into(),
                        "-j".into(),
                        "ACCEPT".into(),
                    ],
                ));

                run(
                    "ip6tables",
                    [
                        "-I",
                        "FORWARD",
                        "1",
                        "-i",
                        external,
                        "-o",
                        tunnel,
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "ESTABLISHED,RELATED",
                        "-j",
                        "ACCEPT",
                    ],
                )
                .await?;
                cleanup_rules.push((
                    "ip6tables",
                    vec![
                        "-D".into(),
                        "FORWARD".into(),
                        "-i".into(),
                        external.into(),
                        "-o".into(),
                        tunnel.into(),
                        "-m".into(),
                        "conntrack".into(),
                        "--ctstate".into(),
                        "ESTABLISHED,RELATED".into(),
                        "-j".into(),
                        "ACCEPT".into(),
                    ],
                ));

                if let Some(cidr) = &config.tunnel_cidr_v6 {
                    run(
                        "ip6tables",
                        [
                            "-t",
                            "nat",
                            "-I",
                            "POSTROUTING",
                            "1",
                            "-s",
                            cidr,
                            "-o",
                            external,
                            "-j",
                            "MASQUERADE",
                        ],
                    )
                    .await?;
                    cleanup_rules.push((
                        "ip6tables",
                        vec![
                            "-t".into(),
                            "nat".into(),
                            "-D".into(),
                            "POSTROUTING".into(),
                            "-s".into(),
                            cidr.clone(),
                            "-o".into(),
                            external.into(),
                            "-j".into(),
                            "MASQUERADE".into(),
                        ],
                    ));
                }
            }
            tracing::info!(backend = "iptables", "installed RVPN firewall rules");
            Ok(Self {
                previous_ipv4_forward,
                previous_ipv6_forward,
                method: Some(FirewallMethod::Iptables {
                    rules: cleanup_rules,
                }),
            })
        }
    }

    pub async fn cleanup(&self) {
        match &self.method {
            Some(FirewallMethod::Nftables) => {
                let _ = run("nft", ["delete", "table", "inet", "rvpn"]).await;
            }
            Some(FirewallMethod::Iptables { rules }) => {
                for (cmd, args) in rules {
                    let _ = run(cmd, args.iter().map(String::as_str)).await;
                }
            }
            None => {}
        }
        if let Some(previous) = &self.previous_ipv4_forward {
            let _ = fs::write("/proc/sys/net/ipv4/ip_forward", previous);
        }
        if let Some(previous) = &self.previous_ipv6_forward {
            let _ = fs::write("/proc/sys/net/ipv6/conf/all/forwarding", previous);
        }
    }
}
