use anyhow::{Context, Result, bail};
use rvpn_config::{FirewallBackend, ForwardingConfig};
use std::{fs, process::Command as StdCommand};
use tokio::process::Command;

const IPV4_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
const IPV6_FORWARD: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

async fn run<I, S>(program: &str, args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let args: Vec<S> = args.into_iter().collect();
    let status = Command::new(program)
        .args(&args)
        .status()
        .await
        .with_context(|| format!("running {program}"))?;
    if !status.success() {
        bail!("{program} exited with status {status}");
    }
    Ok(())
}
struct CleanupCommand {
    program: &'static str,
    args: Vec<String>,
}

impl CleanupCommand {
    fn new(program: &'static str, args: &[&str]) -> Self {
        Self {
            program,
            args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        }
    }
}

pub struct ForwardingGuard {
    sysctls: Vec<(&'static str, String)>,
    cleanup: Vec<CleanupCommand>,
}

impl ForwardingGuard {
    pub async fn install(config: &ForwardingConfig, tunnel: &str, mtu: u16) -> Result<Self> {
        let mut guard = Self {
            sysctls: Vec::new(),
            cleanup: Vec::new(),
        };
        if !config.enabled {
            return Ok(guard);
        }

        if config.tunnel_cidr.is_some() {
            guard.enable_sysctl(IPV4_FORWARD, "IPv4 forwarding")?;
        }
        if config.tunnel_cidr_v6.is_some() {
            guard.enable_sysctl(IPV6_FORWARD, "IPv6 forwarding")?;
        }

        let external = config
            .external_interface
            .as_deref()
            .context("forwarding.external_interface is required when forwarding is enabled")?;

        let use_nft = match config.backend {
            FirewallBackend::Nftables => true,
            FirewallBackend::Iptables => false,
            FirewallBackend::Auto => Command::new("nft")
                .arg("--version")
                .output()
                .await
                .map(|output| output.status.success())
                .unwrap_or(false),
        };

        if use_nft {
            guard
                .install_nftables(config, tunnel, external, mtu)
                .await?;
            tracing::info!(backend = "nftables", "installed RVPN firewall rules");
        } else {
            guard
                .install_iptables(config, tunnel, external, mtu)
                .await?;
            tracing::info!(backend = "iptables", "installed RVPN firewall rules");
        }
        Ok(guard)
    }

    fn enable_sysctl(&mut self, path: &'static str, label: &str) -> Result<()> {
        let previous =
            fs::read_to_string(path).with_context(|| format!("reading {label} state"))?;
        if previous.trim() == "1" {
            return Ok(());
        }
        fs::write(path, "1\n").with_context(|| {
            format!(
                "enabling {label} failed; when RVPN runs as an unprivileged user, enable it \
                 persistently in /etc/sysctl.d instead"
            )
        })?;
        self.sysctls.push((path, previous));
        Ok(())
    }

    async fn install_nftables(
        &mut self,
        config: &ForwardingConfig,
        tunnel: &str,
        external: &str,
        mtu: u16,
    ) -> Result<()> {
        let _ = run("nft", ["delete", "table", "inet", "rvpn"]).await;
        run("nft", ["add", "table", "inet", "rvpn"]).await?;
        self.cleanup.push(CleanupCommand::new(
            "nft",
            &["delete", "table", "inet", "rvpn"],
        ));

        let mss_v4 = mtu.saturating_sub(40).max(536);
        let mss_v6 = mtu.saturating_sub(60).max(1220);

        let mut rules: Vec<Vec<&str>> = vec![
            vec![
                "add", "chain", "inet", "rvpn", "forward", "{", "type", "filter", "hook",
                "forward", "priority", "filter;", "policy", "accept;", "}",
            ],
            vec![
                "add",
                "rule",
                "inet",
                "rvpn",
                "forward",
                "iifname",
                tunnel,
                "oifname",
                external,
                "meta",
                "nfproto",
                "ipv4",
                "tcp",
                "flags",
                "syn",
                "tcp",
                "option",
                "maxseg",
                "size",
                "set",
                Box::leak(mss_v4.to_string().into_boxed_str()),
            ],
            vec![
                "add",
                "rule",
                "inet",
                "rvpn",
                "forward",
                "iifname",
                tunnel,
                "oifname",
                external,
                "meta",
                "nfproto",
                "ipv6",
                "tcp",
                "flags",
                "syn",
                "tcp",
                "option",
                "maxseg",
                "size",
                "set",
                Box::leak(mss_v6.to_string().into_boxed_str()),
            ],
            vec![
                "add",
                "rule",
                "inet",
                "rvpn",
                "forward",
                "iifname",
                external,
                "oifname",
                tunnel,
                "meta",
                "nfproto",
                "ipv4",
                "tcp",
                "flags",
                "syn",
                "tcp",
                "option",
                "maxseg",
                "size",
                "set",
                Box::leak(mss_v4.to_string().into_boxed_str()),
            ],
            vec![
                "add",
                "rule",
                "inet",
                "rvpn",
                "forward",
                "iifname",
                external,
                "oifname",
                tunnel,
                "meta",
                "nfproto",
                "ipv6",
                "tcp",
                "flags",
                "syn",
                "tcp",
                "option",
                "maxseg",
                "size",
                "set",
                Box::leak(mss_v6.to_string().into_boxed_str()),
            ],
            vec![
                "add", "rule", "inet", "rvpn", "forward", "iifname", tunnel, "oifname", external,
                "accept",
            ],
            vec![
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
            vec![
                "add", "rule", "inet", "rvpn", "forward", "iifname", tunnel, "drop",
            ],
            vec![
                "add", "rule", "inet", "rvpn", "forward", "oifname", tunnel, "drop",
            ],
            vec![
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
        ];
        if let Some(cidr) = &config.tunnel_cidr {
            rules.push(vec![
                "add",
                "rule",
                "inet",
                "rvpn",
                "postrouting",
                "ip",
                "saddr",
                cidr.as_str(),
                "oifname",
                external,
                "masquerade",
            ]);
        }
        if let Some(cidr) = &config.tunnel_cidr_v6 {
            rules.push(vec![
                "add",
                "rule",
                "inet",
                "rvpn",
                "postrouting",
                "ip6",
                "saddr",
                cidr.as_str(),
                "oifname",
                external,
                "masquerade",
            ]);
        }
        for rule in rules {
            run("nft", rule).await?;
        }
        Ok(())
    }

    async fn install_iptables(
        &mut self,
        config: &ForwardingConfig,
        tunnel: &str,
        external: &str,
        mtu: u16,
    ) -> Result<()> {
        if let Some(cidr) = &config.tunnel_cidr {
            self.install_iptables_family("iptables", tunnel, external, cidr, mtu)
                .await?;
        }
        if let Some(cidr) = &config.tunnel_cidr_v6 {
            self.install_iptables_family("ip6tables", tunnel, external, cidr, mtu)
                .await?;
        }
        Ok(())
    }

    async fn install_iptables_family(
        &mut self,
        binary: &'static str,
        tunnel: &str,
        external: &str,
        cidr: &str,
        mtu: u16,
    ) -> Result<()> {
        let mss = if binary == "iptables" {
            mtu.saturating_sub(40).max(536)
        } else {
            mtu.saturating_sub(60).max(1220)
        };
        let mss_value = mss.to_string();
        let rules: [(Option<&str>, &str, Vec<&str>); 5] = [
            (
                None,
                "FORWARD",
                vec!["-i", tunnel, "-o", external, "-j", "ACCEPT"],
            ),
            (
                None,
                "FORWARD",
                vec![
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
            ),
            (
                Some("nat"),
                "POSTROUTING",
                vec!["-s", cidr, "-o", external, "-j", "MASQUERADE"],
            ),
            (
                Some("mangle"),
                "FORWARD",
                vec![
                    "-i",
                    tunnel,
                    "-o",
                    external,
                    "-p",
                    "tcp",
                    "--tcp-flags",
                    "SYN,RST",
                    "SYN",
                    "-j",
                    "TCPMSS",
                    "--set-mss",
                    &mss_value,
                ],
            ),
            (
                Some("mangle"),
                "FORWARD",
                vec![
                    "-i",
                    external,
                    "-o",
                    tunnel,
                    "-p",
                    "tcp",
                    "--tcp-flags",
                    "SYN,RST",
                    "SYN",
                    "-j",
                    "TCPMSS",
                    "--set-mss",
                    &mss_value,
                ],
            ),
        ];

        for (table, chain, spec) in rules {
            let table_args: Vec<&str> = match table {
                Some(table) => vec!["-t", table],
                None => Vec::new(),
            };

            let mut check = table_args.clone();
            check.extend(["-C", chain]);
            check.extend(spec.iter().copied());
            if run(binary, check).await.is_err() {
                let mut insert = table_args.clone();
                insert.extend(["-I", chain, "1"]);
                insert.extend(spec.iter().copied());
                run(binary, insert).await?;
            }

            let mut delete = table_args;
            delete.extend(["-D", chain]);
            delete.extend(spec.iter().copied());
            self.cleanup.push(CleanupCommand::new(binary, &delete));
        }
        Ok(())
    }

    pub fn cleanup(&mut self) {
        for command in self.cleanup.drain(..).rev() {
            let _ = StdCommand::new(command.program)
                .args(&command.args)
                .output();
        }
        for (path, previous) in self.sysctls.drain(..) {
            let _ = fs::write(path, previous);
        }
    }
}

impl Drop for ForwardingGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
}
