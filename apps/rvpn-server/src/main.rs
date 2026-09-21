mod firewall;
mod handshake;
mod network;
mod state;
mod tunnel;

use anyhow::{Context, Result};
use rvpn_config::{DeviceMode, ServerConfig};
use rvpn_crypto::AEAD_TAG_LEN;
use rvpn_interface::{DEFAULT_MTU, TunConfig, VirtualInterface};
use rvpn_protocol::HEADER_LEN;
use rvpn_transport::{TransportConfig, UdpTransport, default_udp_payload_mtu};
use std::{env, fs};

use firewall::ForwardingGuard;
use network::configure_server_interface;
use tunnel::run_server_loop;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let path = env::args()
        .nth(1)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(rvpn_config::default_server_config_path);
    let config = ServerConfig::from_toml(&fs::read_to_string(&path).with_context(|| {
        format!(
            "reading {} (pass a path as the first argument to override)",
            path.display()
        )
    })?)?;
    let identities = config.peer_identities()?;
    let certificate_authority = config.certificate_authority.clone();
    let obfuscation = config
        .obfuscation_key_bytes()?
        .map(rvpn_crypto::ObfuscationKey::from_bytes);
    let cookie_key =
        rvpn_crypto::CookieKey::generate().context("generating anti-amplification cookie key")?;
    let mode = config.interface.mode();
    let requested_mtu = config.interface.mtu.unwrap_or(DEFAULT_MTU);
    let frame_overhead = match mode {
        DeviceMode::Tun => 0,
        DeviceMode::Tap | DeviceMode::Both => 18,
    };
    let wire_overhead = frame_overhead
        + HEADER_LEN
        + AEAD_TAG_LEN
        + if obfuscation.is_some() {
            rvpn_crypto::OBFUSCATION_OVERHEAD
        } else {
            0
        };
    let mtu = effective_tunnel_mtu(requested_mtu, wire_overhead, config.bind.is_ipv6());
    if mtu < requested_mtu {
        tracing::warn!(
            requested_mtu,
            effective_mtu = mtu,
            wire_overhead,
            "reduced tunnel MTU so encrypted UDP packets fit a standard path"
        );
    }
    let transport = UdpTransport::open(TransportConfig {
        local_address: config.bind,
        remote_address: None,
        max_datagram_size: usize::from(mtu) + wire_overhead,
    })
    .await?;

    let (tun, tap) = match mode {
        DeviceMode::Tun => {
            let dev = VirtualInterface::create(TunConfig {
                name: config.interface.name.clone(),
                mtu,
                mode: DeviceMode::Tun,
            })
            .await?;
            (Some(dev), None)
        }
        DeviceMode::Tap => {
            let dev = VirtualInterface::create(TunConfig {
                name: config.interface.name.clone(),
                mtu,
                mode: DeviceMode::Tap,
            })
            .await?;
            (None, Some(dev))
        }
        DeviceMode::Both => {
            let tun_name = config.interface.name.clone();
            let tap_name = config.interface.tap_name.clone().or_else(|| {
                config
                    .interface
                    .name
                    .as_ref()
                    .map(|n| format!("{}-tap", n.chars().take(11).collect::<String>()))
            });
            let tun_dev = VirtualInterface::create(TunConfig {
                name: tun_name,
                mtu,
                mode: DeviceMode::Tun,
            })
            .await?;
            let tap_dev = VirtualInterface::create(TunConfig {
                name: tap_name,
                mtu,
                mode: DeviceMode::Tap,
            })
            .await?;
            (Some(tun_dev), Some(tap_dev))
        }
    };

    let primary_dev = tun.as_ref().or(tap.as_ref()).expect("at least one device");
    configure_server_interface(primary_dev, &config).await?;
    let forwarding = ForwardingGuard::install(&config.forwarding, primary_dev.name()).await?;

    tracing::info!(
        bind = %transport.local_addr()?,
        peers = identities.len(),
        certificate_authority = certificate_authority.is_some(),
        primary_interface = %primary_dev.name(),
        mode = ?mode,
        mtu = mtu,
        "RVPN multi-client server started"
    );

    let shutdown = Box::pin(shutdown_signal());
    run_server_loop(
        transport,
        config,
        identities,
        certificate_authority,
        obfuscation,
        cookie_key,
        tun,
        tap,
        forwarding,
        shutdown,
    )
    .await
}

fn effective_tunnel_mtu(requested: u16, wire_overhead: usize, outer_is_ipv6: bool) -> u16 {
    let safe_inner = default_udp_payload_mtu(outer_is_ipv6).saturating_sub(wire_overhead);
    requested.min(safe_inner.try_into().unwrap_or(u16::MAX))
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("waiting for SIGINT"),
            result = async {
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?
                    .recv()
                    .await;
                Ok::<(), std::io::Error>(())
            } => result.context("waiting for SIGTERM"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("waiting for shutdown signal")
    }
}
