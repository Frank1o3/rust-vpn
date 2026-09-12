mod handshake;
mod network;
mod tunnel;

use anyhow::{Context, Result};
use rvpn_config::{ClientConfig, DeviceMode};
use rvpn_crypto::AEAD_TAG_LEN;
use rvpn_interface::{DEFAULT_MTU, TunConfig, TunDevice};
use rvpn_protocol::HEADER_LEN;
use rvpn_transport::{TransportConfig, UdpTransport};
use std::{env, fs, net::SocketAddr};

use handshake::establish;
use network::configure_client_network;
use tunnel::run_data_plane;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let path = env::args()
        .nth(1)
        .context("usage: rvpn-client <client.toml>")?;
    let config = ClientConfig::from_toml(&fs::read_to_string(path)?)?;
    let mode = config.interface.mode();
    let mtu = config.interface.mtu.unwrap_or(DEFAULT_MTU);
    let frame_overhead = match mode {
        DeviceMode::Tun => 0,
        DeviceMode::Tap | DeviceMode::Both => 18,
    };
    let local_bind: SocketAddr = if config.server.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let transport = UdpTransport::open(TransportConfig {
        local_address: local_bind,
        remote_address: None,
        max_datagram_size: usize::from(mtu) + frame_overhead + HEADER_LEN + AEAD_TAG_LEN,
    })
    .await?;
    let psk = config.pre_shared_key_bytes()?;
    let session = establish(&transport, config.server, psk, &config.handshake, None).await?;

    let (tun, tap) = match mode {
        DeviceMode::Tun => {
            let dev = TunDevice::create(TunConfig {
                name: config.interface.name.clone(),
                mtu,
                mode: DeviceMode::Tun,
            })
            .await?;
            (Some(dev), None)
        }
        DeviceMode::Tap => {
            let dev = TunDevice::create(TunConfig {
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
            let tun_dev = TunDevice::create(TunConfig {
                name: tun_name,
                mtu,
                mode: DeviceMode::Tun,
            })
            .await?;
            let tap_dev = TunDevice::create(TunConfig {
                name: tap_name,
                mtu,
                mode: DeviceMode::Tap,
            })
            .await?;
            (Some(tun_dev), Some(tap_dev))
        }
    };

    let primary_dev = tun.as_ref().or(tap.as_ref()).expect("at least one device");
    configure_client_network(primary_dev, &config).await?;
    tracing::info!(
        session_id = ?session.session_id(),
        server = %config.server,
        primary_interface = %primary_dev.name(),
        mode = ?mode,
        mtu = mtu,
        "authenticated RVPN client data plane started"
    );

    let shutdown = Box::pin(shutdown_signal());
    run_data_plane(
        session,
        &transport,
        &config,
        psk,
        tun.as_ref(),
        tap.as_ref(),
        shutdown,
    )
    .await
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
