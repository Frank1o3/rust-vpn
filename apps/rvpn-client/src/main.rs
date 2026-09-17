mod handshake;
mod ipc;
mod platform;
mod tunnel;

use anyhow::{Context, Result};
use ipc::{Daemon, run_ipc_server};
use rvpn_config::{ClientConfig, DeviceMode};
use rvpn_crypto::AEAD_TAG_LEN;
use rvpn_interface::{DEFAULT_MTU, TunConfig, VirtualInterface};
use rvpn_protocol::HEADER_LEN;
use rvpn_transport::{TransportConfig, UdpTransport, default_udp_payload_mtu};
use rvpn_core::GuiStateHandle;
use std::{env, fs, net::SocketAddr, sync::Arc};

use handshake::establish;
use platform::{configure_client_network, teardown_client_network};
use tunnel::run_data_plane;

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    raise_ambient_capabilities();

    let arg = env::args().nth(1);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("creating Tokio runtime")?
        .block_on(async move {
            match arg {
                Some(path) if path != "--daemon" => {
                    let config = ClientConfig::from_toml(&fs::read_to_string(&path)?)?;
                    run_client(config, None, None).await
                }
                _ => {
                    let daemon = Daemon::new();
                    tokio::select! {
                        result = run_ipc_server(Arc::clone(&daemon)) => result,
                        result = shutdown_signal() => {
                            let _ = daemon_disconnect_on_exit(&daemon).await;
                            result
                        }
                    }
                }
            }
        })
}

async fn daemon_disconnect_on_exit(_daemon: &Arc<Daemon>) -> Result<()> {
    Ok(())
}

pub(crate) async fn run_client(
    config: ClientConfig,
    gui_state: Option<GuiStateHandle>,
    shutdown: Option<std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>>,
) -> Result<()> {
    tracing::info!(endpoint = %config.server, "resolving RVPN server endpoint");
    let server: SocketAddr = rvpn_config::resolve_endpoint(&config.server)
        .await
        .context("resolving server endpoint")?;
    config.validate_resolved(server)?;
    tracing::info!(%server, "resolved RVPN server endpoint");

    if let Some(state) = &gui_state {
        let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
        state.set_server(config.server.clone());
    }

    let mode = config.interface.mode();
    let requested_mtu = config.interface.mtu.unwrap_or(DEFAULT_MTU);
    let frame_overhead = match mode {
        DeviceMode::Tun => 0,
        DeviceMode::Tap | DeviceMode::Both => 18,
    };
    let obfuscation = config
        .obfuscation_key_bytes()?
        .map(rvpn_crypto::ObfuscationKey::from_bytes);
    let wire_overhead = frame_overhead
        + HEADER_LEN
        + AEAD_TAG_LEN
        + if obfuscation.is_some() {
            rvpn_crypto::OBFUSCATION_OVERHEAD
        } else {
            0
        };
    let mtu = effective_tunnel_mtu(requested_mtu, wire_overhead, server.is_ipv6());
    if mtu < requested_mtu {
        tracing::warn!(
            requested_mtu,
            effective_mtu = mtu,
            wire_overhead,
            "reduced tunnel MTU so encrypted UDP packets fit a standard path"
        );
    }
    let local_bind: SocketAddr = if server.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let transport = UdpTransport::open(TransportConfig {
        local_address: local_bind,
        remote_address: None,
        max_datagram_size: usize::from(mtu) + wire_overhead,
    })
    .await?;

    let auth = config.auth_config()?;
    let session = establish(
        &transport,
        server,
        &auth,
        obfuscation.as_ref(),
        &config.handshake,
        None,
    )
    .await?;

    if let Some(state) = &gui_state {
        let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
        state.connected(format!("{:?}", session.session_id()), mtu.into());
        state.set_key_phase(session.key_phase());
    }

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
    configure_client_network(primary_dev, &config, server).await?;
    tracing::info!(
        session_id = ?session.session_id(),
        %server,
        primary_interface = %primary_dev.name(),
        mode = ?mode,
        mtu = mtu,
        "authenticated RVPN client data plane started"
    );

    let shutdown = match shutdown {
        Some(shutdown) => shutdown,
        None => Box::pin(shutdown_signal()),
    };

    let result = run_data_plane(
        session,
        &transport,
        &config,
        server,
        &auth,
        obfuscation.as_ref(),
        tun.as_ref(),
        tap.as_ref(),
        shutdown,
        gui_state,
    )
    .await;

    tracing::info!("restoring host network state");
    teardown_client_network(primary_dev, &config, server).await;

    result
}

fn effective_tunnel_mtu(requested: u16, wire_overhead: usize, outer_is_ipv6: bool) -> u16 {
    let safe_inner = default_udp_payload_mtu(outer_is_ipv6).saturating_sub(wire_overhead);
    requested.min(safe_inner.try_into().unwrap_or(u16::MAX))
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate()).context("register SIGTERM handler")?;
        let mut sighup = signal(SignalKind::hangup()).context("register SIGHUP handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("waiting for SIGINT"),
            _ = sigterm.recv() => Ok(()),
            _ = sighup.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("waiting for shutdown signal")
    }
}

#[cfg(target_os = "linux")]
fn raise_ambient_capabilities() {
    use caps::{CapSet, Capability};

    for capability in [Capability::CAP_NET_ADMIN, Capability::CAP_NET_RAW] {
        if let Err(error) = caps::raise(None, CapSet::Inheritable, capability) {
            tracing::warn!(%error, ?capability, "failed to add capability to inheritable set");
            continue;
        }
        if let Err(error) = caps::raise(None, CapSet::Ambient, capability) {
            tracing::warn!(
                %error,
                ?capability,
                "failed to raise capability into ambient set; `ip` commands spawned as \
                 child processes will fail with 'Operation not permitted'"
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn raise_ambient_capabilities() {}
