use std::{fs, time::Duration};

use anyhow::{Context, Result};
use rvpn_ipc::{ControlRequest, ControlResponse, StatusSnapshot};
use tao::event::Event;
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::{
    Icon, TrayIconBuilder, TrayIconEvent,
    menu::{Menu, MenuEvent, MenuItem},
};

const REFRESH_INTERVAL: Duration = Duration::from_millis(100);

enum TrayEvent {
    Icon,
    Menu(MenuEvent),
    Refresh(StatusSnapshot, LedActivity),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedActivity {
    Idle,
    Rx,
    Tx,
    Both,
}

#[derive(Clone, Copy, Debug, Default)]
struct NetworkCounters {
    rx_bytes: u64,
    tx_bytes: u64,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("creating Tokio runtime")?;

    let event_loop = EventLoopBuilder::<TrayEvent>::with_user_event().build();

    // Tray icon events.
    let proxy = event_loop.create_proxy();
    TrayIconEvent::set_event_handler(Some(move |_| {
        let _ = proxy.send_event(TrayEvent::Icon);
    }));

    // Menu events.
    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(TrayEvent::Menu(event));
    }));

    // Menu.
    let menu = Menu::new();

    let connect_item = MenuItem::new("Connect", true, None);
    let disconnect_item = MenuItem::new("Disconnect", true, None);
    let quit_item = MenuItem::new("Quit RVPN Tray", true, None);

    let connect_id = connect_item.id().clone();
    let disconnect_id = disconnect_item.id().clone();
    let quit_id = quit_item.id().clone();

    let _ = menu.append(&connect_item);
    let _ = menu.append(&disconnect_item);
    let _ = menu.append(&quit_item);

    // Keep the menu items alive for the lifetime of the tray menu.
    std::mem::forget(connect_item);
    std::mem::forget(disconnect_item);
    std::mem::forget(quit_item);

    // Initial state.
    let initial = runtime.block_on(query_status());

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip(initial.tooltip_text())
        .with_icon(status_icon(initial.connected, LedActivity::Idle))
        .build()
        .context("creating RVPN tray icon")?;

    // ---------------------------------------------------------------------
    // Background status/traffic polling.
    //
    // The important change is that the tray no longer waits for a user
    // action to refresh. Tokio polls continuously and wakes the Tao event
    // loop with a TrayEvent::Refresh.
    // ---------------------------------------------------------------------
    let refresh_proxy = event_loop.create_proxy();

    runtime.spawn(async move {
        let mut interval = tokio::time::interval(REFRESH_INTERVAL);

        let mut previous_counters = read_network_counters();

        loop {
            interval.tick().await;

            let snapshot = query_status().await;

            let current_counters = read_network_counters();

            let activity = match (previous_counters, current_counters) {
                (Some(previous), Some(current)) => {
                    let rx_changed = current.rx_bytes > previous.rx_bytes;
                    let tx_changed = current.tx_bytes > previous.tx_bytes;

                    match (rx_changed, tx_changed) {
                        (true, true) => LedActivity::Both,
                        (true, false) => LedActivity::Rx,
                        (false, true) => LedActivity::Tx,
                        (false, false) => LedActivity::Idle,
                    }
                }
                _ => LedActivity::Idle,
            };

            previous_counters = current_counters;

            if refresh_proxy
                .send_event(TrayEvent::Refresh(snapshot, activity))
                .is_err()
            {
                break;
            }
        }
    });

    event_loop.run(move |event, _target, control_flow| {
        // The event loop sleeps until something actually happens.
        *control_flow = ControlFlow::Wait;

        match event {
            Event::UserEvent(TrayEvent::Menu(menu_event)) => {
                if menu_event.id == quit_id {
                    *control_flow = ControlFlow::Exit;
                    return;
                }

                if menu_event.id == connect_id
                    && let Err(error) = runtime.block_on(send_connect())
                {
                    tracing::warn!(
                        %error,
                        "failed to send Connect to rvpn-client"
                    );
                }

                if menu_event.id == disconnect_id
                    && let Err(error) = runtime.block_on(send_disconnect())
                {
                    tracing::warn!(
                        %error,
                        "failed to send Disconnect to rvpn-client"
                    );
                }
            }

            Event::UserEvent(TrayEvent::Refresh(snapshot, activity)) => {
                let tooltip = live_tooltip(&snapshot, activity);

                let _ = tray.set_tooltip(Some(tooltip));

                let _ = tray.set_icon(Some(status_icon(snapshot.connected, activity)));
            }

            Event::UserEvent(TrayEvent::Icon) => {
                // Keep this available for future left-click handling.
            }

            _ => {}
        }
    })
}

// -------------------------------------------------------------------------
// IPC
// -------------------------------------------------------------------------

async fn send_connect() -> Result<()> {
    let path = rvpn_config::default_client_config_path();

    let mut conn = rvpn_ipc::Connection::connect().await?;

    if let ControlResponse::Err(message) = conn
        .call(&ControlRequest::Connect {
            config_path: path.to_string_lossy().into_owned(),
        })
        .await?
    {
        tracing::warn!(%message, "rvpn-client rejected Connect");
    }

    Ok(())
}

async fn send_disconnect() -> Result<()> {
    let mut conn = rvpn_ipc::Connection::connect().await?;

    if let ControlResponse::Err(message) = conn.call(&ControlRequest::Disconnect).await? {
        tracing::warn!(%message, "rvpn-client rejected Disconnect");
    }

    Ok(())
}

async fn query_status() -> StatusSnapshot {
    let Ok(mut conn) = rvpn_ipc::Connection::connect().await else {
        return StatusSnapshot::disconnected();
    };

    match conn.call(&ControlRequest::Status).await {
        Ok(ControlResponse::Status(status)) => status,
        _ => StatusSnapshot::disconnected(),
    }
}

// -------------------------------------------------------------------------
// Live tooltip
// -------------------------------------------------------------------------

fn live_tooltip(snapshot: &StatusSnapshot, activity: LedActivity) -> String {
    let mut text = snapshot.tooltip_text();

    let activity_text = match activity {
        LedActivity::Rx => "RX activity",
        LedActivity::Tx => "TX activity",
        LedActivity::Both => "RX + TX activity",
        LedActivity::Idle => "Idle",
    };

    text.push('\n');
    text.push_str(activity_text);

    text
}

// -------------------------------------------------------------------------
// Ethernet-style LED
// -------------------------------------------------------------------------

fn status_icon(connected: bool, activity: LedActivity) -> Icon {
    const SIZE: u32 = 32;

    let (r, g, b) = if !connected {
        // Disconnected.
        (117, 117, 117)
    } else {
        match activity {
            // RX = bright green.
            LedActivity::Rx => (72, 220, 120),

            // TX = yellow.
            LedActivity::Tx => (255, 204, 0),

            // Simultaneous traffic.
            LedActivity::Both => (160, 225, 80),

            // Connected but idle.
            LedActivity::Idle => (56, 161, 105),
        }
    };

    let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);

    let center = (SIZE as f32 - 1.0) / 2.0;
    let radius = SIZE as f32 / 2.0 - 2.0;

    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as f32 - center;
            let dy = y as f32 - center;

            if (dx * dx + dy * dy).sqrt() <= radius {
                rgba.extend_from_slice(&[r, g, b, 255]);
            } else {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }

    Icon::from_rgba(rgba, SIZE, SIZE).expect("32x32 RGBA buffer is always a valid icon")
}

// -------------------------------------------------------------------------
// Network traffic counters
//
// Linux implementation using /proc/net/dev.
//
// Loopback is deliberately ignored so local IPC traffic doesn't make the
// RVPN LED flash constantly.
//
// On non-Linux platforms this returns None, so the tray still gets live
// status updates but the RX/TX traffic LED remains idle.
// -------------------------------------------------------------------------

fn read_network_counters() -> Option<NetworkCounters> {
    #[cfg(target_os = "linux")]
    {
        read_linux_network_counters()
    }

    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn read_linux_network_counters() -> Option<NetworkCounters> {
    let contents = fs::read_to_string("/proc/net/dev").ok()?;

    let mut total_rx = 0u64;
    let mut total_tx = 0u64;

    for line in contents.lines() {
        let Some((interface, data)) = line.split_once(':') else {
            continue;
        };

        let interface = interface.trim();

        // Ignore loopback because RVPN's local IPC/socket traffic can
        // otherwise trigger the LED continuously.
        if interface == "lo" {
            continue;
        }

        let values: Vec<u64> = data
            .split_whitespace()
            .filter_map(|value| value.parse::<u64>().ok())
            .collect();

        // /proc/net/dev:
        //
        // RX bytes  = field 0
        // TX bytes  = field 8
        //
        if values.len() >= 9 {
            total_rx = total_rx.saturating_add(values[0]);
            total_tx = total_tx.saturating_add(values[8]);
        }
    }

    Some(NetworkCounters {
        rx_bytes: total_rx,
        tx_bytes: total_tx,
    })
}
