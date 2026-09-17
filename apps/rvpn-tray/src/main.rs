use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rvpn_ipc::{ControlRequest, ControlResponse, StatusSnapshot};
use tao::event::Event;
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::{
    Icon, TrayIconBuilder, TrayIconEvent,
    menu::{Menu, MenuEvent, MenuItem},
};

const REFRESH_INTERVAL: Duration = Duration::from_millis(750);

enum TrayEvent {
    Icon,
    Menu(MenuEvent),
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("creating Tokio runtime")?;

    let event_loop = EventLoopBuilder::<TrayEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    TrayIconEvent::set_event_handler(Some(move |_| {
        let _ = proxy.send_event(TrayEvent::Icon);
    }));
    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(TrayEvent::Menu(event));
    }));

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
    // The native menu keeps only a weak reference to its items.
    std::mem::forget(connect_item);
    std::mem::forget(disconnect_item);
    std::mem::forget(quit_item);

    let initial = runtime.block_on(query_status());
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip(initial.tooltip_text())
        .with_icon(status_icon(initial.connected))
        .build()
        .context("creating RVPN tray icon")?;

    let mut last_refresh = Instant::now();

    event_loop.run(move |event, _target, control_flow| {
        *control_flow = ControlFlow::WaitUntil(Instant::now() + REFRESH_INTERVAL);

        if let Event::UserEvent(TrayEvent::Menu(menu_event)) = event {
            if menu_event.id == quit_id {
                *control_flow = ControlFlow::Exit;
                return;
            }
            if menu_event.id == connect_id {
                if let Err(error) = runtime.block_on(send_connect()) {
                    tracing::warn!(%error, "failed to send Connect to rvpn-client");
                }
            }
            if menu_event.id == disconnect_id {
                if let Err(error) = runtime.block_on(send_disconnect()) {
                    tracing::warn!(%error, "failed to send Disconnect to rvpn-client");
                }
            }
        }

        if last_refresh.elapsed() >= REFRESH_INTERVAL {
            let snapshot = runtime.block_on(query_status());
            let _ = tray.set_tooltip(Some(snapshot.tooltip_text()));
            let _ = tray.set_icon(Some(status_icon(snapshot.connected)));
            last_refresh = Instant::now();
        }
    })
}

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

fn status_icon(connected: bool) -> Icon {
    const SIZE: u32 = 32;
    let (r, g, b) = if connected {
        (56, 161, 105)
    } else {
        (117, 117, 117)
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
