use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tao::event::Event;
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tokio::sync::watch;
use tray_icon::{
    Icon, TrayIconBuilder, TrayIconEvent,
    menu::{Menu, MenuEvent, MenuItem},
};

use super::GuiStateHandle;

const REFRESH_INTERVAL: Duration = Duration::from_millis(750);

/// Forward tray-library events to Tao so menu clicks wake the application
/// immediately instead of waiting for the next refresh tick.
enum TrayEvent {
    Icon,
    Menu(MenuEvent),
}

pub fn run_tray(
    state: GuiStateHandle,
    shutdown_tx: watch::Sender<bool>,
    client_thread: JoinHandle<()>,
) -> Result<()> {
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
    let quit_item = MenuItem::new("Quit RVPN", true, None);
    let quit_id = quit_item.id().clone();
    let _ = menu.append(&quit_item);
    // The native menu keeps only a weak reference to its items.
    std::mem::forget(quit_item);

    let snapshot = state.lock().unwrap_or_else(|e| e.into_inner()).snapshot();
    let tray = match TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip(snapshot.tooltip_text())
        .with_icon(status_icon(snapshot.connected))
        .build()
    {
        Ok(tray) => tray,
        Err(error) => {
            let _ = shutdown_tx.send(true);
            let _ = client_thread.join();
            return Err(error).context("creating RVPN tray icon");
        }
    };

    let mut client_thread = Some(client_thread);
    let mut last_refresh = Instant::now();

    event_loop.run(move |event, _target, control_flow| {
        *control_flow = ControlFlow::WaitUntil(Instant::now() + REFRESH_INTERVAL);

        if let Event::UserEvent(TrayEvent::Menu(menu_event)) = event {
            if menu_event.id == quit_id {
                let _ = shutdown_tx.send(true);
                if let Some(handle) = client_thread.take() {
                    let _ = handle.join();
                }
                *control_flow = ControlFlow::Exit;
                return;
            }
        }

        if last_refresh.elapsed() >= REFRESH_INTERVAL {
            let snapshot = state.lock().unwrap_or_else(|e| e.into_inner()).snapshot();
            let _ = tray.set_tooltip(Some(snapshot.tooltip_text()));
            let _ = tray.set_icon(Some(status_icon(snapshot.connected)));
            last_refresh = Instant::now();
        }
    })
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
