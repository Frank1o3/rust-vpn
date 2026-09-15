use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tao::event::{Event, StartCause};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tokio::sync::watch;
use tray_icon::{
    Icon, TrayIcon, TrayIconBuilder, TrayIconEvent,
    menu::{Menu, MenuEvent, MenuId, MenuItem},
};

use super::GuiStateHandle;

const REFRESH_INTERVAL: Duration = Duration::from_millis(750);

pub fn run_tray(
    state: GuiStateHandle,
    shutdown_tx: watch::Sender<bool>,
    client_thread: JoinHandle<()>,
) -> ! {
    let event_loop = EventLoopBuilder::new().build();

    let mut tray: Option<TrayIcon> = None;
    let mut quit_id: Option<MenuId> = None;
    let mut client_thread = Some(client_thread);
    let mut last_refresh = Instant::now();

    event_loop.run(move |event, _target, control_flow| {
        *control_flow = ControlFlow::WaitUntil(Instant::now() + REFRESH_INTERVAL);

        if let Event::NewEvents(StartCause::Init) = event {
            let menu = Menu::new();
            let quit_item = MenuItem::new("Quit RVPN", true, None);
            quit_id = Some(quit_item.id().clone());
            let _ = menu.append(&quit_item);

            std::mem::forget(quit_item);

            let snapshot = state.lock().unwrap_or_else(|e| e.into_inner()).snapshot();
            tray = Some(
                TrayIconBuilder::new()
                    .with_menu(Box::new(menu))
                    .with_tooltip(snapshot.tooltip_text())
                    .with_icon(status_icon(snapshot.connected))
                    .build()
                    .expect("failed to create RVPN tray icon"),
            );
        }

        if let Ok(menu_event) = MenuEvent::receiver().try_recv() {
            if Some(&menu_event.id) == quit_id.as_ref() {
                let _ = shutdown_tx.send(true);
                if let Some(handle) = client_thread.take() {
                    let _ = handle.join();
                }
                *control_flow = ControlFlow::Exit;
                return;
            }
        }

        let _ = TrayIconEvent::receiver().try_recv();

        if let Some(tray) = &tray {
            if last_refresh.elapsed() >= REFRESH_INTERVAL {
                let snapshot = state.lock().unwrap_or_else(|e| e.into_inner()).snapshot();
                let _ = tray.set_tooltip(Some(snapshot.tooltip_text()));
                let _ = tray.set_icon(Some(status_icon(snapshot.connected)));
                last_refresh = Instant::now();
            }
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
