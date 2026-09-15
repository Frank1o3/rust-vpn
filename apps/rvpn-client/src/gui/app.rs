use std::time::{Duration, Instant};

use eframe::egui::{self, RichText};

use super::GuiStateHandle;

pub struct DashboardApp {
    state: GuiStateHandle,
    started: Instant,
}

impl DashboardApp {
    pub fn new(state: GuiStateHandle) -> Self {
        Self {
            state,
            started: Instant::now(),
        }
    }

    fn snapshot(&self) -> super::state::GuiState {
        match self.state.lock() {
            Ok(state) => state.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn section_heading(ui: &mut egui::Ui, title: &str) {
        ui.add_space(6.0);
        ui.label(RichText::new(title).strong().size(16.0));
        ui.add_space(2.0);
    }

    fn value(ui: &mut egui::Ui, label: &str, value: impl Into<String>) {
        ui.horizontal(|ui| {
            ui.label(RichText::new(label).weak());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(value.into());
            });
        });
    }

    fn format_bytes(bytes: u64) -> String {
        const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
        let mut value = bytes as f64;
        let mut index = 0;
        while value >= 1024.0 && index < UNITS.len() - 1 {
            value /= 1024.0;
            index += 1;
        }
        if index == 0 {
            format!("{} {}", bytes, UNITS[index])
        } else {
            format!("{value:.2} {}", UNITS[index])
        }
    }

    fn format_duration(duration: Duration) -> String {
        let seconds = duration.as_secs();
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        let seconds = seconds % 60;
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    }
}

impl eframe::App for DashboardApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let state = {
            let guard = self.state.lock().expect("GUI state mutex poisoned");
            guard.snapshot()
        };

        ui.heading("RVPN Client");
        ui.separator();

        ui.horizontal(|ui| {
            ui.label("Status:");
            if state.connected {
                ui.label("Connected");
            } else {
                ui.label("Disconnected");
            }
        });

        ui.separator();

        ui.heading("Connection");
        egui::Grid::new("connection_grid")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                ui.label("Server");
                ui.label(&state.server);
                ui.end_row();

                ui.label("Uptime");
                ui.label(format_duration(state.uptime));
                ui.end_row();

                ui.label("Session");
                ui.label(&state.session_id);
                ui.end_row();

                ui.label("Key phase");
                ui.label(&state.key_phase);
                ui.end_row();
            });

        ui.separator();

        ui.heading("Traffic");
        egui::Grid::new("traffic_grid")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                ui.label("Uploaded");
                ui.label(format_bytes(state.bytes_tx));
                ui.end_row();

                ui.label("Downloaded");
                ui.label(format_bytes(state.bytes_rx));
                ui.end_row();

                ui.label("TX packets");
                ui.label(state.packets_tx.to_string());
                ui.end_row();

                ui.label("RX packets");
                ui.label(state.packets_rx.to_string());
                ui.end_row();
            });

        ui.separator();

        ui.heading("Transport");
        egui::Grid::new("transport_grid")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                ui.label("Configured MTU");
                ui.label(state.configured_mtu.to_string());
                ui.end_row();

                ui.label("Effective MTU");
                ui.label(state.effective_mtu.to_string());
                ui.end_row();

                ui.label("MTU state");
                ui.label(&state.mtu_state);
                ui.end_row();

                ui.label("Last MTU change");
                ui.label(state.last_mtu_change.as_deref().unwrap_or("None"));
                ui.end_row();
            });

        ui.separator();

        ui.heading("Performance");
        egui::Grid::new("performance_grid")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                ui.label("MTU changes");
                ui.label(state.mtu_changes.to_string());
                ui.end_row();

                ui.label("Send errors");
                ui.label(state.send_errors.to_string());
                ui.end_row();

                ui.label("Oversized drops");
                ui.label(state.dropped_oversized.to_string());
                ui.end_row();

                ui.label("Backpressure drops");
                ui.label(state.dropped_backpressure.to_string());
                ui.end_row();

                ui.label("Keepalives sent");
                ui.label(state.keepalives_sent.to_string());
                ui.end_row();
            });

        ui.separator();

        ui.weak("Live telemetry • logs remain enabled");

        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(250));
    }
}
