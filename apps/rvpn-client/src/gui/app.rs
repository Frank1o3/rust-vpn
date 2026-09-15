use std::sync::Mutex;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};

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
        self.state
            .lock()
            .unwrap_or_else(Mutex::into_inner)
            .clone()
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
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let state = self.snapshot();
        let uptime = if state.connected {
            state.uptime
        } else {
            self.started.elapsed()
        };

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("RVPN");
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                let status = if state.connected {
                    RichText::new("● Connected").color(Color32::from_rgb(72, 187, 120))
                } else {
                    RichText::new("● Disconnected").color(Color32::from_rgb(220, 80, 80))
                };
                ui.label(status.strong());
                ui.separator();
                ui.label(&state.server);
            });

            Self::section_heading(ui, "Connection");
            egui::Grid::new("connection_grid")
                .num_columns(2)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    Self::value(ui, "Uptime", Self::format_duration(uptime));
                    ui.end_row();
                    Self::value(ui, "Session", &state.session_id);
                    ui.end_row();
                    Self::value(ui, "Key phase", state.key_phase.to_string());
                    ui.end_row();
                });

            Self::section_heading(ui, "Traffic");
            egui::Grid::new("traffic_grid")
                .num_columns(2)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    Self::value(ui, "Upload", Self::format_bytes(state.bytes_tx));
                    ui.end_row();
                    Self::value(ui, "Download", Self::format_bytes(state.bytes_rx));
                    ui.end_row();
                    Self::value(ui, "Packets TX", state.packets_tx.to_string());
                    ui.end_row();
                    Self::value(ui, "Packets RX", state.packets_rx.to_string());
                    ui.end_row();
                });

            Self::section_heading(ui, "Transport");
            egui::Grid::new("transport_grid")
                .num_columns(2)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    Self::value(ui, "Effective MTU", state.effective_mtu.to_string());
                    ui.end_row();
                    Self::value(ui, "Configured MTU", state.configured_mtu.to_string());
                    ui.end_row();
                    Self::value(ui, "MTU state", &state.mtu_state);
                    ui.end_row();
                    Self::value(
                        ui,
                        "Last MTU change",
                        state.last_mtu_change.as_deref().unwrap_or("None"),
                    );
                    ui.end_row();
                    Self::value(ui, "MTU changes", state.mtu_changes.to_string());
                    ui.end_row();
                });

            Self::section_heading(ui, "Performance");
            egui::Grid::new("performance_grid")
                .num_columns(2)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    Self::value(ui, "Send errors", state.send_errors.to_string());
                    ui.end_row();
                    Self::value(ui, "Oversized drops", state.dropped_oversized.to_string());
                    ui.end_row();
                    Self::value(ui, "Backpressure drops", state.dropped_backpressure.to_string());
                    ui.end_row();
                    Self::value(ui, "Keepalives sent", state.keepalives_sent.to_string());
                    ui.end_row();
                    Self::value(ui, "RTT", "—");
                    ui.end_row();
                    Self::value(ui, "Packet loss", "—");
                    ui.end_row();
                });

            ui.add_space(8.0);
            ui.separator();
            ui.label(
                RichText::new("Live telemetry • logs remain enabled")
                    .weak()
                    .small(),
            );
        });

        ctx.request_repaint_after(Duration::from_millis(250));
    }
}
