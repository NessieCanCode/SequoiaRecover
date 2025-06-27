use chrono::TimeZone;
use eframe::egui::{self, CentralPanel, ComboBox, TextEdit, TopBottomPanel};
use sequoiarecover::backup::{BackupMode, CompressionType};

mod api;
use api::{load_history, perform_backup, schedule_backups, BackupConfig};

#[derive(PartialEq)]
enum View {
    Backup,
    Schedule,
    History,
}

struct AppState {
    view: View,
    backup_cfg: BackupConfig,
    interval: u64,
    max_runs: u64,
    history: Vec<sequoiarecover::config::HistoryEntry>,
    status: String,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            view: View::Backup,
            backup_cfg: BackupConfig::default(),
            interval: 3600,
            max_runs: 0,
            history: Vec::new(),
            status: String::new(),
        }
    }
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Backup").clicked() {
                    self.view = View::Backup;
                }
                if ui.button("Schedule").clicked() {
                    self.view = View::Schedule;
                }
                if ui.button("History").clicked() {
                    self.view = View::History;
                    if let Ok(hist) = load_history() {
                        self.history = hist;
                    }
                }
            });
        });
        CentralPanel::default().show(ctx, |ui| match self.view {
            View::Backup => self.show_backup(ui),
            View::Schedule => self.show_schedule(ui),
            View::History => self.show_history(ui),
        });
    }
}

impl AppState {
    fn show_backup(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.label("Source:");
                ui.add(TextEdit::singleline(&mut self.backup_cfg.source).desired_width(200.0));
            });
            ui.horizontal(|ui| {
                ui.label("Output:");
                ui.add(TextEdit::singleline(&mut self.backup_cfg.output).desired_width(200.0));
            });
            ui.horizontal(|ui| {
                ui.label("Compression:");
                ComboBox::from_id_source("compression")
                    .selected_text(format!("{:?}", self.backup_cfg.compression))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.backup_cfg.compression,
                            CompressionType::None,
                            "None",
                        );
                        ui.selectable_value(
                            &mut self.backup_cfg.compression,
                            CompressionType::Gzip,
                            "Gzip",
                        );
                        ui.selectable_value(
                            &mut self.backup_cfg.compression,
                            CompressionType::Bzip2,
                            "Bzip2",
                        );
                        ui.selectable_value(
                            &mut self.backup_cfg.compression,
                            CompressionType::Zstd,
                            "Zstd",
                        );
                    });
            });
            ui.horizontal(|ui| {
                ui.label("Mode:");
                ComboBox::from_id_source("mode")
                    .selected_text(format!("{:?}", self.backup_cfg.mode))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.backup_cfg.mode, BackupMode::Full, "Full");
                        ui.selectable_value(
                            &mut self.backup_cfg.mode,
                            BackupMode::Incremental,
                            "Incremental",
                        );
                    });
            });
            if ui.button("Run Backup").clicked() {
                match perform_backup(&self.backup_cfg) {
                    Ok(_) => self.status = "Backup completed".into(),
                    Err(e) => self.status = e,
                }
            }
            ui.label(&self.status);
        });
    }

    fn show_schedule(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.label("Interval (s):");
                let mut int_str = self.interval.to_string();
                if ui.text_edit_singleline(&mut int_str).lost_focus() {
                    if let Ok(v) = int_str.parse() {
                        self.interval = v;
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.label("Max runs (0=infinite):");
                let mut max_str = self.max_runs.to_string();
                if ui.text_edit_singleline(&mut max_str).lost_focus() {
                    if let Ok(v) = max_str.parse() {
                        self.max_runs = v;
                    }
                }
            });
            if ui.button("Start Schedule").clicked() {
                schedule_backups(self.backup_cfg.clone(), self.interval, self.max_runs);
                self.status = "Schedule started".into();
            }
            ui.label(&self.status);
        });
    }

    fn show_history(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            for entry in &self.history {
                ui.horizontal(|ui| {
                    let naive =
                        chrono::NaiveDateTime::from_timestamp_opt(entry.timestamp, 0).unwrap();
                    let dt: chrono::DateTime<chrono::Local> =
                        chrono::Local.from_local_datetime(&naive).unwrap();
                    ui.label(dt.format("%Y-%m-%d %H:%M:%S").to_string());
                    ui.label(format!("{:?}", entry.mode));
                    ui.label(&entry.backup);
                });
            }
        });
    }
}

fn main() {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "SequoiaRecover GUI",
        options,
        Box::new(|_cc| Ok(Box::new(AppState::default()))),
    )
    .unwrap();
}
