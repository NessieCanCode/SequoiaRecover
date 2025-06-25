use directories::ProjectDirs;
use eframe::egui::{self, ComboBox};
use sequoiarecover::backup::{
    restore_backup, run_backup_with_progress, BackupMode, CompressionType,
};
use sequoiarecover::config::{history_file_path, HistoryEntry};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize, Default)]
struct GuiConfig {
    source: String,
    output: String,
    restore_path: String,
    restore_dest: String,
}

enum Tab {
    Backup,
    Restore,
    History,
}

struct App {
    tab: Tab,
    source: String,
    output: String,
    compression: CompressionType,
    mode: BackupMode,
    restore_path: String,
    restore_dest: String,
    history: Vec<HistoryEntry>,
    status: Arc<Mutex<String>>,
    progress: Arc<Mutex<f32>>,
}

fn load_config() -> GuiConfig {
    if let Some(proj) = ProjectDirs::from("org", "", "SequoiaRecover") {
        let path = proj.config_dir().join("gui_config.json");
        if let Ok(f) = std::fs::File::open(path) {
            serde_json::from_reader(f).unwrap_or_default()
        } else {
            GuiConfig::default()
        }
    } else {
        GuiConfig::default()
    }
}

fn save_config(cfg: &GuiConfig) {
    if let Some(proj) = ProjectDirs::from("org", "", "SequoiaRecover") {
        let dir = proj.config_dir();
        let _ = std::fs::create_dir_all(dir);
        let path = dir.join("gui_config.json");
        if let Ok(f) = std::fs::File::create(path) {
            let _ = serde_json::to_writer_pretty(f, cfg);
        }
    }
}

fn load_history() -> Vec<HistoryEntry> {
    if let Ok(path) = history_file_path() {
        if let Ok(f) = std::fs::File::open(path) {
            serde_json::from_reader(f).unwrap_or_default()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui
                    .selectable_label(matches!(self.tab, Tab::Backup), "Backup")
                    .clicked()
                {
                    self.tab = Tab::Backup;
                }
                if ui
                    .selectable_label(matches!(self.tab, Tab::Restore), "Restore")
                    .clicked()
                {
                    self.tab = Tab::Restore;
                }
                if ui
                    .selectable_label(matches!(self.tab, Tab::History), "History")
                    .clicked()
                {
                    self.tab = Tab::History;
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Backup => {
                ui.heading("Run Backup");
                ui.horizontal(|ui| {
                    ui.label("Source:");
                    ui.text_edit_singleline(&mut self.source);
                });
                ui.horizontal(|ui| {
                    ui.label("Output:");
                    ui.text_edit_singleline(&mut self.output);
                });
                ComboBox::from_label("Compression")
                    .selected_text(format!("{:?}", self.compression))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.compression, CompressionType::None, "None");
                        ui.selectable_value(&mut self.compression, CompressionType::Gzip, "Gzip");
                        ui.selectable_value(&mut self.compression, CompressionType::Bzip2, "Bzip2");
                        ui.selectable_value(&mut self.compression, CompressionType::Zstd, "Zstd");
                    });
                ComboBox::from_label("Mode")
                    .selected_text(format!("{:?}", self.mode))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.mode, BackupMode::Full, "Full");
                        ui.selectable_value(&mut self.mode, BackupMode::Incremental, "Incremental");
                    });
                if ui.button("Run Backup").clicked() {
                    let source = self.source.clone();
                    let output = self.output.clone();
                    let compression = self.compression;
                    let mode = self.mode;
                    let status = self.status.clone();
                    let progress = self.progress.clone();
                    std::thread::spawn(move || {
                        let res = run_backup_with_progress(
                            &source,
                            &output,
                            compression,
                            mode,
                            |d, t| {
                                let mut p = progress.lock().unwrap();
                                if t > 0 {
                                    *p = d as f32 / t as f32;
                                }
                            },
                        );
                        let mut s = status.lock().unwrap();
                        *s = match res {
                            Ok(_) => "Backup complete".to_string(),
                            Err(e) => format!("Error: {}", e),
                        };
                    });
                    save_config(&GuiConfig {
                        source: self.source.clone(),
                        output: self.output.clone(),
                        restore_path: self.restore_path.clone(),
                        restore_dest: self.restore_dest.clone(),
                    });
                    self.history = load_history();
                }
                let msg = self.status.lock().unwrap().clone();
                ui.label(msg);
                let value = *self.progress.lock().unwrap();
                ui.add(egui::ProgressBar::new(value).show_percentage());
            }
            Tab::Restore => {
                ui.heading("Restore Backup");
                ui.horizontal(|ui| {
                    ui.label("Backup file:");
                    ui.text_edit_singleline(&mut self.restore_path);
                });
                ui.horizontal(|ui| {
                    ui.label("Destination:");
                    ui.text_edit_singleline(&mut self.restore_dest);
                });
                if ui.button("Restore").clicked() {
                    let src = self.restore_path.clone();
                    let dst = self.restore_dest.clone();
                    let status = self.status.clone();
                    std::thread::spawn(move || {
                        let res = restore_backup(&src, &dst, None);
                        let mut s = status.lock().unwrap();
                        *s = match res {
                            Ok(_) => "Restore complete".to_string(),
                            Err(e) => format!("Error: {}", e),
                        };
                    });
                    save_config(&GuiConfig {
                        source: self.source.clone(),
                        output: self.output.clone(),
                        restore_path: self.restore_path.clone(),
                        restore_dest: self.restore_dest.clone(),
                    });
                }
                let msg = self.status.lock().unwrap().clone();
                ui.label(msg);
            }
            Tab::History => {
                ui.heading("Backup History");
                if self.history.is_empty() {
                    ui.label("No history available");
                } else {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for entry in &self.history {
                            let dt = chrono::NaiveDateTime::from_timestamp_opt(entry.timestamp, 0)
                                .unwrap_or_default();
                            ui.horizontal(|ui| {
                                ui.label(dt.format("%Y-%m-%d %H:%M:%S").to_string());
                                ui.label(format!("{:?}", entry.mode));
                                ui.label(&entry.backup);
                            });
                        }
                    });
                }
            }
        });
    }
}

fn main() -> Result<(), eframe::Error> {
    eframe::run_native(
        "SequoiaRecover",
        eframe::NativeOptions::default(),
        Box::new(|_cc| {
            let cfg = load_config();
            Ok(Box::new(App {
                tab: Tab::Backup,
                source: cfg.source,
                output: cfg.output,
                compression: CompressionType::Gzip,
                mode: BackupMode::Full,
                restore_path: cfg.restore_path,
                restore_dest: cfg.restore_dest,
                history: load_history(),
                status: Arc::new(Mutex::new(String::new())),
                progress: Arc::new(Mutex::new(0.0)),
            }))
        }),
    )
}
