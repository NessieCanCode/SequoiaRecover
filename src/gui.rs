use chrono::TimeZone;
use directories::ProjectDirs;
use eframe::egui::{self, ComboBox, TextEdit};
use rfd::FileDialog;
use sequoiarecover::backup::{
    restore_backup, run_backup_with_progress, BackupMode, CompressionType,
};
use sequoiarecover::config::{
    config_file_path, encrypt_config, history_file_path, Config, HistoryEntry,
};
use sequoiarecover::remote::{
    restore_remote_backup_blocking, restore_s3_backup_blocking, restore_azure_backup_blocking,
};
use sequoiarecover::server_client::restore_server_backup_blocking;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize, Default)]
struct GuiConfig {
    #[serde(default)]
    source: String,
    #[serde(default)]
    output: String,
    #[serde(default)]
    restore_path: String,
    #[serde(default)]
    restore_dest: String,
    #[serde(default)]
    compression: CompressionType,
    #[serde(default)]
    mode: BackupMode,
    #[serde(default)]
    restore_method: RestoreMethod,
    #[serde(default)]
    bucket: String,
    #[serde(default)]
    server_url: String,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
enum RestoreMethod {
    #[default]
    Local,
    Backblaze,
    Aws,
    Azure,
    Server,
}

enum Tab {
    Backup,
    Restore,
    History,
    Settings,
}

struct App {
    tab: Tab,
    source: String,
    output: String,
    compression: CompressionType,
    mode: BackupMode,
    restore_method: RestoreMethod,
    restore_path: String,
    restore_dest: String,
    bucket: String,
    server_url: String,
    history: Vec<HistoryEntry>,
    status: Arc<Mutex<String>>,
    progress: Arc<Mutex<f32>>,
    account_id: String,
    application_key: String,
    password: String,
    confirm: String,
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
                if ui
                    .selectable_label(matches!(self.tab, Tab::Settings), "Settings")
                    .clicked()
                {
                    self.tab = Tab::Settings;
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Backup => {
                ui.heading("Run Backup");
                ui.horizontal(|ui| {
                    ui.label("Source:");
                    ui.text_edit_singleline(&mut self.source);
                    if ui.button("Browse").clicked() {
                        if let Some(p) = FileDialog::new().pick_folder() {
                            self.source = p.display().to_string();
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Output:");
                    ui.text_edit_singleline(&mut self.output);
                    if ui.button("Browse").clicked() {
                        if let Some(p) = FileDialog::new().save_file() {
                            self.output = p.display().to_string();
                        }
                    }
                });
                ComboBox::from_label("Compression")
                    .selected_text(format!("{:?}", self.compression))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.compression, CompressionType::None, "None");
                        ui.selectable_value(&mut self.compression, CompressionType::Gzip, "Gzip");
                        ui.selectable_value(&mut self.compression, CompressionType::Bzip2, "Bzip2");
                        ui.selectable_value(&mut self.compression, CompressionType::Zstd, "Zstd");
                        ui.selectable_value(&mut self.compression, CompressionType::Auto, "Auto");
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
                        compression: self.compression,
                        mode: self.mode,
                        restore_method: self.restore_method.clone(),
                        bucket: self.bucket.clone(),
                        server_url: self.server_url.clone(),
                    });
                    self.history = load_history();
                }
                let msg = self.status.lock().unwrap().clone();
                ui.label(msg);
                let value = *self.progress.lock().unwrap();
                ui.add(egui::ProgressBar::new(value).show_percentage());
                ui.label(format!("{:.0}%", value * 100.0));
            }
            Tab::Restore => {
                ui.heading("Restore Backup");
                ComboBox::from_label("Method")
                    .selected_text(format!("{:?}", self.restore_method))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.restore_method,
                            RestoreMethod::Local,
                            "Local",
                        );
                        ui.selectable_value(
                            &mut self.restore_method,
                            RestoreMethod::Backblaze,
                            "Backblaze",
                        );
                        ui.selectable_value(
                            &mut self.restore_method,
                            RestoreMethod::Aws,
                            "AWS",
                        );
                        ui.selectable_value(
                            &mut self.restore_method,
                            RestoreMethod::Azure,
                            "Azure",
                        );
                        ui.selectable_value(
                            &mut self.restore_method,
                            RestoreMethod::Server,
                            "Server",
                        );
                    });
                match self.restore_method {
                    RestoreMethod::Local => {
                        ui.horizontal(|ui| {
                            ui.label("Backup file:");
                            ui.text_edit_singleline(&mut self.restore_path);
                            if ui.button("Browse").clicked() {
                                if let Some(p) = FileDialog::new().pick_file() {
                                    self.restore_path = p.display().to_string();
                                }
                            }
                        });
                    }
                    RestoreMethod::Backblaze | RestoreMethod::Aws | RestoreMethod::Azure | RestoreMethod::Server => {
                        ui.horizontal(|ui| {
                            ui.label("Bucket:");
                            ui.text_edit_singleline(&mut self.bucket);
                        });
                        if self.restore_method == RestoreMethod::Server {
                            ui.horizontal(|ui| {
                                ui.label("Server URL:");
                                ui.text_edit_singleline(&mut self.server_url);
                            });
                        }
                        ui.horizontal(|ui| {
                            ui.label("Backup name:");
                            ui.text_edit_singleline(&mut self.restore_path);
                        });
                    }
                }
                ui.horizontal(|ui| {
                    ui.label("Destination:");
                    ui.text_edit_singleline(&mut self.restore_dest);
                    if ui.button("Browse").clicked() {
                        if let Some(p) = FileDialog::new().pick_folder() {
                            self.restore_dest = p.display().to_string();
                        }
                    }
                });
                if ui.button("Restore").clicked() {
                    let src = self.restore_path.clone();
                    let dst = self.restore_dest.clone();
                    let bucket = self.bucket.clone();
                    let method = self.restore_method.clone();
                    let server_url = self.server_url.clone();
                    let account_id = self.account_id.clone();
                    let application_key = self.application_key.clone();
                    let status = self.status.clone();
                    std::thread::spawn(move || {
                        let res = match method {
                            RestoreMethod::Local => restore_backup(&src, &dst, None),
                            RestoreMethod::Backblaze => restore_remote_backup_blocking(
                                &account_id,
                                &application_key,
                                &bucket,
                                &src,
                                &dst,
                                None,
                            ),
                            RestoreMethod::Aws => {
                                if let (Ok(ak), Ok(sk), Ok(region)) = (
                                    std::env::var("AWS_ACCESS_KEY_ID"),
                                    std::env::var("AWS_SECRET_ACCESS_KEY"),
                                    std::env::var("AWS_REGION"),
                                ) {
                                    restore_s3_backup_blocking(&ak, &sk, &region, &bucket, &src, &dst, None)
                                } else {
                                    Err("Missing AWS credentials".into())
                                }
                            }
                            RestoreMethod::Azure => {
                                if let (Ok(acct), Ok(key)) = (
                                    std::env::var("AZURE_STORAGE_ACCOUNT"),
                                    std::env::var("AZURE_STORAGE_KEY"),
                                ) {
                                    restore_azure_backup_blocking(&acct, &key, &bucket, &src, &dst, None)
                                } else {
                                    Err("Missing Azure credentials".into())
                                }
                            }
                            RestoreMethod::Server => restore_server_backup_blocking(
                                &server_url,
                                &bucket,
                                &src,
                                &dst,
                                None,
                            ),
                        };
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
                        compression: self.compression,
                        mode: self.mode,
                        restore_method: self.restore_method.clone(),
                        bucket: self.bucket.clone(),
                        server_url: self.server_url.clone(),
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
                            let dt = chrono::Local.timestamp_opt(entry.timestamp, 0).unwrap();
                            ui.horizontal(|ui| {
                                ui.label(dt.format("%Y-%m-%d %H:%M:%S").to_string());
                                ui.label(format!("{:?}", entry.mode));
                                ui.label(&entry.backup);
                            });
                        }
                    });
                }
            }
            Tab::Settings => {
                ui.heading("Initialize Config");
                ui.horizontal(|ui| {
                    ui.label("Account ID:");
                    ui.text_edit_singleline(&mut self.account_id);
                });
                ui.horizontal(|ui| {
                    ui.label("Application Key:");
                    ui.text_edit_singleline(&mut self.application_key);
                });
                ui.horizontal(|ui| {
                    ui.label("Password:");
                    ui.add(TextEdit::singleline(&mut self.password).password(true));
                });
                ui.horizontal(|ui| {
                    ui.label("Confirm:");
                    ui.add(TextEdit::singleline(&mut self.confirm).password(true));
                });
                if ui.button("Init").clicked() {
                    if self.password != self.confirm {
                        let mut s = self.status.lock().unwrap();
                        *s = "Passwords do not match".into();
                    } else if let Ok(path) = config_file_path() {
                        let cfg = Config {
                            account_id: self.account_id.clone(),
                            application_key: self.application_key.clone(),
                        };
                        match encrypt_config(&cfg, &self.password) {
                            Ok(enc) => {
                                if let Some(p) = path.parent() {
                                    let _ = std::fs::create_dir_all(p);
                                }
                                if let Ok(f) = std::fs::File::create(&path) {
                                    if serde_json::to_writer_pretty(f, &enc).is_ok() {
                                        let mut s = self.status.lock().unwrap();
                                        *s = format!("Config written to {:?}", path);
                                    } else {
                                        let mut s = self.status.lock().unwrap();
                                        *s = "Failed to write config".into();
                                    }
                                } else {
                                    let mut s = self.status.lock().unwrap();
                                    *s = "Could not create config file".into();
                                }
                            }
                            Err(e) => {
                                let mut s = self.status.lock().unwrap();
                                *s = format!("Failed to encrypt config: {}", e);
                            }
                        }
                    } else {
                        let mut s = self.status.lock().unwrap();
                        *s = "Could not determine config path".into();
                    }
                }
                let msg = self.status.lock().unwrap().clone();
                ui.label(msg);
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
                compression: cfg.compression,
                mode: cfg.mode,
                restore_method: cfg.restore_method,
                restore_path: cfg.restore_path,
                restore_dest: cfg.restore_dest,
                bucket: cfg.bucket,
                server_url: cfg.server_url,
                history: load_history(),
                status: Arc::new(Mutex::new(String::new())),
                progress: Arc::new(Mutex::new(0.0)),
                account_id: String::new(),
                application_key: String::new(),
                password: String::new(),
                confirm: String::new(),
            }))
        }),
    )
}
