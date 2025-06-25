use directories::ProjectDirs;
use eframe::egui;
use sequoiarecover::backup::{run_backup_with_progress, BackupMode, CompressionType};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize, Default)]
struct GuiConfig {
    source: String,
    output: String,
}

struct App {
    source: String,
    output: String,
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

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("SequoiaRecover GUI");
            ui.horizontal(|ui| {
                ui.label("Source:");
                ui.text_edit_singleline(&mut self.source);
            });
            ui.horizontal(|ui| {
                ui.label("Output:");
                ui.text_edit_singleline(&mut self.output);
            });
            if ui.button("Run Backup").clicked() {
                let source = self.source.clone();
                let output = self.output.clone();
                let status = self.status.clone();
                let progress = self.progress.clone();
                std::thread::spawn(move || {
                    let res = run_backup_with_progress(
                        &source,
                        &output,
                        CompressionType::Gzip,
                        BackupMode::Full,
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
                });
            }
            let msg = self.status.lock().unwrap().clone();
            ui.label(msg);
            let value = *self.progress.lock().unwrap();
            ui.add(egui::ProgressBar::new(value).show_percentage());
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
                source: cfg.source,
                output: cfg.output,
                status: Arc::new(Mutex::new(String::new())),
                progress: Arc::new(Mutex::new(0.0)),
            }))
        }),
    )
}
