use eframe::egui;
use std::sync::{Arc, Mutex};
use sequoiarecover::backup::{run_backup, BackupMode, CompressionType};

struct App {
    source: String,
    output: String,
    status: Arc<Mutex<String>>,
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
                std::thread::spawn(move || {
                    let res = run_backup(&source, &output, CompressionType::Gzip, BackupMode::Full);
                    let mut s = status.lock().unwrap();
                    *s = match res {
                        Ok(_) => "Backup complete".to_string(),
                        Err(e) => format!("Error: {}", e),
                    };
                });
            }
            let msg = self.status.lock().unwrap().clone();
            ui.label(msg);
        });
    }
}

fn main() -> Result<(), eframe::Error> {
    eframe::run_native(
        "SequoiaRecover",
        eframe::NativeOptions::default(),
        Box::new(|_cc| {
            Ok(Box::new(App {
                source: String::new(),
                output: String::new(),
                status: Arc::new(Mutex::new(String::new())),
            }))
        }),
    )
}

