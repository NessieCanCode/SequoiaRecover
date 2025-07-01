use std::error::Error;
use std::thread;
use std::time::Duration;

use sequoiarecover::backup::{run_backup, BackupMode, CompressionType};
use sequoiarecover::config::{history_file_path, HistoryEntry};

#[derive(Default, Clone)]
pub struct BackupConfig {
    pub source: String,
    pub output: String,
    pub compression: CompressionType,
    pub mode: BackupMode,
}

pub fn perform_backup(cfg: &BackupConfig) -> Result<(), String> {
    run_backup(&cfg.source, &cfg.output, cfg.compression, cfg.mode).map_err(|e| e.to_string())
}

pub fn schedule_backups(cfg: BackupConfig, interval: u64, max_runs: u64) {
    thread::spawn(move || {
        let mut runs = 0u64;
        loop {
            if max_runs > 0 && runs >= max_runs {
                break;
            }
            if let Err(e) = perform_backup(&cfg) {
                eprintln!("Scheduled backup failed: {}", e);
            }
            runs += 1;
            thread::sleep(Duration::from_secs(interval));
        }
    });
}

pub fn load_history() -> Result<Vec<HistoryEntry>, Box<dyn Error>> {
    let path = history_file_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let f = std::fs::File::open(path)?;
    let history: Vec<HistoryEntry> = serde_json::from_reader(f)?;
    Ok(history)
}
