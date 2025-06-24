use crate::backup::{list_backup, restore_backup, CompressionType};
use crate::server::FileInfo;
use chrono::{DateTime, Local};
use reqwest::blocking::Client;
use std::error::Error;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};
use tracing::{error, info};

pub fn upload_to_server_blocking(
    server_url: &str,
    bucket: &str,
    file_path: &str,
) -> Result<(), Box<dyn Error>> {
    let client = Client::new();
    let data = std::fs::read(file_path)?;
    let name = Path::new(file_path)
        .file_name()
        .ok_or("invalid file")?
        .to_string_lossy();
    let url = format!(
        "{}/upload/{}/{}",
        server_url.trim_end_matches('/'),
        bucket,
        name
    );
    let mut delay = Duration::from_secs(1);
    for attempt in 0..3 {
        let resp = client.post(&url).body(data.clone()).send();
        match resp {
            Ok(r) if r.status().is_success() => return Ok(()),
            Ok(r) => {
                if attempt == 2 {
                    return Err(format!("Upload failed: {}", r.status()).into());
                }
                error!("Upload attempt {} failed: {}", attempt + 1, r.status());
            }
            Err(e) => {
                if attempt == 2 {
                    return Err(format!("Upload failed: {}", e).into());
                }
                error!("Upload attempt {} error: {}", attempt + 1, e);
            }
        }
        std::thread::sleep(delay);
        delay *= 2;
    }
    unreachable!()
}

pub fn download_from_server_blocking(
    server_url: &str,
    bucket: &str,
    file_name: &str,
    dest: &Path,
) -> Result<(), Box<dyn Error>> {
    let client = Client::new();
    let url = format!(
        "{}/download/{}/{}",
        server_url.trim_end_matches('/'),
        bucket,
        file_name
    );
    let mut delay = Duration::from_secs(1);
    for attempt in 0..3 {
        let resp = client.get(&url).send();
        match resp {
            Ok(r) if r.status().is_success() => {
                let bytes = r.bytes()?;
                std::fs::write(dest, &bytes)?;
                return Ok(());
            }
            Ok(r) => {
                if attempt == 2 {
                    return Err(format!("Download failed: {}", r.status()).into());
                }
                error!("Download attempt {} failed: {}", attempt + 1, r.status());
            }
            Err(e) => {
                if attempt == 2 {
                    return Err(format!("Download failed: {}", e).into());
                }
                error!("Download attempt {} error: {}", attempt + 1, e);
            }
        }
        std::thread::sleep(delay);
        delay *= 2;
    }
    unreachable!()
}

pub fn show_server_history_blocking(server_url: &str, bucket: &str) -> Result<(), Box<dyn Error>> {
    let client = Client::new();
    let url = format!("{}/list/{}", server_url.trim_end_matches('/'), bucket);
    let resp = client.get(url).send()?;
    if resp.status().is_success() {
        let entries: Vec<FileInfo> = resp.json()?;
        for e in entries {
            let dt: DateTime<Local> = (UNIX_EPOCH + Duration::from_secs(e.modified as u64)).into();
            info!("{}\t{}", dt.format("%Y-%m-%d %H:%M:%S"), e.name);
        }
        Ok(())
    } else {
        Err(format!("Failed to get history: {}", resp.status()).into())
    }
}

pub fn list_server_backup_blocking(
    server_url: &str,
    bucket: &str,
    backup: &str,
    compression: Option<CompressionType>,
) -> Result<(), Box<dyn Error>> {
    let tmp_path = std::env::temp_dir().join(
        Path::new(backup)
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("backup.tmp")),
    );
    download_from_server_blocking(server_url, bucket, backup, &tmp_path)?;
    let result = list_backup(tmp_path.to_str().unwrap(), compression);
    let _ = std::fs::remove_file(&tmp_path);
    result
}

pub fn restore_server_backup_blocking(
    server_url: &str,
    bucket: &str,
    backup: &str,
    destination: &str,
    compression: Option<CompressionType>,
) -> Result<(), Box<dyn Error>> {
    let tmp_path = std::env::temp_dir().join(
        Path::new(backup)
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("backup.tmp")),
    );
    download_from_server_blocking(server_url, bucket, backup, &tmp_path)?;
    let result = restore_backup(tmp_path.to_str().unwrap(), destination, compression);
    let _ = std::fs::remove_file(&tmp_path);
    result
}
