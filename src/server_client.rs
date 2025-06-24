use crate::backup::{list_backup, restore_backup, CompressionType};
use crate::server::FileInfo;
use chrono::{DateTime, Local};
use reqwest::blocking::Client;
use std::error::Error;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

pub fn upload_to_server_blocking(server_url: &str, bucket: &str, file_path: &str) -> Result<(), Box<dyn Error>> {
    let client = Client::new();
    let data = std::fs::read(file_path)?;
    let name = Path::new(file_path)
        .file_name()
        .ok_or("invalid file")?
        .to_string_lossy();
    let url = format!("{}/upload/{}/{}", server_url.trim_end_matches('/'), bucket, name);
    let resp = client.post(url).body(data).send()?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("Upload failed: {}", resp.status()).into())
    }
}

pub fn download_from_server_blocking(server_url: &str, bucket: &str, file_name: &str, dest: &Path) -> Result<(), Box<dyn Error>> {
    let client = Client::new();
    let url = format!("{}/download/{}/{}", server_url.trim_end_matches('/'), bucket, file_name);
    let resp = client.get(url).send()?;
    if resp.status().is_success() {
        let bytes = resp.bytes()?;
        std::fs::write(dest, &bytes)?;
        Ok(())
    } else {
        Err(format!("Download failed: {}", resp.status()).into())
    }
}

pub fn show_server_history_blocking(server_url: &str, bucket: &str) -> Result<(), Box<dyn Error>> {
    let client = Client::new();
    let url = format!("{}/list/{}", server_url.trim_end_matches('/'), bucket);
    let resp = client.get(url).send()?;
    if resp.status().is_success() {
        let entries: Vec<FileInfo> = resp.json()?;
        for e in entries {
            let dt: DateTime<Local> = (UNIX_EPOCH + Duration::from_secs(e.modified as u64)).into();
            println!("{}\t{}", dt.format("%Y-%m-%d %H:%M:%S"), e.name);
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
