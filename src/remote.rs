use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::backup::{list_backup, restore_backup, CompressionType};
use backblaze_b2_client::client::B2Client;
use backblaze_b2_client::definitions::bodies::B2DeleteFileVersionBody;
use backblaze_b2_client::definitions::bodies::B2ListBucketsBody;
use backblaze_b2_client::definitions::query_params::B2ListFileNamesQueryParameters;
use chrono::{DateTime, Local};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs::File as TokioFile;
use tokio::runtime::Runtime;
use tracing::{error, info};

fn file_sha256(path: &Path) -> Result<String, Box<dyn Error>> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

async fn upload_to_backblaze(
    account_id: &str,
    application_key: &str,
    bucket: &str,
    file_path: &str,
    checksum: &str,
) -> Result<(), Box<dyn Error>> {
    let client = B2Client::new(account_id.to_string(), application_key.to_string()).await?;
    let file = TokioFile::open(file_path).await?;
    let metadata = file.metadata().await?;
    let name = PathBuf::from(file_path)
        .file_name()
        .ok_or("invalid file")?
        .to_string_lossy()
        .to_string();
    let upload = client
        .create_upload(
            file,
            name.clone(),
            bucket.to_string(),
            None,
            metadata.len(),
            None,
        )
        .await;
    upload.start().await?;
    // verify checksum by re-downloading the file
    let basic = client.basic_client();
    let resp = basic
        .download_file_by_name(bucket.to_string(), name.clone(), None)
        .await?;
    let data = resp.file.read_all().await?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let remote = format!("{:x}", hasher.finalize());
    if remote != checksum {
        return Err("Checksum mismatch after upload".into());
    }
    Ok(())
}

pub fn upload_to_backblaze_blocking(
    account_id: &str,
    application_key: &str,
    bucket: &str,
    file_path: &str,
) -> Result<(), Box<dyn Error>> {
    let checksum = file_sha256(Path::new(file_path))?;
    if let Ok(local) = std::env::var("LOCAL_B2_DIR") {
        let bucket_dir = Path::new(&local).join(bucket);
        std::fs::create_dir_all(&bucket_dir)?;
        let name = Path::new(file_path).file_name().ok_or("invalid file")?;
        let dest = bucket_dir.join(name);
        std::fs::copy(file_path, &dest)?;
        let remote = file_sha256(&dest)?;
        if remote != checksum {
            return Err("Checksum mismatch after upload".into());
        }
        Ok(())
    } else {
        let rt = Runtime::new()?;
        let mut delay = Duration::from_secs(1);
        for attempt in 0..3 {
            match rt.block_on(upload_to_backblaze(
                account_id,
                application_key,
                bucket,
                file_path,
                &checksum,
            )) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if attempt == 2 {
                        return Err(e);
                    } else {
                        error!("Upload attempt {} failed: {}", attempt + 1, e);
                        std::thread::sleep(delay);
                        delay *= 2;
                    }
                }
            }
        }
        unreachable!()
    }
}

async fn download_from_backblaze(
    account_id: &str,
    application_key: &str,
    bucket: &str,
    file_name: &str,
    dest: &Path,
) -> Result<(), Box<dyn Error>> {
    let client = B2Client::new(account_id.to_string(), application_key.to_string()).await?;
    let basic = client.basic_client();
    let resp = basic
        .download_file_by_name(bucket.to_string(), file_name.to_string(), None)
        .await?;
    let data = resp.file.read_all().await?;
    tokio::fs::write(dest, data).await?;
    Ok(())
}

pub fn download_from_backblaze_blocking(
    account_id: &str,
    application_key: &str,
    bucket: &str,
    file_name: &str,
    dest: &Path,
) -> Result<(), Box<dyn Error>> {
    if let Ok(local) = std::env::var("LOCAL_B2_DIR") {
        let src_path = Path::new(&local).join(bucket).join(file_name);
        if !src_path.exists() {
            return Err("File not found".into());
        }
        std::fs::copy(src_path, dest)?;
        Ok(())
    } else {
        let rt = Runtime::new()?;
        let mut delay = Duration::from_secs(1);
        for attempt in 0..3 {
            match rt.block_on(download_from_backblaze(
                account_id,
                application_key,
                bucket,
                file_name,
                dest,
            )) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if attempt == 2 {
                        return Err(e);
                    } else {
                        error!("Download attempt {} failed: {}", attempt + 1, e);
                        std::thread::sleep(delay);
                        delay *= 2;
                    }
                }
            }
        }
        unreachable!()
    }
}

async fn show_remote_history(
    account_id: &str,
    application_key: &str,
    bucket: &str,
    retention: Option<Duration>,
) -> Result<(), Box<dyn Error>> {
    let client = B2Client::new(account_id.to_string(), application_key.to_string()).await?;
    let basic = client.basic_client();
    let buckets = basic
        .list_buckets(
            B2ListBucketsBody::builder()
                .account_id(account_id.to_string())
                .bucket_name(Some(bucket.to_string()))
                .build(),
        )
        .await?;
    let bucket_id = buckets
        .buckets
        .first()
        .ok_or("Bucket not found")?
        .bucket_id
        .clone();
    let mut next: Option<String> = None;
    loop {
        let params = B2ListFileNamesQueryParameters::builder()
            .bucket_id(bucket_id.clone())
            .start_file_name(next.clone())
            .max_file_count(Some(std::num::NonZeroU32::new(1000).unwrap()))
            .build();
        let resp = basic.list_file_names(params).await?;
        for file in resp.files {
            let file_time = UNIX_EPOCH + Duration::from_millis(file.upload_timestamp);
            let dt: DateTime<Local> = file_time.into();
            info!("{}\t{}", dt.format("%Y-%m-%d %H:%M:%S"), file.file_name);
            if let Some(r) = retention {
                if SystemTime::now().duration_since(file_time)? > r {
                    let _ = basic
                        .delete_file_version(
                            B2DeleteFileVersionBody::builder()
                                .file_name(file.file_name.clone())
                                .file_id(file.file_id.clone())
                                .build(),
                        )
                        .await?;
                }
            }
        }
        if let Some(n) = resp.next_file_name {
            next = Some(n);
        } else {
            break;
        }
    }
    Ok(())
}

pub fn show_remote_history_blocking(
    account_id: &str,
    application_key: &str,
    bucket: &str,
    retention: Option<Duration>,
) -> Result<(), Box<dyn Error>> {
    if let Ok(local) = std::env::var("LOCAL_B2_DIR") {
        let dir = Path::new(&local).join(bucket);
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                if let Ok(meta) = e.metadata() {
                    if meta.is_file() {
                        let ts = meta.modified()?.duration_since(UNIX_EPOCH)?;
                        let dt: DateTime<Local> = (UNIX_EPOCH + ts).into();
                        info!(
                            "{}\t{}",
                            dt.format("%Y-%m-%d %H:%M:%S"),
                            e.file_name().to_string_lossy()
                        );
                        if let Some(r) = retention {
                            if SystemTime::now().duration_since(UNIX_EPOCH + ts)? > r {
                                let _ = std::fs::remove_file(e.path());
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    } else {
        let rt = Runtime::new()?;
        rt.block_on(show_remote_history(
            account_id,
            application_key,
            bucket,
            retention,
        ))
    }
}

pub fn list_remote_backup_blocking(
    account_id: &str,
    application_key: &str,
    bucket: &str,
    backup: &str,
    compression: Option<CompressionType>,
) -> Result<(), Box<dyn Error>> {
    let tmp_path = std::env::temp_dir().join(
        Path::new(backup)
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("backup.tmp")),
    );
    download_from_backblaze_blocking(account_id, application_key, bucket, backup, &tmp_path)?;
    let result = list_backup(tmp_path.to_str().unwrap(), compression);
    let _ = std::fs::remove_file(&tmp_path);
    result
}

pub fn restore_remote_backup_blocking(
    account_id: &str,
    application_key: &str,
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
    download_from_backblaze_blocking(account_id, application_key, bucket, backup, &tmp_path)?;
    let result = restore_backup(tmp_path.to_str().unwrap(), destination, compression);
    let _ = std::fs::remove_file(&tmp_path);
    result
}
