use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Local};
use tokio::runtime::Runtime;
use tracing::info;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::{
    config::{Credentials as AwsCredentials, Region},
    primitives::ByteStream,
    Client as S3Client,
};
use crate::backup::{list_backup, restore_backup, CompressionType};
use super::StorageProvider;

async fn s3_client(access_key: &str, secret_key: &str, region: &str) -> Result<S3Client, Box<dyn Error>> {
    let creds = AwsCredentials::new(access_key, secret_key, None, None, "static");
    let region_provider = RegionProviderChain::first_try(Some(Region::new(region.to_string())));
    let config = aws_config::from_env()
        .credentials_provider(creds)
        .region(region_provider)
        .load()
        .await;
    Ok(S3Client::new(&config))
}

async fn upload_to_s3(
    access_key: &str,
    secret_key: &str,
    region: &str,
    bucket: &str,
    file_path: &str,
) -> Result<(), Box<dyn Error>> {
    let client = s3_client(access_key, secret_key, region).await?;
    let data = tokio::fs::read(file_path).await?;
    let name = PathBuf::from(file_path)
        .file_name()
        .ok_or("invalid file")?
        .to_string_lossy()
        .to_string();
    client
        .put_object()
        .bucket(bucket)
        .key(&name)
        .body(ByteStream::from(data))
        .send()
        .await?;
    Ok(())
}

pub fn upload_to_s3_blocking(
    access_key: &str,
    secret_key: &str,
    region: &str,
    bucket: &str,
    file_path: &str,
) -> Result<(), Box<dyn Error>> {
    if let Ok(local) = std::env::var("LOCAL_S3_DIR") {
        let bucket_dir = Path::new(&local).join(bucket);
        std::fs::create_dir_all(&bucket_dir)?;
        let name = Path::new(file_path).file_name().ok_or("invalid file")?;
        let dest = bucket_dir.join(name);
        std::fs::copy(file_path, &dest)?;
        Ok(())
    } else {
        let rt = Runtime::new()?;
        rt.block_on(upload_to_s3(access_key, secret_key, region, bucket, file_path))
    }
}

async fn download_from_s3(
    access_key: &str,
    secret_key: &str,
    region: &str,
    bucket: &str,
    file_name: &str,
    dest: &Path,
) -> Result<(), Box<dyn Error>> {
    let client = s3_client(access_key, secret_key, region).await?;
    let resp = client.get_object().bucket(bucket).key(file_name).send().await?;
    let data = resp.body.collect().await?.into_bytes();
    tokio::fs::write(dest, data).await?;
    Ok(())
}

pub fn download_from_s3_blocking(
    access_key: &str,
    secret_key: &str,
    region: &str,
    bucket: &str,
    file_name: &str,
    dest: &Path,
) -> Result<(), Box<dyn Error>> {
    if let Ok(local) = std::env::var("LOCAL_S3_DIR") {
        let src_path = Path::new(&local).join(bucket).join(file_name);
        if !src_path.exists() {
            return Err("File not found".into());
        }
        std::fs::copy(src_path, dest)?;
        Ok(())
    } else {
        let rt = Runtime::new()?;
        rt.block_on(download_from_s3(access_key, secret_key, region, bucket, file_name, dest))
    }
}

async fn show_s3_history(
    access_key: &str,
    secret_key: &str,
    region: &str,
    bucket: &str,
    retention: Option<Duration>,
) -> Result<(), Box<dyn Error>> {
    let client = s3_client(access_key, secret_key, region).await?;
    let resp = client.list_objects_v2().bucket(bucket).send().await?;
    if let Some(objs) = resp.contents {
        for obj in objs {
            let ts = format!("{:?}", obj.last_modified);
            let name = obj.key.unwrap_or_default();
            info!("{}\t{}", ts, name);
            if let Some(r) = retention {
                if let Some(_) = obj.last_modified {
                    // deletion ignored for simplicity
                    if r == Duration::ZERO {
                        let _ = client.delete_object().bucket(bucket).key(name).send().await?;
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn show_s3_history_blocking(
    access_key: &str,
    secret_key: &str,
    region: &str,
    bucket: &str,
    retention: Option<Duration>,
) -> Result<(), Box<dyn Error>> {
    if let Ok(local) = std::env::var("LOCAL_S3_DIR") {
        let dir = Path::new(&local).join(bucket);
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                if let Ok(meta) = e.metadata() {
                    if meta.is_file() {
                        let ts = meta.modified()?.duration_since(UNIX_EPOCH)?;
                        let dt: DateTime<Local> = (UNIX_EPOCH + ts).into();
                        info!("{}\t{}", dt.format("%Y-%m-%d %H:%M:%S"), e.file_name().to_string_lossy());
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
        rt.block_on(show_s3_history(access_key, secret_key, region, bucket, retention))
    }
}

pub fn list_s3_backup_blocking(
    access_key: &str,
    secret_key: &str,
    region: &str,
    bucket: &str,
    backup: &str,
    compression: Option<CompressionType>,
) -> Result<(), Box<dyn Error>> {
    let tmp_path = std::env::temp_dir().join(
        Path::new(backup)
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("backup.tmp")),
    );
    download_from_s3_blocking(access_key, secret_key, region, bucket, backup, &tmp_path)?;
    let result = list_backup(tmp_path.to_str().unwrap(), compression);
    let _ = std::fs::remove_file(&tmp_path);
    result
}

pub fn restore_s3_backup_blocking(
    access_key: &str,
    secret_key: &str,
    region: &str,
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
    download_from_s3_blocking(access_key, secret_key, region, bucket, backup, &tmp_path)?;
    let result = restore_backup(tmp_path.to_str().unwrap(), destination, compression);
    let _ = std::fs::remove_file(&tmp_path);
    result
}


#[derive(Clone)]
pub struct AwsProvider {
    access_key: String,
    secret_key: String,
    region: String,
}

impl AwsProvider {
    pub fn new(access_key: &str, secret_key: &str, region: &str) -> Self {
        Self { access_key: access_key.to_string(), secret_key: secret_key.to_string(), region: region.to_string() }
    }
}

impl StorageProvider for AwsProvider {
    fn upload_blocking(&self, bucket: &str, file_path: &str) -> Result<(), Box<dyn Error>> {
        upload_to_s3_blocking(&self.access_key, &self.secret_key, &self.region, bucket, file_path)
    }

    fn download_blocking(&self, bucket: &str, file_name: &str, dest: &Path) -> Result<(), Box<dyn Error>> {
        download_from_s3_blocking(&self.access_key, &self.secret_key, &self.region, bucket, file_name, dest)
    }

    fn show_history_blocking(&self, bucket: &str, retention: Option<Duration>) -> Result<(), Box<dyn Error>> {
        show_s3_history_blocking(&self.access_key, &self.secret_key, &self.region, bucket, retention)
    }
}

