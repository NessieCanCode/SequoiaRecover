use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Local};
use tokio::runtime::Runtime;
use tracing::info;
use azure_storage::prelude::*;
use azure_storage_blobs::prelude::*;
use futures::StreamExt;
use crate::backup::{list_backup, restore_backup, CompressionType};
use super::StorageProvider;

async fn azure_container(account: &str, key: &str, container: &str) -> Result<ContainerClient, Box<dyn Error>> {
    let credentials = StorageCredentials::Key(account.to_owned(), key.to_owned());
    let service_client = BlobServiceClient::new(account.to_owned(), credentials);
    Ok(service_client.container_client(container))
}

async fn upload_to_azure(
    account: &str,
    key: &str,
    container: &str,
    file_path: &str,
) -> Result<(), Box<dyn Error>> {
    let client = azure_container(account, key, container).await?;
    let data = tokio::fs::read(file_path).await?;
    let name = PathBuf::from(file_path)
        .file_name()
        .ok_or("invalid file")?
        .to_string_lossy()
        .to_string();
    client
        .blob_client(name)
        .put_block_blob(data)
        .into_future()
        .await?;
    Ok(())
}

pub fn upload_to_azure_blocking(
    account: &str,
    key: &str,
    container: &str,
    file_path: &str,
) -> Result<(), Box<dyn Error>> {
    if let Ok(local) = std::env::var("LOCAL_AZURE_DIR") {
        let bucket_dir = Path::new(&local).join(container);
        std::fs::create_dir_all(&bucket_dir)?;
        let name = Path::new(file_path).file_name().ok_or("invalid file")?;
        let dest = bucket_dir.join(name);
        std::fs::copy(file_path, &dest)?;
        Ok(())
    } else {
        let rt = Runtime::new()?;
        rt.block_on(upload_to_azure(account, key, container, file_path))
    }
}

async fn download_from_azure(
    account: &str,
    key: &str,
    container: &str,
    file_name: &str,
    dest: &Path,
) -> Result<(), Box<dyn Error>> {
    let client = azure_container(account, key, container).await?;
    let data = client.blob_client(file_name).get_content().await?;
    tokio::fs::write(dest, data).await?;
    Ok(())
}

pub fn download_from_azure_blocking(
    account: &str,
    key: &str,
    container: &str,
    file_name: &str,
    dest: &Path,
) -> Result<(), Box<dyn Error>> {
    if let Ok(local) = std::env::var("LOCAL_AZURE_DIR") {
        let src_path = Path::new(&local).join(container).join(file_name);
        if !src_path.exists() {
            return Err("File not found".into());
        }
        std::fs::copy(src_path, dest)?;
        Ok(())
    } else {
        let rt = Runtime::new()?;
        rt.block_on(download_from_azure(account, key, container, file_name, dest))
    }
}

async fn show_azure_history(
    account: &str,
    key: &str,
    container: &str,
    retention: Option<Duration>,
) -> Result<(), Box<dyn Error>> {
    let client = azure_container(account, key, container).await?;
    let mut stream = client.list_blobs().into_stream();
    while let Some(res) = stream.next().await {
        let resp = res?;
        for blob in resp.blobs.blobs() {
            let ts = format!("{:?}", blob.properties.last_modified);
            info!("{}\t{}", ts, blob.name);
            if let Some(r) = retention {
                if r == Duration::ZERO {
                    let _ = client.blob_client(blob.name.clone()).delete().into_future().await?;
                }
            }
        }
    }
    Ok(())
}

pub fn show_azure_history_blocking(
    account: &str,
    key: &str,
    container: &str,
    retention: Option<Duration>,
) -> Result<(), Box<dyn Error>> {
    if let Ok(local) = std::env::var("LOCAL_AZURE_DIR") {
        let dir = Path::new(&local).join(container);
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
        rt.block_on(show_azure_history(account, key, container, retention))
    }
}

pub fn list_azure_backup_blocking(
    account: &str,
    key: &str,
    container: &str,
    backup: &str,
    compression: Option<CompressionType>,
) -> Result<(), Box<dyn Error>> {
    let tmp_path = std::env::temp_dir().join(
        Path::new(backup)
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("backup.tmp")),
    );
    download_from_azure_blocking(account, key, container, backup, &tmp_path)?;
    let result = list_backup(tmp_path.to_str().unwrap(), compression);
    let _ = std::fs::remove_file(&tmp_path);
    result
}

pub fn restore_azure_backup_blocking(
    account: &str,
    key: &str,
    container: &str,
    backup: &str,
    destination: &str,
    compression: Option<CompressionType>,
) -> Result<(), Box<dyn Error>> {
    let tmp_path = std::env::temp_dir().join(
        Path::new(backup)
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("backup.tmp")),
    );
    download_from_azure_blocking(account, key, container, backup, &tmp_path)?;
    let result = restore_backup(tmp_path.to_str().unwrap(), destination, compression);
    let _ = std::fs::remove_file(&tmp_path);
    result
}

#[derive(Clone)]
pub struct AzureProvider {
    account: String,
    key: String,
}

impl AzureProvider {
    pub fn new(account: &str, key: &str) -> Self {
        Self { account: account.to_string(), key: key.to_string() }
    }
}

impl StorageProvider for AzureProvider {
    fn upload_blocking(&self, bucket: &str, file_path: &str) -> Result<(), Box<dyn Error>> {
        upload_to_azure_blocking(&self.account, &self.key, bucket, file_path)
    }

    fn download_blocking(&self, bucket: &str, file_name: &str, dest: &Path) -> Result<(), Box<dyn Error>> {
        download_from_azure_blocking(&self.account, &self.key, bucket, file_name, dest)
    }

    fn show_history_blocking(&self, bucket: &str, retention: Option<Duration>) -> Result<(), Box<dyn Error>> {
        show_azure_history_blocking(&self.account, &self.key, bucket, retention)
    }
}

