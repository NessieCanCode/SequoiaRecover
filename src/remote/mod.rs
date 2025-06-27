use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::Duration;

use once_cell::sync::Lazy;
use std::sync::Mutex;

use crate::backup::{list_backup, restore_backup, CompressionType};

pub mod backblaze;
pub mod aws;
pub mod azure;

pub trait StorageProvider: Send + Sync {
    fn upload_blocking(&self, bucket: &str, file_path: &str) -> Result<(), Box<dyn Error>>;
    fn download_blocking(&self, bucket: &str, file_name: &str, dest: &Path) -> Result<(), Box<dyn Error>>;
    fn show_history_blocking(&self, bucket: &str, retention: Option<Duration>) -> Result<(), Box<dyn Error>>;

    fn list_backup_blocking(
        &self,
        bucket: &str,
        backup: &str,
        compression: Option<CompressionType>,
    ) -> Result<(), Box<dyn Error>> {
        let tmp_path = std::env::temp_dir().join(
            Path::new(backup)
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("backup.tmp")),
        );
        self.download_blocking(bucket, backup, &tmp_path)?;
        let result = list_backup(tmp_path.to_str().unwrap(), compression);
        let _ = std::fs::remove_file(&tmp_path);
        result
    }

    fn restore_backup_blocking(
        &self,
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
        self.download_blocking(bucket, backup, &tmp_path)?;
        let result = restore_backup(tmp_path.to_str().unwrap(), destination, compression);
        let _ = std::fs::remove_file(&tmp_path);
        result
    }
}

pub type ProviderFactory = Box<dyn Fn() -> Box<dyn StorageProvider> + Send + Sync>;

static REGISTRY: Lazy<Mutex<HashMap<String, ProviderFactory>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn register_provider(name: &str, factory: ProviderFactory) {
    REGISTRY.lock().unwrap().insert(name.to_string(), factory);
}

pub fn get_provider(name: &str) -> Option<Box<dyn StorageProvider>> {
    REGISTRY.lock().unwrap().get(name).map(|f| f())
}

use serde::Deserialize;

const PROVIDERS_CONFIG_PATH: &str = ".sequoiarecover/providers.json";

#[derive(Deserialize)]
struct ProvidersFile {
    providers: Vec<ProviderEntry>,
}

#[derive(Deserialize)]
struct ProviderEntry {
    name: String,
    #[serde(rename = "type")]
    provider_type: String,
    #[serde(default)]
    credentials: HashMap<String, String>,
}

pub fn load_providers_from_config() -> Result<(), Box<dyn Error>> {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"))?;
    let path = PathBuf::from(home).join(PROVIDERS_CONFIG_PATH);
    if !path.exists() {
        return Ok(());
    }
    let file = std::fs::File::open(path)?;
    let cfg: ProvidersFile = serde_json::from_reader(file)?;
    for p in cfg.providers {
        match p.provider_type.as_str() {
            "backblaze" => {
                if let (Some(id), Some(key)) = (
                    p.credentials.get("account_id"),
                    p.credentials.get("application_key"),
                ) {
                    let id = id.clone();
                    let key = key.clone();
                    register_provider(
                        &p.name,
                        Box::new(move || Box::new(backblaze::BackblazeProvider::new(&id, &key))),
                    );
                }
            }
            "aws" => {
                if let (Some(ak), Some(sk), Some(region)) = (
                    p.credentials.get("access_key"),
                    p.credentials.get("secret_key"),
                    p.credentials.get("region"),
                ) {
                    let ak = ak.clone();
                    let sk = sk.clone();
                    let region = region.clone();
                    register_provider(
                        &p.name,
                        Box::new(move || Box::new(aws::AwsProvider::new(&ak, &sk, &region))),
                    );
                }
            }
            "azure" => {
                if let (Some(acct), Some(key)) = (
                    p.credentials.get("account"),
                    p.credentials.get("key"),
                ) {
                    let acct = acct.clone();
                    let key = key.clone();
                    register_provider(
                        &p.name,
                        Box::new(move || Box::new(azure::AzureProvider::new(&acct, &key))),
                    );
                }
            }
            _ => {}
        }
    }
    Ok(())
}

pub use backblaze::{
    download_from_backblaze_blocking, list_remote_backup_blocking,
    restore_remote_backup_blocking, show_remote_history_blocking,
    upload_to_backblaze_blocking,
};

pub use aws::{
    download_from_s3_blocking, list_s3_backup_blocking, restore_s3_backup_blocking,
    show_s3_history_blocking, upload_to_s3_blocking,
};

pub use azure::{
    download_from_azure_blocking, list_azure_backup_blocking,
    restore_azure_backup_blocking, show_azure_history_blocking,
    upload_to_azure_blocking,
};
