use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use once_cell::sync::Lazy;
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

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

const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4MB
const DEDUP_INDEX: &str = ".sequoiarecover/dedup.json";

#[derive(Serialize, Deserialize, Default)]
struct DedupIndexFile {
    hashes: HashSet<String>,
}

fn load_dedup_index() -> DedupIndexFile {
    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        let path = PathBuf::from(home).join(DEDUP_INDEX);
        if let Ok(file) = File::open(&path) {
            if let Ok(index) = serde_json::from_reader(file) {
                return index;
            }
        }
    }
    DedupIndexFile::default()
}

fn save_dedup_index(index: &DedupIndexFile) {
    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        let path = PathBuf::from(home).join(DEDUP_INDEX);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut f) = File::create(path) {
            let _ = serde_json::to_writer(&mut f, index);
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    hashes: Vec<String>,
    uploaded: Vec<bool>,
}

pub fn upload_in_chunks(
    provider: &dyn StorageProvider,
    bucket: &str,
    file_path: &str,
) -> Result<(), Box<dyn Error>> {
    let manifest_path = format!("{}.manifest", file_path);
    let mut manifest: Manifest;

    if Path::new(&manifest_path).exists() {
        let file = File::open(&manifest_path)?;
        manifest = serde_json::from_reader(file)?;
    } else {
        let mut file = File::open(file_path)?;
        let mut hashes = Vec::new();
        let mut buf = vec![0u8; CHUNK_SIZE];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 { break; }
            let mut hasher = Sha256::new();
            hasher.update(&buf[..n]);
            hashes.push(format!("{:x}", hasher.finalize()));
        }
        let len = hashes.len();
        manifest = Manifest { hashes, uploaded: vec![false; len] };
        let mut mf = File::create(&manifest_path)?;
        serde_json::to_writer(&mut mf, &manifest)?;
    }

    let mut index = load_dedup_index();
    let mut file = File::open(file_path)?;
    let mut buf = vec![0u8; CHUNK_SIZE];
    for (i, hash) in manifest.hashes.iter().enumerate() {
        file.seek(SeekFrom::Start((i as u64) * CHUNK_SIZE as u64))?;
        let n = file.read(&mut buf)?;
        if manifest.uploaded[i] || index.hashes.contains(hash) {
            manifest.uploaded[i] = true;
            continue;
        }
        let mut tmp = std::env::temp_dir();
        tmp.push(hash);
        {
            let mut chunk_f = File::create(&tmp)?;
            chunk_f.write_all(&buf[..n])?;
        }
        provider.upload_blocking(bucket, tmp.to_str().unwrap())?;
        let _ = std::fs::remove_file(&tmp);
        manifest.uploaded[i] = true;
        index.hashes.insert(hash.clone());

        let mut mf = OpenOptions::new().write(true).truncate(true).open(&manifest_path)?;
        serde_json::to_writer(&mut mf, &manifest)?;
        save_dedup_index(&index);
    }

    Ok(())
}
