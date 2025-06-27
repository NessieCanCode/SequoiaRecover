use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use chrono::{DateTime, Local};
use keyring::Entry;
use pbkdf2::pbkdf2_hmac;
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::error::Error;
use std::fs::File;
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use crate::backup::{BackupMode, CompressionType};

pub const CONFIG_PATH: &str = ".sequoiarecover/config.enc";
pub const HISTORY_PATH: &str = ".sequoiarecover/history.json";
pub const LOCAL_KEY_PATH: &str = ".sequoiarecover/archive_key";
pub const SALT_PATH: &str = ".sequoiarecover/archive_salt";
pub const KEYRING_SERVICE: &str = "sequoiarecover";

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub account_id: String,
    pub application_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedConfig {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Serialize, Deserialize)]
pub struct HistoryEntry {
    pub timestamp: i64,
    pub backup: String,
    pub mode: BackupMode,
    pub compression: CompressionType,
    #[serde(default)]
    pub providers: Vec<String>,
}

pub fn config_file_path() -> Result<PathBuf, Box<dyn Error>> {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"))?;
    Ok(PathBuf::from(home).join(CONFIG_PATH))
}

pub fn history_file_path() -> Result<PathBuf, Box<dyn Error>> {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"))?;
    Ok(PathBuf::from(home).join(HISTORY_PATH))
}

pub fn salt_file_path() -> Result<PathBuf, Box<dyn Error>> {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"))?;
    Ok(PathBuf::from(home).join(SALT_PATH))
}

pub fn get_or_create_archive_salt() -> Result<Vec<u8>, Box<dyn Error>> {
    let path = salt_file_path()?;
    if path.exists() {
        let data = std::fs::read(&path)?;
        return Ok(data);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    std::fs::write(&path, &salt)?;
    Ok(salt.to_vec())
}

pub fn load_archive_salt() -> Result<Vec<u8>, Box<dyn Error>> {
    let path = salt_file_path()?;
    if !path.exists() {
        return Err("Encryption key missing. Generate it with 'keygen'".into());
    }
    Ok(std::fs::read(path)?)
}

pub fn derive_archive_key(account_id: &str, application_key: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let password = format!("{}:{}", account_id, application_key);
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 200_000, &mut key);
    key
}

pub fn local_key_file_path() -> Result<PathBuf, Box<dyn Error>> {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"))?;
    Ok(PathBuf::from(home).join(LOCAL_KEY_PATH))
}

pub fn get_or_create_local_key() -> Result<[u8; 32], Box<dyn Error>> {
    let path = local_key_file_path()?;
    if path.exists() {
        let data = std::fs::read(&path)?;
        if data.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&data);
            return Ok(key);
        }
    }
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    std::fs::write(&path, &key)?;
    Ok(key)
}

pub fn load_local_key() -> Result<[u8; 32], Box<dyn Error>> {
    let path = local_key_file_path()?;
    if !path.exists() {
        return Err("Encryption key missing. Generate it with 'keygen'".into());
    }
    let data = std::fs::read(&path)?;
    if data.len() != 32 {
        return Err("Invalid key length".into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data);
    Ok(key)
}

pub fn encrypt_config(config: &Config, password: &str) -> Result<EncryptedConfig, Box<dyn Error>> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 100_000, &mut key);
    let cipher = ChaCha20Poly1305::new(&key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = nonce_bytes
        .as_slice()
        .try_into()
        .expect("nonce length mismatch");
    let plaintext = serde_json::to_vec(config)?;
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;
    Ok(EncryptedConfig {
        salt: general_purpose::STANDARD.encode(salt),
        nonce: general_purpose::STANDARD.encode(nonce_bytes),
        ciphertext: general_purpose::STANDARD.encode(&ciphertext),
    })
}

pub fn decrypt_config(enc: &EncryptedConfig, password: &str) -> Result<Config, Box<dyn Error>> {
    let salt = general_purpose::STANDARD.decode(&enc.salt)?;
    let nonce_bytes = general_purpose::STANDARD.decode(&enc.nonce)?;
    let ciphertext = general_purpose::STANDARD.decode(&enc.ciphertext)?;
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 100_000, &mut key);
    let cipher = ChaCha20Poly1305::new(&key.into());
    let nonce = nonce_bytes
        .as_slice()
        .try_into()
        .expect("nonce length mismatch");
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
    Ok(serde_json::from_slice(&plaintext)?)
}

fn load_credentials_file() -> Result<(String, String), Box<dyn Error>> {
    let path = config_file_path()?;
    if !path.exists() {
        return Err("Missing credentials".into());
    }
    let password = rpassword::prompt_password("Config password: ")?;
    let reader = File::open(path)?;
    let enc: EncryptedConfig = serde_json::from_reader(reader)?;
    let config = decrypt_config(&enc, &password)?;
    Ok((config.account_id, config.application_key))
}

fn load_credentials_keyring() -> Result<(String, String), Box<dyn Error>> {
    let id_entry = Entry::new(KEYRING_SERVICE, "account_id")?;
    let key_entry = Entry::new(KEYRING_SERVICE, "application_key")?;
    let id = id_entry.get_password()?;
    let key = key_entry.get_password()?;
    Ok((id, key))
}

pub fn store_credentials_keyring(
    account_id: &str,
    application_key: &str,
) -> Result<(), Box<dyn Error>> {
    let id_entry = Entry::new(KEYRING_SERVICE, "account_id")?;
    let key_entry = Entry::new(KEYRING_SERVICE, "application_key")?;
    id_entry.set_password(account_id)?;
    key_entry.set_password(application_key)?;
    Ok(())
}

pub fn load_credentials(
    account_id: Option<String>,
    application_key: Option<String>,
    use_keyring: bool,
) -> Result<(String, String), Box<dyn Error>> {
    match (account_id, application_key) {
        (Some(id), Some(key)) => Ok((id, key)),
        _ => {
            if use_keyring {
                match load_credentials_keyring() {
                    Ok(creds) => Ok(creds),
                    Err(e) => {
                        eprintln!("Keyring error: {}. Falling back to config file", e);
                        load_credentials_file()
                    }
                }
            } else {
                load_credentials_file()
            }
        }
    }
}

pub fn record_backup(
    backup: &str,
    mode: BackupMode,
    compression: CompressionType,
) -> Result<(), Box<dyn Error>> {
    let path = history_file_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut history: Vec<HistoryEntry> = if path.exists() {
        let f = File::open(&path)?;
        serde_json::from_reader(f).unwrap_or_default()
    } else {
        Vec::new()
    };
    history.push(HistoryEntry {
        timestamp: chrono::Utc::now().timestamp(),
        backup: backup.to_string(),
        mode,
        compression,
        providers: Vec::new(),
    });
    let f = File::create(&path)?;
    serde_json::to_writer_pretty(f, &history)?;
    Ok(())
}

pub fn show_history() -> Result<(), Box<dyn Error>> {
    let path = history_file_path()?;
    if !path.exists() {
        println!("No history available");
        return Ok(());
    }
    let f = File::open(path)?;
    let history: Vec<HistoryEntry> = serde_json::from_reader(f)?;
    for entry in history {
        let dt: DateTime<Local> = (UNIX_EPOCH + Duration::from_secs(entry.timestamp as u64)).into();
        println!(
            "{}\t{:?}\t{}\t{}",
            dt.format("%Y-%m-%d %H:%M:%S"),
            entry.mode,
            entry.backup,
            entry.providers.join(",")
        );
    }
    Ok(())
}

pub fn read_history() -> Result<Vec<HistoryEntry>, Box<dyn Error>> {
    let path = history_file_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let f = File::open(path)?;
    let history: Vec<HistoryEntry> = serde_json::from_reader(f)?;
    Ok(history)
}

pub fn update_backup_providers(backup: &str, providers: &[String]) -> Result<(), Box<dyn Error>> {
    let path = history_file_path()?;
    if !path.exists() {
        return Ok(());
    }
    let f = File::open(&path)?;
    let mut history: Vec<HistoryEntry> = serde_json::from_reader(f)?;
    if let Some(entry) = history.iter_mut().find(|e| e.backup == backup) {
        entry.providers = providers.to_vec();
        let f = File::create(&path)?;
        serde_json::to_writer_pretty(f, &history)?;
    }
    Ok(())
}
