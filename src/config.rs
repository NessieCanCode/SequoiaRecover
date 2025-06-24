use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use chrono::{DateTime, Local};
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
}

pub fn config_file_path() -> Result<PathBuf, Box<dyn Error>> {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"))?;
    Ok(PathBuf::from(home).join(CONFIG_PATH))
}

pub fn history_file_path() -> Result<PathBuf, Box<dyn Error>> {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"))?;
    Ok(PathBuf::from(home).join(HISTORY_PATH))
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
        salt: general_purpose::STANDARD.encode(&salt),
        nonce: general_purpose::STANDARD.encode(&nonce_bytes),
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

pub fn load_credentials(
    account_id: Option<String>,
    application_key: Option<String>,
) -> Result<(String, String), Box<dyn Error>> {
    match (account_id, application_key) {
        (Some(id), Some(key)) => Ok((id, key)),
        _ => {
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
            "{}\t{:?}\t{:?}",
            dt.format("%Y-%m-%d %H:%M:%S"),
            entry.mode,
            entry.backup
        );
    }
    Ok(())
}
