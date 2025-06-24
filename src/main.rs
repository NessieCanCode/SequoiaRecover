use backblaze_b2_client::client::B2Client;
use bzip2::write::BzEncoder;
use bzip2::Compression as BzCompression;
use clap::{Parser, Subcommand, ValueEnum};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
use rand::rngs::OsRng;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use rand::RngCore;
use base64::{engine::general_purpose, Engine as _};
use rpassword;
use serde::{Deserialize, Serialize};
use flate2::write::GzEncoder;
use flate2::Compression as GzCompression;
use num_cpus;
use serde_json;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::{Duration, UNIX_EPOCH};
use tar::Builder;
use tokio::fs::File as TokioFile;
use tokio::runtime::Runtime;
use walkdir::WalkDir;
use zstd::stream::write::Encoder as ZstdEncoder;

const CONFIG_PATH: &str = ".sequoiarecover/config.enc";

#[derive(Serialize, Deserialize)]
struct Config {
    account_id: String,
    application_key: String,
}

#[derive(Serialize, Deserialize)]
struct EncryptedConfig {
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Parser)]
#[command(
    name = "SequoiaRecover",
    version,
    about = "Backup tool for Linux command line."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Perform a backup of the specified directory
    Backup {
        /// Path to the source directory
        #[arg(long)]
        source: String,
        /// Output backup file path
        #[arg(long, default_value = "backup.tar")]
        output: String,
        /// Compression method
        #[arg(long, value_enum, default_value_t = CompressionType::Gzip)]
        compression: CompressionType,
        /// Backup mode: full or incremental
        #[arg(long, value_enum, default_value_t = BackupMode::Full)]
        mode: BackupMode,
        /// Destination cloud provider. Placeholder for now
        #[arg(long, default_value = "backblaze")]
        cloud: String,
        /// Bucket name in the cloud provider
        #[arg(long)]
        bucket: String,
        /// Backblaze account ID (can also come from B2_ACCOUNT_ID env var)
        #[arg(long, env = "B2_ACCOUNT_ID", hide_env_values = true)]
        account_id: Option<String>,
        /// Backblaze application key (can also come from B2_APPLICATION_KEY env var)
        #[arg(long, env = "B2_APPLICATION_KEY", hide_env_values = true)]
        application_key: Option<String>,
    },
    /// Schedule automated backups at a fixed interval (in seconds)
    Schedule {
        /// Path to the source directory
        #[arg(long)]
        source: String,
        /// Output backup file path
        #[arg(long, default_value = "backup.tar")]
        output: String,
        /// Compression method
        #[arg(long, value_enum, default_value_t = CompressionType::Gzip)]
        compression: CompressionType,
        /// Backup mode: full or incremental
        #[arg(long, value_enum, default_value_t = BackupMode::Full)]
        mode: BackupMode,
        /// Destination cloud provider. Placeholder for now
        #[arg(long, default_value = "backblaze")]
        cloud: String,
        /// Bucket name in the cloud provider
        #[arg(long)]
        bucket: String,
        /// Backblaze account ID (can also come from B2_ACCOUNT_ID env var)
        #[arg(long, env = "B2_ACCOUNT_ID", hide_env_values = true)]
        account_id: Option<String>,
        /// Backblaze application key (can also come from B2_APPLICATION_KEY env var)
        #[arg(long, env = "B2_APPLICATION_KEY", hide_env_values = true)]
        application_key: Option<String>,
        /// Interval in seconds between backups
        #[arg(long, default_value_t = 3600)]
        interval: u64,
        /// Maximum number of backups to run (0 for infinite)
        #[arg(long, default_value_t = 0)]
        max_runs: u64,
    },
    /// Initialize encrypted configuration
    Init,
}

#[derive(Clone, Copy, ValueEnum, Debug, PartialEq)]
enum CompressionType {
    /// No compression
    None,
    /// Use gzip compression
    Gzip,
    /// Use bzip2 compression
    Bzip2,
    /// Use zstd compression
    Zstd,
    /// Automatically select a compression method based on network speed
    Auto,
}

#[derive(Clone, Copy, ValueEnum, Debug)]
enum BackupMode {
    Full,
    Incremental,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Backup {
            source,
            output,
            compression,
            mode,
            cloud,
            bucket,
            account_id,
            application_key,
        } => {
            let actual_compression = if compression == CompressionType::Auto {
                let c = auto_select_compression();
                println!("Auto selected compression: {:?}", c);
                c
            } else {
                compression
            };
            println!(
                "Starting backup from {} to {} bucket {} using {:?}",
                source, cloud, bucket, actual_compression
            );
            if let Err(e) = run_backup(&source, &output, actual_compression, mode) {
                eprintln!("Backup failed: {}", e);
            } else {
                println!("Backup written to {}", output);
                if cloud == "backblaze" {
                    match load_credentials(account_id, application_key) {
                        Ok((id, key)) => {
                            if let Err(e) = upload_to_backblaze_blocking(&id, &key, &bucket, &output)
                            {
                                eprintln!("Upload failed: {}", e);
                            } else {
                                println!("Uploaded to Backblaze bucket {}", bucket);
                            }
                        }
                        Err(e) => eprintln!("{}", e),
                    }
                }
            }
        }
        Commands::Schedule {
            source,
            output,
            compression,
            cloud,
            bucket,
            account_id,
            application_key,
            interval,
            max_runs,
            mode,
        } => {
            let actual_compression = if compression == CompressionType::Auto {
                let c = auto_select_compression();
                println!("Auto selected compression: {:?}", c);
                c
            } else {
                compression
            };
            println!(
                "Scheduling backups every {} seconds from {} to {} bucket {} using {:?}",
                interval, source, cloud, bucket, actual_compression
            );
            let mut run_count = 0u64;
            loop {
                if max_runs > 0 && run_count >= max_runs {
                    break;
                }
                println!("Starting scheduled backup #{}", run_count + 1);
                if let Err(e) = run_backup(&source, &output, actual_compression, mode.clone()) {
                    eprintln!("Scheduled backup failed: {}", e);
                } else {
                    println!("Scheduled backup written to {}", output);
                    if cloud == "backblaze" {
                        match load_credentials(account_id.clone(), application_key.clone()) {
                            Ok((id, key)) => {
                                if let Err(e) =
                                    upload_to_backblaze_blocking(&id, &key, &bucket, &output)
                                {
                                    eprintln!("Upload failed: {}", e);
                                } else {
                                    println!("Uploaded to Backblaze bucket {}", bucket);
                                }
                            }
                            Err(e) => eprintln!("{}", e),
                        }
                    }
                }
                run_count += 1;
                sleep(Duration::from_secs(interval));
            }
        }
        Commands::Init => {
            match config_file_path() {
                Ok(path) => {
                    let account_id = rpassword::prompt_password("Backblaze Account ID: ").unwrap_or_default();
                    let application_key = rpassword::prompt_password("Backblaze Application Key: ").unwrap_or_default();
                    let password = rpassword::prompt_password("Encryption password: ").unwrap_or_default();
                    let confirm = rpassword::prompt_password("Confirm password: ").unwrap_or_default();
                    if password != confirm {
                        eprintln!("Passwords do not match");
                        return;
                    }
                    let cfg = Config { account_id, application_key };
                    match encrypt_config(&cfg, &password) {
                        Ok(enc) => {
                            if let Some(p) = path.parent() { let _ = std::fs::create_dir_all(p); }
                            if let Ok(f) = File::create(&path) {
                                if serde_json::to_writer_pretty(f, &enc).is_ok() {
                                    println!("Config written to {:?}", path);
                                } else {
                                    eprintln!("Failed to write config");
                                }
                            } else {
                                eprintln!("Could not create config file");
                            }
                        }
                        Err(e) => eprintln!("Failed to encrypt config: {}", e),
                    }
                }
                Err(e) => eprintln!("{}", e),
            }
        }
    }
}

fn run_backup(
    source: &str,
    output: &str,
    compression: CompressionType,
    mode: BackupMode,
) -> Result<(), Box<dyn Error>> {
    let path = Path::new(source);
    let meta_path = format!("{}.meta", output);
    let previous: HashMap<String, u64> = if let Ok(f) = File::open(&meta_path) {
        serde_json::from_reader(f)?
    } else {
        HashMap::new()
    };
    let mut current: HashMap<String, u64> = HashMap::new();

    let file = File::create(output)?;

    let actual = if compression == CompressionType::Auto {
        auto_select_compression()
    } else {
        compression
    };

    match actual {
        CompressionType::Gzip => {
            let enc = GzEncoder::new(file, GzCompression::default());
            let mut tar = Builder::new(enc);
            add_files(&mut tar, path, mode, &previous, &mut current)?;
            let enc = tar.into_inner()?;
            enc.finish()?;
        }
        CompressionType::Bzip2 => {
            let enc = BzEncoder::new(file, BzCompression::default());
            let mut tar = Builder::new(enc);
            add_files(&mut tar, path, mode, &previous, &mut current)?;
            let enc = tar.into_inner()?;
            enc.finish()?;
        }
        CompressionType::Zstd => {
            let mut enc = ZstdEncoder::new(file, 0)?;
            enc.multithread(num_cpus::get() as u32)?;
            let mut tar = Builder::new(enc);
            add_files(&mut tar, path, mode, &previous, &mut current)?;
            let enc = tar.into_inner()?;
            enc.finish()?;
        }
        CompressionType::None => {
            let mut tar = Builder::new(file);
            add_files(&mut tar, path, mode, &previous, &mut current)?;
            tar.finish()?;
        }
        CompressionType::Auto => unreachable!(),
    }

    let meta_file = File::create(&meta_path)?;
    serde_json::to_writer_pretty(meta_file, &current)?;
    Ok(())
}

fn add_files<T: std::io::Write>(
    tar: &mut Builder<T>,
    root: &Path,
    mode: BackupMode,
    previous: &HashMap<String, u64>,
    current: &mut HashMap<String, u64>,
) -> Result<(), Box<dyn Error>> {
    for entry in WalkDir::new(root) {
        let entry = entry?;
        if entry.depth() == 0 && entry.file_type().is_dir() {
            continue;
        }
        let path = entry.path();
        if entry.file_type().is_file() {
            let rel = path.strip_prefix(root)?;
            let rel_str = rel.to_string_lossy().to_string();
            let mtime = entry
                .metadata()?
                .modified()?
                .duration_since(UNIX_EPOCH)?
                .as_secs();
            current.insert(rel_str.clone(), mtime);
            let include = match mode {
                BackupMode::Full => true,
                BackupMode::Incremental => previous.get(&rel_str).map_or(true, |old| *old < mtime),
            };
            if include {
                tar.append_path_with_name(path, rel)?;
            }
        }
    }
    Ok(())
}

async fn upload_to_backblaze(
    account_id: &str,
    application_key: &str,
    bucket: &str,
    file_path: &str,
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
        .create_upload(file, name, bucket.to_string(), None, metadata.len(), None)
        .await;
    upload.start().await?;
    Ok(())
}

fn upload_to_backblaze_blocking(
    account_id: &str,
    application_key: &str,
    bucket: &str,
    file_path: &str,
) -> Result<(), Box<dyn Error>> {
    let rt = Runtime::new()?;
    rt.block_on(upload_to_backblaze(
        account_id,
        application_key,
        bucket,
        file_path,
    ))
}

#[cfg(target_os = "linux")]
fn detect_link_speed() -> Option<u64> {
    use std::fs;
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy() == "lo" {
                continue;
            }
            let speed_path = entry.path().join("speed");
            if let Ok(speed_str) = fs::read_to_string(speed_path) {
                if let Ok(speed) = speed_str.trim().parse::<u64>() {
                    if speed > 0 {
                        return Some(speed);
                    }
                }
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn detect_link_speed() -> Option<u64> {
    None
}

fn auto_select_compression() -> CompressionType {
    match detect_link_speed().unwrap_or(0) {
        s if s >= 1000 => CompressionType::None,
        s if s >= 100 => CompressionType::Gzip,
        _ => CompressionType::Zstd,
    }
}

fn config_file_path() -> Result<PathBuf, Box<dyn Error>> {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"))?;
    Ok(PathBuf::from(home).join(CONFIG_PATH))
}

fn encrypt_config(config: &Config, password: &str) -> Result<EncryptedConfig, Box<dyn Error>> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 100_000, &mut key);
    let cipher = ChaCha20Poly1305::new(&key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = serde_json::to_vec(config)?;
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;
    Ok(EncryptedConfig {
        salt: general_purpose::STANDARD.encode(&salt),
        nonce: general_purpose::STANDARD.encode(&nonce_bytes),
        ciphertext: general_purpose::STANDARD.encode(&ciphertext),
    })
}

fn decrypt_config(enc: &EncryptedConfig, password: &str) -> Result<Config, Box<dyn Error>> {
    let salt = general_purpose::STANDARD.decode(&enc.salt)?;
    let nonce_bytes = general_purpose::STANDARD.decode(&enc.nonce)?;
    let ciphertext = general_purpose::STANDARD.decode(&enc.ciphertext)?;
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 100_000, &mut key);
    let cipher = ChaCha20Poly1305::new(&key.into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
    Ok(serde_json::from_slice(&plaintext)?)
}

fn load_credentials(
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
