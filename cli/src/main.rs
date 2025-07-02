use sequoiarecover::backup::{
    auto_select_compression, decrypt_file, encrypt_file, ensure_extension, list_backup,
    restore_backup, run_backup, BackupMode, CompressionType,
};
use sequoiarecover::compliance;
use sequoiarecover::config::{
    config_file_path, encrypt_config, get_or_create_local_key, load_local_key, local_key_file_path,
    read_history, show_history, store_credentials_keyring, update_backup_providers, Config,
};

#[cfg(feature = "hardware-auth")]
use sequoiarecover::hardware_key;
use tracing_subscriber::EnvFilter;

use clap::{CommandFactory, Parser, Subcommand};
use clap_mangen::Man;
use rand::rngs::OsRng;
use rand::RngCore;
use std::thread::sleep;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "SequoiaRecover",
    version,
    about = "Backup tool for Linux command line."
)]
struct Cli {
    /// Limit upload bandwidth in Mbps
    #[arg(long)]
    max_upload_mbps: Option<u64>,
    /// Limit download bandwidth in Mbps
    #[arg(long)]
    max_download_mbps: Option<u64>,
    /// Resume interrupted transfers
    #[arg(long, default_value_t = false)]
    resume: bool,
    /// Chunk size in bytes for transfers
    #[arg(long)]
    chunk_size: Option<usize>,
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
        /// Destination cloud providers (comma separated or repeated)
        #[arg(long = "cloud", value_delimiter = ',', default_value = "backblaze")]
        clouds: Vec<String>,
        /// Bucket name in the cloud provider
        #[arg(long)]
        bucket: String,
        /// Backblaze account ID (can also come from B2_ACCOUNT_ID env var)
        #[arg(long, env = "B2_ACCOUNT_ID", hide_env_values = true)]
        account_id: Option<String>,
        /// Backblaze application key (can also come from B2_APPLICATION_KEY env var)
        #[arg(long, env = "B2_APPLICATION_KEY", hide_env_values = true)]
        application_key: Option<String>,
        /// Store credentials in OS keychain
        #[arg(long, default_value_t = false)]
        keyring: bool,
        /// Override detected link speed in Mbps when using auto compression
        #[arg(long)]
        compression_threshold: Option<u64>,
        /// Abort upload if suspicious files are detected
        #[arg(long, default_value_t = false)]
        reject_suspicious: bool,
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
        /// Destination cloud providers (comma separated or repeated)
        #[arg(long = "cloud", value_delimiter = ',', default_value = "backblaze")]
        clouds: Vec<String>,
        /// Bucket name in the cloud provider
        #[arg(long)]
        bucket: String,
        /// Backblaze account ID (can also come from B2_ACCOUNT_ID env var)
        #[arg(long, env = "B2_ACCOUNT_ID", hide_env_values = true)]
        account_id: Option<String>,
        /// Backblaze application key (can also come from B2_APPLICATION_KEY env var)
        #[arg(long, env = "B2_APPLICATION_KEY", hide_env_values = true)]
        application_key: Option<String>,
        /// Retrieve credentials from the keychain
        #[arg(long, default_value_t = false)]
        keyring: bool,
        /// Override detected link speed in Mbps when using auto compression
        #[arg(long)]
        compression_threshold: Option<u64>,
        /// Abort upload if suspicious files are detected
        #[arg(long, default_value_t = false)]
        reject_suspicious: bool,
        /// Interval in seconds between backups
        #[arg(long, default_value_t = 3600)]
        interval: u64,
        /// Maximum number of backups to run (0 for infinite)
        #[arg(long, default_value_t = 0)]
        max_runs: u64,
    },
    /// Show previous backup history
    History {
        #[arg(long)]
        bucket: Option<String>,
        #[arg(long, default_value = "backblaze")]
        cloud: String,
        #[arg(long, env = "B2_ACCOUNT_ID", hide_env_values = true)]
        account_id: Option<String>,
        #[arg(long, env = "B2_APPLICATION_KEY", hide_env_values = true)]
        application_key: Option<String>,
        /// Retrieve credentials from keychain
        #[arg(long, default_value_t = false)]
        keyring: bool,
        /// Delete backups older than this many days
        #[arg(long)]
        retain_days: Option<u64>,
        /// Delete backups older than this many weeks
        #[arg(long)]
        retain_weeks: Option<u64>,
    },
    /// List files inside a backup without extracting
    List {
        #[arg(long)]
        backup: String,
        #[arg(long)]
        compression: Option<CompressionType>,
        #[arg(long)]
        bucket: Option<String>,
        #[arg(long, default_value = "backblaze")]
        cloud: String,
        #[arg(long, env = "B2_ACCOUNT_ID", hide_env_values = true)]
        account_id: Option<String>,
        #[arg(long, env = "B2_APPLICATION_KEY", hide_env_values = true)]
        application_key: Option<String>,
        /// Retrieve credentials from keychain
        #[arg(long, default_value_t = false)]
        keyring: bool,
    },
    /// Restore files from a backup archive
    Restore {
        #[arg(long)]
        backup: String,
        #[arg(long)]
        destination: String,
        #[arg(long)]
        compression: Option<CompressionType>,
        #[arg(long)]
        bucket: Option<String>,
        #[arg(long, default_value = "backblaze")]
        cloud: String,
        #[arg(long, env = "B2_ACCOUNT_ID", hide_env_values = true)]
        account_id: Option<String>,
        #[arg(long, env = "B2_APPLICATION_KEY", hide_env_values = true)]
        application_key: Option<String>,
        /// Retrieve credentials from keychain
        #[arg(long, default_value_t = false)]
        keyring: bool,
    },
    /// Verify replication status of backups
    Verify {
        #[arg(long)]
        backup: Option<String>,
        #[arg(long)]
        bucket: String,
    },
    /// Compliance reporting commands
    Compliance {
        #[command(subcommand)]
        command: ComplianceCommands,
    },
    /// Initialize encrypted configuration
    Init {
        /// Store credentials in the OS keychain
        #[arg(long, default_value_t = false)]
        keyring: bool,
        #[cfg(feature = "hardware-auth")]
        /// Use a connected YubiKey/HSM for the archive key
        #[arg(long, default_value_t = false)]
        hardware_key: bool,
    },
    /// Generate encryption key used for archive encryption
    Keygen {
        #[cfg(feature = "hardware-auth")]
        /// Store key on a YubiKey/HSM
        #[arg(long, default_value_t = false)]
        hardware_key: bool,
    },
    /// Rotate to a new encryption key
    Keyrotate,
    /// Generate the SequoiaRecover man page
    Manpage,
}

#[derive(Subcommand)]
enum ComplianceCommands {
    /// Produce compliance reports
    Report {
        /// Directory to write reports
        #[arg(long, default_value = "./reports")]
        output: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    sequoiarecover::throttle::set_limits(cli.max_upload_mbps, cli.max_download_mbps);
    let _ = sequoiarecover::remote::load_providers_from_config();
    let _ = sequoiarecover::remote::load_providers_from_env();
    match cli.command {
        Commands::Backup {
            source,
            output,
            compression,
            mode,
            clouds,
            bucket,
            account_id: _,
            application_key: _,
            keyring: _,
            compression_threshold,
            reject_suspicious,
        } => {
            let actual_compression = if compression == CompressionType::Auto {
                let c = auto_select_compression(compression_threshold);
                println!("Auto selected compression: {:?}", c);
                c
            } else {
                compression
            };
            let output_path = ensure_extension(&output, actual_compression);
            println!(
                "Starting backup from {} using {:?}",
                source, actual_compression
            );
            if let Err(e) = run_backup(&source, &output_path, actual_compression, mode) {
                eprintln!("Backup failed: {}", e);
            } else {
                println!("Backup written to {}", output_path);
                let suspicious = match sequoiarecover::monitor::scan_for_ransomware(&source) {
                    Ok(Some(msg)) => {
                        println!("Warning: {}", msg);
                        sequoiarecover::monitor::send_alert(&msg);
                        true
                    }
                    Ok(None) => false,
                    Err(e) => {
                        eprintln!("Scan failed: {}", e);
                        false
                    }
                };
                if suspicious && reject_suspicious {
                    println!("Suspicious content detected; upload aborted");
                    return Ok(());
                }
                let enc_path = format!("{}.enc", output_path);
                match get_or_create_local_key() {
                    Ok(k) => {
                        if let Err(e) = encrypt_file(&output_path, &enc_path, &k) {
                            eprintln!("Encryption failed: {}", e);
                            return Err(e);
                        }
                        let _ = std::fs::remove_file(&output_path);
                    }
                    Err(e) => {
                        eprintln!("{}", e);
                    }
                }
                let target = &enc_path;
                let opts = sequoiarecover::transfer::TransferOpts {
                    chunk_size: cli.chunk_size.unwrap_or(4 * 1024 * 1024),
                    resume: cli.resume,
                };
                let mut uploaded = Vec::new();
                for cloud in &clouds {
                    if let Some(p) = sequoiarecover::remote::get_provider(cloud) {
                        if let Err(e) =
                            sequoiarecover::transfer::upload_file(&*p, &bucket, target, &opts)
                        {
                            eprintln!("Upload to {} failed: {}", cloud, e);
                        } else {
                            println!("Uploaded to {} bucket {}", cloud, bucket);
                            uploaded.push(cloud.clone());
                        }
                    } else {
                        eprintln!("Unsupported cloud provider: {}", cloud);
                    }
                }
                let _ = update_backup_providers(&output_path, &uploaded);
            }
        }
        Commands::Schedule {
            source,
            output,
            compression,
            clouds,
            bucket,
            account_id: _,
            application_key: _,
            keyring: _,
            compression_threshold,
            reject_suspicious,
            interval,
            max_runs,
            mode,
        } => {
            let actual_compression = if compression == CompressionType::Auto {
                let c = auto_select_compression(compression_threshold);
                println!("Auto selected compression: {:?}", c);
                c
            } else {
                compression
            };
            let output_path = ensure_extension(&output, actual_compression);
            println!(
                "Scheduling backups every {} seconds from {} using {:?}",
                interval, source, actual_compression
            );
            let mut run_count = 0u64;
            loop {
                if max_runs > 0 && run_count >= max_runs {
                    break;
                }
                println!("Starting scheduled backup #{}", run_count + 1);
                if let Err(e) = run_backup(&source, &output_path, actual_compression, mode) {
                    eprintln!("Scheduled backup failed: {}", e);
                } else {
                    println!("Scheduled backup written to {}", output_path);
                    let suspicious = match sequoiarecover::monitor::scan_for_ransomware(&source) {
                        Ok(Some(msg)) => {
                            println!("Warning: {}", msg);
                            sequoiarecover::monitor::send_alert(&msg);
                            true
                        }
                        Ok(None) => false,
                        Err(e) => {
                            eprintln!("Scan failed: {}", e);
                            false
                        }
                    };
                    if suspicious && reject_suspicious {
                        println!("Suspicious content detected; upload aborted");
                        run_count += 1;
                        sleep(Duration::from_secs(interval));
                        continue;
                    }
                    let opts = sequoiarecover::transfer::TransferOpts {
                        chunk_size: cli.chunk_size.unwrap_or(4 * 1024 * 1024),
                        resume: cli.resume,
                    };
                    let mut uploaded = Vec::new();
                    for cloud in &clouds {
                        if let Some(p) = sequoiarecover::remote::get_provider(cloud) {
                            if let Err(e) = sequoiarecover::transfer::upload_file(
                                &*p,
                                &bucket,
                                &output_path,
                                &opts,
                            ) {
                                eprintln!("Upload to {} failed: {}", cloud, e);
                            } else {
                                println!("Uploaded to {} bucket {}", cloud, bucket);
                                uploaded.push(cloud.clone());
                            }
                        } else {
                            eprintln!("Unsupported cloud provider: {}", cloud);
                        }
                    }
                    let _ = update_backup_providers(&output_path, &uploaded);
                }
                run_count += 1;
                sleep(Duration::from_secs(interval));
            }
        }
        Commands::History {
            bucket,
            cloud,
            account_id: _,
            application_key: _,
            keyring: _,
            retain_days,
            retain_weeks,
        } => {
            let retention = retain_days
                .map(|d| Duration::from_secs(d * 24 * 3600))
                .or_else(|| retain_weeks.map(|w| Duration::from_secs(w * 7 * 24 * 3600)));
            if let Some(b) = bucket {
                if let Some(p) = sequoiarecover::remote::get_provider(&cloud) {
                    if let Err(e) = p.show_history_blocking(&b, retention) {
                        eprintln!("{}", e);
                    }
                } else {
                    eprintln!("Unknown cloud provider: {}", cloud);
                }
            } else if let Err(e) = show_history() {
                eprintln!("{}", e);
            }
        }
        Commands::List {
            backup,
            compression,
            bucket,
            cloud,
            account_id: _,
            application_key: _,
            keyring: _,
        } => {
            let result = if let Some(b) = bucket {
                if let Some(p) = sequoiarecover::remote::get_provider(&cloud) {
                    p.list_backup_blocking(&b, &backup, compression)
                } else {
                    Err("Unsupported cloud".into())
                }
            } else {
                list_backup(&backup, compression)
            };
            if let Err(e) = result {
                eprintln!("{}", e);
            }
        }
        Commands::Restore {
            backup,
            destination,
            compression,
            bucket,
            cloud,
            account_id: _,
            application_key: _,
            keyring: _,
        } => {
            let result = if let Some(b) = bucket {
                let tmp_enc = std::env::temp_dir().join("backup.enc");
                let download_res: Result<(), Box<dyn std::error::Error>> = if cloud == "auto" {
                    let history = read_history().unwrap_or_default();
                    if let Some(entry) = history
                        .into_iter()
                        .find(|h| h.backup == backup || format!("{}.enc", h.backup) == backup)
                    {
                        let remote = if backup.ends_with(".enc") {
                            backup.clone()
                        } else {
                            format!("{}.enc", entry.backup)
                        };
                        let mut last_err: Option<Box<dyn std::error::Error>> = None;
                        let opts = sequoiarecover::transfer::TransferOpts {
                            chunk_size: cli.chunk_size.unwrap_or(4 * 1024 * 1024),
                            resume: cli.resume,
                        };
                        for prov in entry.providers {
                            if let Some(p) = sequoiarecover::remote::get_provider(&prov) {
                                match sequoiarecover::transfer::download_file(
                                    &*p, &b, &remote, &tmp_enc, &opts,
                                ) {
                                    Ok(_) => {
                                        last_err = None;
                                        break;
                                    }
                                    Err(e) => last_err = Some(e),
                                }
                            }
                        }
                        last_err.map_or(Ok(()), Err)
                    } else {
                        Err("History entry not found".into())
                    }
                } else if let Some(p) = sequoiarecover::remote::get_provider(&cloud) {
                    let opts = sequoiarecover::transfer::TransferOpts {
                        chunk_size: cli.chunk_size.unwrap_or(4 * 1024 * 1024),
                        resume: cli.resume,
                    };
                    sequoiarecover::transfer::download_file(&*p, &b, &backup, &tmp_enc, &opts)
                } else {
                    Err("Unsupported cloud".into())
                };
                match download_res {
                    Ok(()) => {
                        let key = match load_local_key() {
                            Ok(k) => k,
                            Err(e) => return Err(e),
                        };
                        let tmp_plain = tmp_enc.with_extension("tar");
                        let dec_res = decrypt_file(
                            tmp_enc.to_str().unwrap(),
                            tmp_plain.to_str().unwrap(),
                            &key,
                        );
                        let res = if dec_res.is_ok() {
                            restore_backup(tmp_plain.to_str().unwrap(), &destination, compression)
                        } else {
                            Err("Decryption failed".into())
                        };
                        let _ = std::fs::remove_file(&tmp_enc);
                        let _ = std::fs::remove_file(&tmp_plain);
                        res
                    }
                    Err(e) => Err(e),
                }
            } else {
                restore_backup(&backup, &destination, compression)
            };
            if let Err(e) = result {
                eprintln!("{}", e);
            }
        }
        Commands::Verify { backup, bucket } => {
            let history = match read_history() {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("{}", e);
                    Vec::new()
                }
            };
            let entries: Vec<_> = match backup {
                Some(b) => history.into_iter().filter(|h| h.backup == b).collect(),
                None => history,
            };
            for entry in entries {
                let remote_name = format!("{}.enc", entry.backup);
                for provider in &entry.providers {
                    if let Some(p) = sequoiarecover::remote::get_provider(provider) {
                        let tmp = std::env::temp_dir().join("verify.tmp");
                        let opts = sequoiarecover::transfer::TransferOpts {
                            chunk_size: cli.chunk_size.unwrap_or(4 * 1024 * 1024),
                            resume: cli.resume,
                        };
                        match sequoiarecover::transfer::download_file(
                            &*p,
                            &bucket,
                            &remote_name,
                            &tmp,
                            &opts,
                        ) {
                            Ok(_) => {
                                let _ = std::fs::remove_file(&tmp);
                                println!("{} present on {}", remote_name, provider);
                            }
                            Err(e) => println!("{} missing on {}: {}", remote_name, provider, e),
                        }
                    }
                }
            }
        }
        Commands::Compliance { command } => match command {
            ComplianceCommands::Report { output } => {
                if let Err(e) = compliance::generate_reports(&output) {
                    eprintln!("{}", e);
                }
            }
        },
        Commands::Init {
            keyring,
            #[cfg(feature = "hardware-auth")]
            hardware_key,
        } => match config_file_path() {
            Ok(path) => {
                let account_id =
                    rpassword::prompt_password("Backblaze Account ID: ").unwrap_or_default();
                let application_key =
                    rpassword::prompt_password("Backblaze Application Key: ").unwrap_or_default();
                if keyring {
                    match store_credentials_keyring(&account_id, &application_key) {
                        Ok(_) => println!("Credentials stored in keyring"),
                        Err(e) => eprintln!("Failed to store in keyring: {}", e),
                    }
                } else {
                    let password =
                        rpassword::prompt_password("Encryption password: ").unwrap_or_default();
                    let confirm =
                        rpassword::prompt_password("Confirm password: ").unwrap_or_default();
                    if password != confirm {
                        eprintln!("Passwords do not match");
                        return Ok(());
                    }
                    let cfg = Config {
                        account_id,
                        application_key,
                    };
                    match encrypt_config(&cfg, &password) {
                        Ok(enc) => {
                            if let Some(p) = path.parent() {
                                let _ = std::fs::create_dir_all(p);
                            }
                            if let Ok(f) = std::fs::File::create(&path) {
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
                #[cfg(feature = "hardware-auth")]
                if hardware_key {
                    match hardware_key::get_or_create() {
                        Ok(_) => println!("Hardware encryption key ready"),
                        Err(e) => eprintln!("Hardware key error: {}", e),
                    }
                }
            }
            Err(e) => eprintln!("{}", e),
        },
        Commands::Keygen {
            #[cfg(feature = "hardware-auth")]
            hardware_key,
        } => {
            #[cfg(feature = "hardware-auth")]
            if hardware_key {
                match hardware_key::get_or_create() {
                    Ok(_) => println!("Hardware encryption key generated"),
                    Err(e) => eprintln!("{}", e),
                }
                return Ok(());
            }
            match get_or_create_local_key() {
                Ok(_) => println!("Encryption key generated"),
                Err(e) => eprintln!("{}", e),
            }
        }
        Commands::Keyrotate => match local_key_file_path() {
            Ok(path) => {
                if let Some(p) = path.parent() {
                    let _ = std::fs::create_dir_all(p);
                }
                let mut key = [0u8; 32];
                OsRng.fill_bytes(&mut key);
                if let Err(e) = std::fs::write(&path, &key) {
                    eprintln!("Failed to rotate key: {}", e);
                } else {
                    println!("Encryption key rotated");
                }
            }
            Err(e) => eprintln!("{}", e),
        },
        Commands::Manpage => {
            let cmd = Cli::command();
            let man = Man::new(cmd);
            if let Err(e) = man.render(&mut std::io::stdout()) {
                eprintln!("Failed to generate man page: {}", e);
            }
        }
    }
    Ok(())
}
