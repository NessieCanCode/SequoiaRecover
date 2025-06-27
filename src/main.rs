use sequoiarecover::backup::{
    auto_select_compression, decrypt_file, encrypt_file, ensure_extension, list_backup,
    restore_backup, run_backup, BackupMode, CompressionType,
};
use sequoiarecover::compliance;
use sequoiarecover::config::{
    config_file_path, derive_archive_key, encrypt_config, get_or_create_archive_salt,
    load_archive_salt, load_credentials, read_history, salt_file_path, show_history,
    store_credentials_keyring, update_backup_providers, Config,
};
use sequoiarecover::remote::{
    download_from_azure_blocking, download_from_backblaze_blocking, download_from_s3_blocking,
    list_azure_backup_blocking, list_remote_backup_blocking, list_s3_backup_blocking,
    show_azure_history_blocking, show_remote_history_blocking, show_s3_history_blocking,
    upload_to_azure_blocking, upload_to_backblaze_blocking, upload_to_s3_blocking,
};
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
    },
    /// Generate encryption key used for archive encryption
    Keygen,
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
    match cli.command {
        Commands::Backup {
            source,
            output,
            compression,
            mode,
            clouds,
            bucket,
            account_id,
            application_key,
            keyring,
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
                if let Ok((id, key)) =
                    load_credentials(account_id.clone(), application_key.clone(), keyring)
                {
                    match get_or_create_archive_salt() {
                        Ok(salt) => {
                            let k = derive_archive_key(&id, &key, &salt);
                            if let Err(e) = encrypt_file(&output_path, &enc_path, &k) {
                                eprintln!("Encryption failed: {}", e);
                                return Err(e);
                            }
                            let _ = std::fs::remove_file(&output_path);
                        }
                        Err(e) => eprintln!("{}", e),
                    }
                }
                let target = &enc_path;
                let mut uploaded = Vec::new();
                for cloud in &clouds {
                    if let Some(p) = sequoiarecover::remote::get_provider(cloud) {
                        if let Err(e) = p.upload_blocking(&bucket, target) {
                            eprintln!("Upload to {} failed: {}", cloud, e);
                        } else {
                            println!("Uploaded to {} bucket {}", cloud, bucket);
                            uploaded.push(cloud.clone());
                        }
                        continue;
                    }
                    if cloud == "backblaze" {
                        match load_credentials(account_id.clone(), application_key.clone(), keyring)
                        {
                            Ok((id, key)) => {
                                if let Err(e) =
                                    upload_to_backblaze_blocking(&id, &key, &bucket, target)
                                {
                                    eprintln!("Upload to backblaze failed: {}", e);
                                } else {
                                    println!("Uploaded to Backblaze bucket {}", bucket);
                                    uploaded.push(cloud.clone());
                                }
                            }
                            Err(e) => eprintln!("{}", e),
                        }
                    } else if cloud == "aws" {
                        if let (Ok(ak), Ok(sk), Ok(region)) = (
                            std::env::var("AWS_ACCESS_KEY_ID"),
                            std::env::var("AWS_SECRET_ACCESS_KEY"),
                            std::env::var("AWS_REGION"),
                        ) {
                            if let Err(e) =
                                upload_to_s3_blocking(&ak, &sk, &region, &bucket, target)
                            {
                                eprintln!("Upload to aws failed: {}", e);
                            } else {
                                println!("Uploaded to S3 bucket {}", bucket);
                                uploaded.push(cloud.clone());
                            }
                        } else {
                            eprintln!("Missing AWS credentials");
                        }
                    } else if cloud == "azure" {
                        if let (Ok(acct), Ok(key)) = (
                            std::env::var("AZURE_STORAGE_ACCOUNT"),
                            std::env::var("AZURE_STORAGE_KEY"),
                        ) {
                            if let Err(e) = upload_to_azure_blocking(&acct, &key, &bucket, target) {
                                eprintln!("Upload to azure failed: {}", e);
                            } else {
                                println!("Uploaded to Azure container {}", bucket);
                                uploaded.push(cloud.clone());
                            }
                        } else {
                            eprintln!("Missing Azure credentials");
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
            account_id,
            application_key,
            keyring,
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
                    let mut uploaded = Vec::new();
                    for cloud in &clouds {
                        if let Some(p) = sequoiarecover::remote::get_provider(cloud) {
                            if let Err(e) = p.upload_blocking(&bucket, &output_path) {
                                eprintln!("Upload to {} failed: {}", cloud, e);
                            } else {
                                println!("Uploaded to {} bucket {}", cloud, bucket);
                                uploaded.push(cloud.clone());
                            }
                            continue;
                        }
                        if cloud == "backblaze" {
                            match load_credentials(
                                account_id.clone(),
                                application_key.clone(),
                                keyring,
                            ) {
                                Ok((id, key)) => {
                                    if let Err(e) = upload_to_backblaze_blocking(
                                        &id,
                                        &key,
                                        &bucket,
                                        &output_path,
                                    ) {
                                        eprintln!("Upload to backblaze failed: {}", e);
                                    } else {
                                        println!("Uploaded to Backblaze bucket {}", bucket);
                                        uploaded.push(cloud.clone());
                                    }
                                }
                                Err(e) => eprintln!("{}", e),
                            }
                        } else if cloud == "aws" {
                            if let (Ok(ak), Ok(sk), Ok(region)) = (
                                std::env::var("AWS_ACCESS_KEY_ID"),
                                std::env::var("AWS_SECRET_ACCESS_KEY"),
                                std::env::var("AWS_REGION"),
                            ) {
                                if let Err(e) =
                                    upload_to_s3_blocking(&ak, &sk, &region, &bucket, &output_path)
                                {
                                    eprintln!("Upload to aws failed: {}", e);
                                } else {
                                    println!("Uploaded to S3 bucket {}", bucket);
                                    uploaded.push(cloud.clone());
                                }
                            } else {
                                eprintln!("Missing AWS credentials");
                            }
                        } else if cloud == "azure" {
                            if let (Ok(acct), Ok(key)) = (
                                std::env::var("AZURE_STORAGE_ACCOUNT"),
                                std::env::var("AZURE_STORAGE_KEY"),
                            ) {
                                if let Err(e) =
                                    upload_to_azure_blocking(&acct, &key, &bucket, &output_path)
                                {
                                    eprintln!("Upload to azure failed: {}", e);
                                } else {
                                    println!("Uploaded to Azure container {}", bucket);
                                    uploaded.push(cloud.clone());
                                }
                            } else {
                                eprintln!("Missing Azure credentials");
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
            account_id,
            application_key,
            keyring,
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
                } else if cloud == "backblaze" {
                    match load_credentials(account_id, application_key, keyring) {
                        Ok((id, key)) => {
                            if let Err(e) = show_remote_history_blocking(&id, &key, &b, retention) {
                                eprintln!("{}", e);
                            }
                        }
                        Err(e) => eprintln!("{}", e),
                    }
                } else if cloud == "aws" {
                    if let (Ok(ak), Ok(sk), Ok(region)) = (
                        std::env::var("AWS_ACCESS_KEY_ID"),
                        std::env::var("AWS_SECRET_ACCESS_KEY"),
                        std::env::var("AWS_REGION"),
                    ) {
                        if let Err(e) = show_s3_history_blocking(&ak, &sk, &region, &b, retention) {
                            eprintln!("{}", e);
                        }
                    } else {
                        eprintln!("Missing AWS credentials");
                    }
                } else if cloud == "azure" {
                    if let (Ok(acct), Ok(key)) = (
                        std::env::var("AZURE_STORAGE_ACCOUNT"),
                        std::env::var("AZURE_STORAGE_KEY"),
                    ) {
                        if let Err(e) = show_azure_history_blocking(&acct, &key, &b, retention) {
                            eprintln!("{}", e);
                        }
                    } else {
                        eprintln!("Missing Azure credentials");
                    }
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
            account_id,
            application_key,
            keyring,
        } => {
            let result = if let Some(b) = bucket {
                if let Some(p) = sequoiarecover::remote::get_provider(&cloud) {
                    p.list_backup_blocking(&b, &backup, compression)
                } else if cloud == "backblaze" {
                    match load_credentials(account_id, application_key, keyring) {
                        Ok((id, key)) => {
                            list_remote_backup_blocking(&id, &key, &b, &backup, compression)
                        }
                        Err(e) => Err(e),
                    }
                } else if cloud == "aws" {
                    if let (Ok(ak), Ok(sk), Ok(region)) = (
                        std::env::var("AWS_ACCESS_KEY_ID"),
                        std::env::var("AWS_SECRET_ACCESS_KEY"),
                        std::env::var("AWS_REGION"),
                    ) {
                        list_s3_backup_blocking(&ak, &sk, &region, &b, &backup, compression)
                    } else {
                        Err("Missing AWS credentials".into())
                    }
                } else if cloud == "azure" {
                    if let (Ok(acct), Ok(key)) = (
                        std::env::var("AZURE_STORAGE_ACCOUNT"),
                        std::env::var("AZURE_STORAGE_KEY"),
                    ) {
                        list_azure_backup_blocking(&acct, &key, &b, &backup, compression)
                    } else {
                        Err("Missing Azure credentials".into())
                    }
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
            account_id,
            application_key,
            keyring,
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
                        for prov in entry.providers {
                            if let Some(p) = sequoiarecover::remote::get_provider(&prov) {
                                match p.download_blocking(&b, &remote, &tmp_enc) {
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
                    p.download_blocking(&b, &backup, &tmp_enc)
                } else if cloud == "backblaze" {
                    match load_credentials(account_id.clone(), application_key.clone(), keyring) {
                        Ok((id, key)) => {
                            download_from_backblaze_blocking(&id, &key, &b, &backup, &tmp_enc)
                        }
                        Err(e) => Err(e),
                    }
                } else if cloud == "aws" {
                    if let (Ok(ak), Ok(sk), Ok(region)) = (
                        std::env::var("AWS_ACCESS_KEY_ID"),
                        std::env::var("AWS_SECRET_ACCESS_KEY"),
                        std::env::var("AWS_REGION"),
                    ) {
                        download_from_s3_blocking(&ak, &sk, &region, &b, &backup, &tmp_enc)
                    } else {
                        Err("Missing AWS credentials".into())
                    }
                } else if cloud == "azure" {
                    if let (Ok(acct), Ok(key)) = (
                        std::env::var("AZURE_STORAGE_ACCOUNT"),
                        std::env::var("AZURE_STORAGE_KEY"),
                    ) {
                        download_from_azure_blocking(&acct, &key, &b, &backup, &tmp_enc)
                    } else {
                        Err("Missing Azure credentials".into())
                    }
                } else {
                    Err("Unsupported cloud".into())
                };
                match download_res {
                    Ok(()) => {
                        let salt = match load_archive_salt() {
                            Ok(s) => s,
                            Err(e) => return Err(e),
                        };
                        let (id, key) = match load_credentials(account_id, application_key, keyring)
                        {
                            Ok(creds) => creds,
                            Err(e) => return Err(e),
                        };
                        let k = derive_archive_key(&id, &key, &salt);
                        let tmp_plain = tmp_enc.with_extension("tar");
                        let dec_res = decrypt_file(
                            tmp_enc.to_str().unwrap(),
                            tmp_plain.to_str().unwrap(),
                            &k,
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
                        match p.download_blocking(&bucket, &remote_name, &tmp) {
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
        Commands::Init { keyring } => match config_file_path() {
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
            }
            Err(e) => eprintln!("{}", e),
        },
        Commands::Keygen => match get_or_create_archive_salt() {
            Ok(_) => println!("Encryption key generated"),
            Err(e) => eprintln!("{}", e),
        },
        Commands::Keyrotate => match get_or_create_archive_salt() {
            Ok(_) => {
                let path = salt_file_path().unwrap();
                let mut salt = [0u8; 16];
                OsRng.fill_bytes(&mut salt);
                if let Err(e) = std::fs::write(path, &salt) {
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
