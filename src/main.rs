use sequoiarecover::backup::{
    auto_select_compression, list_backup, restore_backup, run_backup, BackupMode, CompressionType,
};
use sequoiarecover::config::{
    config_file_path, encrypt_config, load_credentials, show_history,
    store_credentials_keyring, Config,
};
use sequoiarecover::remote::{
    list_remote_backup_blocking, restore_remote_backup_blocking, show_remote_history_blocking,
    upload_to_backblaze_blocking, upload_to_s3_blocking,
    show_s3_history_blocking, list_s3_backup_blocking, restore_s3_backup_blocking,
    upload_to_azure_blocking, show_azure_history_blocking,
    list_azure_backup_blocking, restore_azure_backup_blocking,
};
use sequoiarecover::server::run_server;
use sequoiarecover::server_client::{
    list_server_backup_blocking, restore_server_backup_blocking, show_server_history_blocking,
    upload_to_server_blocking,
};
use tracing_subscriber::EnvFilter;

use clap::{CommandFactory, Parser, Subcommand};
use clap_mangen::Man;
use std::thread::sleep;
use std::time::Duration;

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
        /// Store credentials in OS keychain
        #[arg(long, default_value_t = false)]
        keyring: bool,
        /// URL of the backup server when using the server cloud option
        #[arg(long)]
        server_url: Option<String>,
        /// Override detected link speed in Mbps when using auto compression
        #[arg(long)]
        compression_threshold: Option<u64>,
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
        /// Retrieve credentials from the keychain
        #[arg(long, default_value_t = false)]
        keyring: bool,
        /// URL of the backup server when using the server cloud option
        #[arg(long)]
        server_url: Option<String>,
        /// Override detected link speed in Mbps when using auto compression
        #[arg(long)]
        compression_threshold: Option<u64>,
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
        /// URL of the backup server when using the server cloud option
        #[arg(long)]
        server_url: Option<String>,
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
        /// URL of the backup server when using the server cloud option
        #[arg(long)]
        server_url: Option<String>,
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
        /// URL of the backup server when using the server cloud option
        #[arg(long)]
        server_url: Option<String>,
    },
    /// Run a local backup server
    Serve {
        /// Address to listen on, e.g. 0.0.0.0:3030
        #[arg(long, default_value = "127.0.0.1:3030")]
        address: String,
        /// Directory to store uploaded backups
        #[arg(long, default_value = "storage")]
        dir: String,
    },
    /// Initialize encrypted configuration
    Init {
        /// Store credentials in the OS keychain
        #[arg(long, default_value_t = false)]
        keyring: bool,
    },
    /// Generate the SequoiaRecover man page
    Manpage,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
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
            keyring,
            server_url,
            compression_threshold,
        } => {
            let actual_compression = if compression == CompressionType::Auto {
                let c = auto_select_compression(compression_threshold);
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
                    match load_credentials(account_id, application_key, keyring) {
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
                } else if cloud == "aws" {
                    if let (Ok(ak), Ok(sk), Ok(region)) = (
                        std::env::var("AWS_ACCESS_KEY_ID"),
                        std::env::var("AWS_SECRET_ACCESS_KEY"),
                        std::env::var("AWS_REGION"),
                    ) {
                        if let Err(e) = upload_to_s3_blocking(&ak, &sk, &region, &bucket, &output) {
                            eprintln!("Upload failed: {}", e);
                        } else {
                            println!("Uploaded to S3 bucket {}", bucket);
                        }
                    } else {
                        eprintln!("Missing AWS credentials");
                    }
                } else if cloud == "azure" {
                    if let (Ok(acct), Ok(key)) = (
                        std::env::var("AZURE_STORAGE_ACCOUNT"),
                        std::env::var("AZURE_STORAGE_KEY"),
                    ) {
                        if let Err(e) = upload_to_azure_blocking(&acct, &key, &bucket, &output) {
                            eprintln!("Upload failed: {}", e);
                        } else {
                            println!("Uploaded to Azure container {}", bucket);
                        }
                    } else {
                        eprintln!("Missing Azure credentials");
                    }
                } else if cloud == "server" {
                    let url = server_url.or_else(|| std::env::var("SERVER_URL").ok());
                    if let Some(u) = url {
                        if let Err(e) = upload_to_server_blocking(&u, &bucket, &output) {
                            eprintln!("Upload failed: {}", e);
                        } else {
                            println!("Uploaded to server {}", u);
                        }
                    } else {
                        eprintln!("Missing server_url");
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
            keyring,
            server_url,
            compression_threshold,
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
                if let Err(e) = run_backup(&source, &output, actual_compression, mode) {
                    eprintln!("Scheduled backup failed: {}", e);
                } else {
                    println!("Scheduled backup written to {}", output);
                    if cloud == "backblaze" {
                        match load_credentials(account_id.clone(), application_key.clone(), keyring) {
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
                    } else if cloud == "aws" {
                        if let (Ok(ak), Ok(sk), Ok(region)) = (
                            std::env::var("AWS_ACCESS_KEY_ID"),
                            std::env::var("AWS_SECRET_ACCESS_KEY"),
                            std::env::var("AWS_REGION"),
                        ) {
                            if let Err(e) = upload_to_s3_blocking(&ak, &sk, &region, &bucket, &output) {
                                eprintln!("Upload failed: {}", e);
                            } else {
                                println!("Uploaded to S3 bucket {}", bucket);
                            }
                        } else {
                            eprintln!("Missing AWS credentials");
                        }
                    } else if cloud == "azure" {
                        if let (Ok(acct), Ok(key)) = (
                            std::env::var("AZURE_STORAGE_ACCOUNT"),
                            std::env::var("AZURE_STORAGE_KEY"),
                        ) {
                            if let Err(e) = upload_to_azure_blocking(&acct, &key, &bucket, &output) {
                                eprintln!("Upload failed: {}", e);
                            } else {
                                println!("Uploaded to Azure container {}", bucket);
                            }
                        } else {
                            eprintln!("Missing Azure credentials");
                        }
                    } else if cloud == "server" {
                        let url = server_url
                            .clone()
                            .or_else(|| std::env::var("SERVER_URL").ok());
                        if let Some(u) = url {
                            if let Err(e) = upload_to_server_blocking(&u, &bucket, &output) {
                                eprintln!("Upload failed: {}", e);
                            } else {
                                println!("Uploaded to server {}", u);
                            }
                        } else {
                            eprintln!("Missing server_url");
                        }
                    }
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
            server_url,
            retain_days,
            retain_weeks,
        } => {
            let retention = retain_days
                .map(|d| Duration::from_secs(d * 24 * 3600))
                .or_else(|| retain_weeks.map(|w| Duration::from_secs(w * 7 * 24 * 3600)));
            if let Some(b) = bucket {
                if cloud == "backblaze" {
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
                } else if cloud == "server" {
                    let url = server_url.or_else(|| std::env::var("SERVER_URL").ok());
                    if let Some(u) = url {
                        if let Err(e) = show_server_history_blocking(&u, &b) {
                            eprintln!("{}", e);
                        }
                    } else {
                        eprintln!("Missing server_url");
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
            server_url,
        } => {
            let result = if let Some(b) = bucket {
                if cloud == "backblaze" {
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
                } else if cloud == "server" {
                    let url = server_url.or_else(|| std::env::var("SERVER_URL").ok());
                    if let Some(u) = url {
                        list_server_backup_blocking(&u, &b, &backup, compression)
                    } else {
                        Err("Missing server_url".into())
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
            server_url,
        } => {
            let result = if let Some(b) = bucket {
                if cloud == "backblaze" {
                    match load_credentials(account_id, application_key, keyring) {
                        Ok((id, key)) => restore_remote_backup_blocking(
                            &id,
                            &key,
                            &b,
                            &backup,
                            &destination,
                            compression,
                        ),
                        Err(e) => Err(e),
                    }
                } else if cloud == "aws" {
                    if let (Ok(ak), Ok(sk), Ok(region)) = (
                        std::env::var("AWS_ACCESS_KEY_ID"),
                        std::env::var("AWS_SECRET_ACCESS_KEY"),
                        std::env::var("AWS_REGION"),
                    ) {
                        restore_s3_backup_blocking(&ak, &sk, &region, &b, &backup, &destination, compression)
                    } else {
                        Err("Missing AWS credentials".into())
                    }
                } else if cloud == "azure" {
                    if let (Ok(acct), Ok(key)) = (
                        std::env::var("AZURE_STORAGE_ACCOUNT"),
                        std::env::var("AZURE_STORAGE_KEY"),
                    ) {
                        restore_azure_backup_blocking(&acct, &key, &b, &backup, &destination, compression)
                    } else {
                        Err("Missing Azure credentials".into())
                    }
                } else if cloud == "server" {
                    let url = server_url.or_else(|| std::env::var("SERVER_URL").ok());
                    if let Some(u) = url {
                        restore_server_backup_blocking(&u, &b, &backup, &destination, compression)
                    } else {
                        Err("Missing server_url".into())
                    }
                } else {
                    Err("Unsupported cloud".into())
                }
            } else {
                restore_backup(&backup, &destination, compression)
            };
            if let Err(e) = result {
                eprintln!("{}", e);
            }
        }
        Commands::Serve { address, dir } => {
            let addr: std::net::SocketAddr = match address.parse() {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("Invalid address: {}", e);
                    return;
                }
            };
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            if let Err(e) = rt.block_on(run_server(addr, dir.into())) {
                eprintln!("{}", e);
            }
        }
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
                    let confirm = rpassword::prompt_password("Confirm password: ").unwrap_or_default();
                    if password != confirm {
                        eprintln!("Passwords do not match");
                        return;
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
        Commands::Manpage => {
            let cmd = Cli::command();
            let man = Man::new(cmd);
            if let Err(e) = man.render(&mut std::io::stdout()) {
                eprintln!("Failed to generate man page: {}", e);
            }
        }
    }
}
