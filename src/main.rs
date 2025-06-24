use backblaze_b2_client::client::B2Client;
use bzip2::write::BzEncoder;
use bzip2::Compression as BzCompression;
use clap::{Parser, Subcommand, ValueEnum};
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
}

#[derive(Clone, ValueEnum, Debug)]
enum CompressionType {
    None,
    Gzip,
    Bzip2,
    Zstd,
}

#[derive(Clone, ValueEnum, Debug)]
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
            println!(
                "Starting backup from {} to {} bucket {} using {:?}",
                source, cloud, bucket, compression
            );
            if let Err(e) = run_backup(&source, &output, compression, mode) {
                eprintln!("Backup failed: {}", e);
            } else {
                println!("Backup written to {}", output);
                if cloud == "backblaze" {
                    match (&account_id, &application_key) {
                        (Some(id), Some(key)) => {
                            if let Err(e) = upload_to_backblaze_blocking(id, key, &bucket, &output)
                            {
                                eprintln!("Upload failed: {}", e);
                            } else {
                                println!("Uploaded to Backblaze bucket {}", bucket);
                            }
                        }
                        _ => eprintln!("Missing Backblaze credentials"),
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
            println!(
                "Scheduling backups every {} seconds from {} to {} bucket {} using {:?}",
                interval, source, cloud, bucket, compression
            );
            let mut run_count = 0u64;
            loop {
                if max_runs > 0 && run_count >= max_runs {
                    break;
                }
                println!("Starting scheduled backup #{}", run_count + 1);
                if let Err(e) = run_backup(&source, &output, compression.clone(), mode.clone()) {
                    eprintln!("Scheduled backup failed: {}", e);
                } else {
                    println!("Scheduled backup written to {}", output);
                    if cloud == "backblaze" {
                        match (&account_id, &application_key) {
                            (Some(id), Some(key)) => {
                                if let Err(e) =
                                    upload_to_backblaze_blocking(id, key, &bucket, &output)
                                {
                                    eprintln!("Upload failed: {}", e);
                                } else {
                                    println!("Uploaded to Backblaze bucket {}", bucket);
                                }
                            }
                            _ => eprintln!("Missing Backblaze credentials"),
                        }
                    }
                }
                run_count += 1;
                sleep(Duration::from_secs(interval));
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

    match compression {
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
