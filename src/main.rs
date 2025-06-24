use bzip2::write::BzEncoder;
use bzip2::Compression as BzCompression;
use clap::{Parser, Subcommand, ValueEnum};
use flate2::write::GzEncoder;
use flate2::Compression as GzCompression;
use num_cpus;
use std::error::Error;
use std::fs::File;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;
use tar::Builder;
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
        /// Destination cloud provider. Placeholder for now
        #[arg(long, default_value = "backblaze")]
        cloud: String,
        /// Bucket name in the cloud provider
        #[arg(long)]
        bucket: String,
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
        /// Destination cloud provider. Placeholder for now
        #[arg(long, default_value = "backblaze")]
        cloud: String,
        /// Bucket name in the cloud provider
        #[arg(long)]
        bucket: String,
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

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Backup {
            source,
            output,
            compression,
            cloud,
            bucket,
        } => {
            println!(
                "Starting backup from {} to {} bucket {} using {:?}",
                source, cloud, bucket, compression
            );
            if let Err(e) = run_backup(&source, &output, compression) {
                eprintln!("Backup failed: {}", e);
            } else {
                println!("Backup written to {}", output);
            }
        }
        Commands::Schedule {
            source,
            output,
            compression,
            cloud,
            bucket,
            interval,
            max_runs,
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
                if let Err(e) = run_backup(&source, &output, compression.clone()) {
                    eprintln!("Scheduled backup failed: {}", e);
                } else {
                    println!("Scheduled backup written to {}", output);
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
) -> Result<(), Box<dyn Error>> {
    let file = File::create(output)?;
    let path = Path::new(source);
    match compression {
        CompressionType::Gzip => {
            let enc = GzEncoder::new(file, GzCompression::default());
            let mut tar = Builder::new(enc);
            if path.is_dir() {
                tar.append_dir_all(".", path)?;
            } else {
                tar.append_path_with_name(path, path.file_name().unwrap())?;
            }
            let enc = tar.into_inner()?;
            enc.finish()?;
        }
        CompressionType::Bzip2 => {
            let enc = BzEncoder::new(file, BzCompression::default());
            let mut tar = Builder::new(enc);
            if path.is_dir() {
                tar.append_dir_all(".", path)?;
            } else {
                tar.append_path_with_name(path, path.file_name().unwrap())?;
            }
            let enc = tar.into_inner()?;
            enc.finish()?;
        }
        CompressionType::Zstd => {
            let mut enc = ZstdEncoder::new(file, 0)?;
            enc.multithread(num_cpus::get() as u32)?;
            let mut tar = Builder::new(enc);
            if path.is_dir() {
                tar.append_dir_all(".", path)?;
            } else {
                tar.append_path_with_name(path, path.file_name().unwrap())?;
            }
            let enc = tar.into_inner()?;
            enc.finish()?;
        }
        CompressionType::None => {
            let mut tar = Builder::new(file);
            if path.is_dir() {
                tar.append_dir_all(".", path)?;
            } else {
                tar.append_path_with_name(path, path.file_name().unwrap())?;
            }
            tar.finish()?;
        }
    }
    Ok(())
}
