use clap::{Parser, Subcommand, ValueEnum};
use std::error::Error;
use std::fs::File;
use std::path::Path;
use tar::Builder;
use flate2::write::GzEncoder;
use flate2::Compression as GzCompression;
use bzip2::write::BzEncoder;
use bzip2::Compression as BzCompression;

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
}

#[derive(Clone, ValueEnum, Debug)]
enum CompressionType {
    None,
    Gzip,
    Bzip2,
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
    }
}

fn run_backup(source: &str, output: &str, compression: CompressionType) -> Result<(), Box<dyn Error>> {
    let file = File::create(output)?;
    match compression {
        CompressionType::Gzip => {
            let enc = GzEncoder::new(file, GzCompression::default());
            let mut tar = Builder::new(enc);
            tar.append_dir_all(".", Path::new(source))?;
            let enc = tar.into_inner()?;
            enc.finish()?;
        }
        CompressionType::Bzip2 => {
            let enc = BzEncoder::new(file, BzCompression::default());
            let mut tar = Builder::new(enc);
            tar.append_dir_all(".", Path::new(source))?;
            let enc = tar.into_inner()?;
            enc.finish()?;
        }
        CompressionType::None => {
            let mut tar = Builder::new(file);
            tar.append_dir_all(".", Path::new(source))?;
            tar.finish()?;
        }
    }
    Ok(())
}
