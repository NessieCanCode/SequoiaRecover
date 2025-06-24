use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use bzip2::read::BzDecoder;
use bzip2::write::BzEncoder;
use bzip2::Compression as BzCompression;
use chrono::{DateTime, Local};
use clap::ValueEnum;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression as GzCompression;
use num_cpus;
use serde::{Deserialize, Serialize};
use sysinfo::Networks;
use tar::{Archive, Builder};
use tracing::info;
use walkdir::WalkDir;
use zstd::stream::read::Decoder as ZstdDecoder;
use zstd::stream::write::Encoder as ZstdEncoder;

use crate::config::record_backup;

#[derive(Clone, Copy, ValueEnum, Debug, PartialEq, Serialize, Deserialize)]
pub enum CompressionType {
    None,
    Gzip,
    Bzip2,
    Zstd,
    Auto,
}

#[derive(Clone, Copy, ValueEnum, Debug, Serialize, Deserialize)]
pub enum BackupMode {
    Full,
    Incremental,
}

pub fn run_backup(
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
    record_backup(output, mode, actual)?;
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

fn detect_link_speed() -> Option<u64> {
    let mut networks = Networks::new_with_refreshed_list();
    let mut start = HashMap::new();
    for (name, data) in &networks {
        if name == "lo" || name.starts_with("lo") {
            continue;
        }
        start.insert(
            name.clone(),
            data.total_received() + data.total_transmitted(),
        );
    }
    std::thread::sleep(Duration::from_secs(1));
    networks.refresh(true);
    let mut max_diff = 0u64;
    for (name, data) in &networks {
        if name == "lo" || name.starts_with("lo") {
            continue;
        }
        if let Some(prev) = start.get(name) {
            let diff = (data.total_received() + data.total_transmitted()).saturating_sub(*prev);
            if diff > max_diff {
                max_diff = diff;
            }
        }
    }
    if max_diff == 0 {
        None
    } else {
        Some((max_diff * 8) / 1_000_000)
    }
}

pub fn auto_select_compression() -> CompressionType {
    match detect_link_speed().unwrap_or(0) {
        s if s >= 1000 => CompressionType::None,
        s if s >= 100 => CompressionType::Gzip,
        _ => CompressionType::Zstd,
    }
}

fn guess_compression(path: &str) -> CompressionType {
    let p = path.to_lowercase();
    if p.ends_with(".tar.gz") || p.ends_with(".tgz") {
        CompressionType::Gzip
    } else if p.ends_with(".tar.bz2") || p.ends_with(".tbz2") {
        CompressionType::Bzip2
    } else if p.ends_with(".tar.zst") || p.ends_with(".tzst") {
        CompressionType::Zstd
    } else {
        CompressionType::None
    }
}

fn open_archive(
    path: &str,
    compression: CompressionType,
) -> Result<Archive<Box<dyn Read>>, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader: Box<dyn Read> = match compression {
        CompressionType::Gzip => Box::new(GzDecoder::new(file)),
        CompressionType::Bzip2 => Box::new(BzDecoder::new(file)),
        CompressionType::Zstd => Box::new(ZstdDecoder::new(file)?),
        CompressionType::None | CompressionType::Auto => Box::new(file),
    };
    Ok(Archive::new(reader))
}

pub fn list_backup(path: &str, compression: Option<CompressionType>) -> Result<(), Box<dyn Error>> {
    let comp = compression.unwrap_or_else(|| guess_compression(path));
    let mut ar = open_archive(path, comp)?;
    for file in ar.entries()? {
        let entry = file?;
        let header = entry.header();
        let mtime = header.mtime().unwrap_or(0);
        let mode = header.mode().unwrap_or(0);
        let dt: DateTime<Local> = (UNIX_EPOCH + Duration::from_secs(mtime)).into();
        let path = entry.path()?.display().to_string();
        info!("{}\t{:o}\t{}", path, mode, dt.format("%Y-%m-%d %H:%M:%S"));
    }
    Ok(())
}

pub fn restore_backup(
    path: &str,
    destination: &str,
    compression: Option<CompressionType>,
) -> Result<(), Box<dyn Error>> {
    let comp = compression.unwrap_or_else(|| guess_compression(path));
    let mut ar = open_archive(path, comp)?;
    ar.unpack(destination)?;
    Ok(())
}
