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
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305};
use base64::{engine::general_purpose, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
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

impl Default for CompressionType {
    fn default() -> Self {
        CompressionType::Gzip
    }
}

#[derive(Clone, Copy, ValueEnum, Debug, Serialize, Deserialize, PartialEq)]
pub enum BackupMode {
    Full,
    Incremental,
}

impl Default for BackupMode {
    fn default() -> Self {
        BackupMode::Full
    }
}

fn count_files(
    root: &Path,
    mode: BackupMode,
    previous: &HashMap<String, u64>,
) -> Result<u64, Box<dyn Error>> {
    let mut count = 0u64;
    for entry in WalkDir::new(root) {
        let entry = entry?;
        if entry.depth() == 0 && entry.file_type().is_dir() {
            continue;
        }
        if entry.file_type().is_file() {
            let rel = entry.path().strip_prefix(root)?;
            let rel_str = rel.to_string_lossy().to_string();
            let mtime = entry
                .metadata()?
                .modified()?
                .duration_since(UNIX_EPOCH)?
                .as_secs();
            let include = match mode {
                BackupMode::Full => true,
                BackupMode::Incremental => previous.get(&rel_str).map_or(true, |old| *old < mtime),
            };
            if include {
                count += 1;
            }
        }
    }
    Ok(count)
}

pub fn run_backup_with_progress<F>(
    source: &str,
    output: &str,
    compression: CompressionType,
    mode: BackupMode,
    mut progress: F,
) -> Result<(), Box<dyn Error>>
where
    F: FnMut(u64, u64),
{
    let path = Path::new(source);
    let actual = if compression == CompressionType::Auto {
        auto_select_compression(None)
    } else {
        compression
    };
    let output_path = ensure_extension(output, actual);
    let meta_path = format!("{}.meta", output_path);
    let previous: HashMap<String, u64> = if let Ok(f) = File::open(&meta_path) {
        serde_json::from_reader(f)?
    } else {
        HashMap::new()
    };
    let mut current: HashMap<String, u64> = HashMap::new();

    let file = File::create(&output_path)?;

    let total = count_files(path, mode, &previous)?;
    let mut done = 0u64;

    match actual {
        CompressionType::Gzip => {
            let enc = GzEncoder::new(file, GzCompression::default());
            let mut tar = Builder::new(enc);
            add_files_progress(
                &mut tar,
                path,
                mode,
                &previous,
                &mut current,
                &mut done,
                total,
                &mut progress,
            )?;
            let enc = tar.into_inner()?;
            enc.finish()?;
        }
        CompressionType::Bzip2 => {
            let enc = BzEncoder::new(file, BzCompression::default());
            let mut tar = Builder::new(enc);
            add_files_progress(
                &mut tar,
                path,
                mode,
                &previous,
                &mut current,
                &mut done,
                total,
                &mut progress,
            )?;
            let enc = tar.into_inner()?;
            enc.finish()?;
        }
        CompressionType::Zstd => {
            let mut enc = ZstdEncoder::new(file, 0)?;
            enc.multithread(num_cpus::get() as u32)?;
            let mut tar = Builder::new(enc);
            add_files_progress(
                &mut tar,
                path,
                mode,
                &previous,
                &mut current,
                &mut done,
                total,
                &mut progress,
            )?;
            let enc = tar.into_inner()?;
            enc.finish()?;
        }
        CompressionType::None => {
            let mut tar = Builder::new(file);
            add_files_progress(
                &mut tar,
                path,
                mode,
                &previous,
                &mut current,
                &mut done,
                total,
                &mut progress,
            )?;
            tar.finish()?;
        }
        CompressionType::Auto => unreachable!(),
    }

    let meta_file = File::create(&meta_path)?;
    serde_json::to_writer_pretty(meta_file, &current)?;
    record_backup(&output_path, mode, actual)?;
    Ok(())
}

pub fn run_backup(
    source: &str,
    output: &str,
    compression: CompressionType,
    mode: BackupMode,
) -> Result<(), Box<dyn Error>> {
    let path = Path::new(source);
    let actual = if compression == CompressionType::Auto {
        auto_select_compression(None)
    } else {
        compression
    };
    let output_path = ensure_extension(output, actual);
    let meta_path = format!("{}.meta", output_path);
    let previous: HashMap<String, u64> = if let Ok(f) = File::open(&meta_path) {
        serde_json::from_reader(f)?
    } else {
        HashMap::new()
    };
    let mut current: HashMap<String, u64> = HashMap::new();

    let file = File::create(&output_path)?;

    match actual {
        CompressionType::Gzip => {
            let enc = GzEncoder::new(file, GzCompression::default());
            let mut tar = Builder::new(enc);
            let mut dummy = 0u64;
            add_files_progress(
                &mut tar,
                path,
                mode,
                &previous,
                &mut current,
                &mut dummy,
                0,
                &mut |_d, _t| {},
            )?;
            let enc = tar.into_inner()?;
            enc.finish()?;
        }
        CompressionType::Bzip2 => {
            let enc = BzEncoder::new(file, BzCompression::default());
            let mut tar = Builder::new(enc);
            let mut dummy = 0u64;
            add_files_progress(
                &mut tar,
                path,
                mode,
                &previous,
                &mut current,
                &mut dummy,
                0,
                &mut |_d, _t| {},
            )?;
            let enc = tar.into_inner()?;
            enc.finish()?;
        }
        CompressionType::Zstd => {
            let mut enc = ZstdEncoder::new(file, 0)?;
            enc.multithread(num_cpus::get() as u32)?;
            let mut tar = Builder::new(enc);
            let mut dummy = 0u64;
            add_files_progress(
                &mut tar,
                path,
                mode,
                &previous,
                &mut current,
                &mut dummy,
                0,
                &mut |_d, _t| {},
            )?;
            let enc = tar.into_inner()?;
            enc.finish()?;
        }
        CompressionType::None => {
            let mut tar = Builder::new(file);
            let mut dummy = 0u64;
            add_files_progress(
                &mut tar,
                path,
                mode,
                &previous,
                &mut current,
                &mut dummy,
                0,
                &mut |_d, _t| {},
            )?;
            tar.finish()?;
        }
        CompressionType::Auto => unreachable!(),
    }

    let meta_file = File::create(&meta_path)?;
    serde_json::to_writer_pretty(meta_file, &current)?;
    record_backup(&output_path, mode, actual)?;
    Ok(())
}

fn add_files_progress<T: std::io::Write>(
    tar: &mut Builder<T>,
    root: &Path,
    mode: BackupMode,
    previous: &HashMap<String, u64>,
    current: &mut HashMap<String, u64>,
    done: &mut u64,
    total: u64,
    progress: &mut dyn FnMut(u64, u64),
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
                BackupMode::Incremental => previous.get(&rel_str).is_none_or(|old| *old < mtime),
            };
            if include {
                tar.append_path_with_name(path, rel)?;
                *done += 1;
                progress(*done, total);
            }
        }
    }
    Ok(())
}

fn detect_link_speed(duration_secs: u64) -> Option<u64> {
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
    std::thread::sleep(Duration::from_secs(duration_secs));
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
        Some((max_diff * 8) / 1_000_000 / duration_secs)
    }
}

pub fn auto_select_compression(override_speed: Option<u64>) -> CompressionType {
    let speed = override_speed.unwrap_or_else(|| detect_link_speed(5).unwrap_or(0));
    match speed {
        s if s >= 1000 => CompressionType::None,
        s if s >= 100 => CompressionType::Gzip,
        _ => CompressionType::Zstd,
    }
}

pub fn ensure_extension(path: &str, compression: CompressionType) -> String {
    let lc = path.to_lowercase();
    let base = [
        (".tar.gz", CompressionType::Gzip),
        (".tgz", CompressionType::Gzip),
        (".tar.bz2", CompressionType::Bzip2),
        (".tbz2", CompressionType::Bzip2),
        (".tar.zst", CompressionType::Zstd),
        (".tzst", CompressionType::Zstd),
        (".tar", CompressionType::None),
    ]
    .iter()
    .find_map(|(ext, ty)| {
        if lc.ends_with(ext) {
            Some((path[..path.len() - ext.len()].to_string(), *ty))
        } else {
            None
        }
    });

    let stem = match base {
        Some((b, _)) => b,
        None => path.to_string(),
    };

    let ext = match compression {
        CompressionType::Gzip => ".tar.gz",
        CompressionType::Bzip2 => ".tar.bz2",
        CompressionType::Zstd => ".tar.zst",
        CompressionType::None => ".tar",
        CompressionType::Auto => return path.to_string(),
    };

    format!("{}{}", stem, ext)
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

#[derive(Serialize, Deserialize)]
pub struct EncryptedArchive {
    pub nonce: String,
    pub ciphertext: String,
    pub checksum: String,
}

pub fn encrypt_file(src: &str, dest: &str, key: &[u8; 32]) -> Result<(), Box<dyn Error>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = nonce_bytes.as_slice().try_into().expect("nonce len");
    let data = std::fs::read(src)?;
    let checksum = Sha256::digest(&data);
    let ct = cipher.encrypt(nonce, data.as_ref())?;
    let enc = EncryptedArchive {
        nonce: general_purpose::STANDARD.encode(nonce_bytes),
        ciphertext: general_purpose::STANDARD.encode(ct),
        checksum: format!("{:x}", checksum),
    };
    let f = File::create(dest)?;
    serde_json::to_writer_pretty(f, &enc)?;
    Ok(())
}

pub fn decrypt_file(src: &str, dest: &str, key: &[u8; 32]) -> Result<(), Box<dyn Error>> {
    let f = File::open(src)?;
    let enc: EncryptedArchive = serde_json::from_reader(f)?;
    let nonce_bytes = general_purpose::STANDARD.decode(enc.nonce)?;
    let ct = general_purpose::STANDARD.decode(enc.ciphertext)?;
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = nonce_bytes.as_slice().try_into().expect("nonce len");
    let data = cipher.decrypt(nonce, ct.as_ref())?;
    let check = format!("{:x}", Sha256::digest(&data));
    if check != enc.checksum {
        return Err("Checksum mismatch".into());
    }
    std::fs::write(dest, &data)?;
    Ok(())
}
