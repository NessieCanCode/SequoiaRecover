use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::remote::StorageProvider;

#[derive(Clone, Copy)]
pub struct TransferOpts {
    pub chunk_size: usize,
    pub resume: bool,
}

impl Default for TransferOpts {
    fn default() -> Self {
        TransferOpts {
            chunk_size: 4 * 1024 * 1024,
            resume: false,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct State {
    completed: usize,
}

fn state_dir() -> Result<PathBuf, Box<dyn Error>> {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"))?;
    let path = PathBuf::from(home).join(".sequoiarecover");
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

pub fn upload_file(
    provider: &dyn StorageProvider,
    bucket: &str,
    file_path: &str,
    opts: &TransferOpts,
) -> Result<(), Box<dyn Error>> {
    let file_name = Path::new(file_path)
        .file_name()
        .ok_or("invalid file")?
        .to_string_lossy()
        .to_string();
    let dir = state_dir()?;
    let state_path = dir.join(format!("{}.upload", file_name));
    let mut completed = if opts.resume && state_path.exists() {
        let f = File::open(&state_path)?;
        serde_json::from_reader(f)?
    } else {
        State { completed: 0 }
    };

    let mut f = File::open(file_path)?;
    f.seek(SeekFrom::Start(
        (completed.completed as u64) * opts.chunk_size as u64,
    ))?;
    let mut buf = vec![0u8; opts.chunk_size];
    let mut part = completed.completed;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let tmp = dir.join(format!("{}.part{}", file_name, part));
        {
            let mut t = File::create(&tmp)?;
            t.write_all(&buf[..n])?;
        }
        provider.upload_blocking(bucket, tmp.to_str().unwrap())?;
        std::fs::remove_file(&tmp)?;
        part += 1;
        completed.completed = part;
        let mut s = File::create(&state_path)?;
        serde_json::to_writer(&mut s, &completed)?;
    }
    // upload manifest
    let manifest_tmp = dir.join(format!("{}.manifest", file_name));
    let mut mf = File::create(&manifest_tmp)?;
    serde_json::to_writer(&mut mf, &completed.completed)?;
    provider.upload_blocking(bucket, manifest_tmp.to_str().unwrap())?;
    let _ = std::fs::remove_file(&manifest_tmp);
    let _ = std::fs::remove_file(&state_path);
    Ok(())
}

pub fn download_file(
    provider: &dyn StorageProvider,
    bucket: &str,
    file_name: &str,
    dest: &Path,
    opts: &TransferOpts,
) -> Result<(), Box<dyn Error>> {
    let dir = state_dir()?;
    let base = Path::new(file_name)
        .file_name()
        .ok_or("invalid file")?
        .to_string_lossy()
        .to_string();
    let state_path = dir.join(format!("{}.download", base));
    let mut completed: State = if opts.resume && state_path.exists() {
        let f = File::open(&state_path)?;
        serde_json::from_reader(f)?
    } else {
        State { completed: 0 }
    };

    // download manifest to know part count
    let manifest_tmp = dir.join(format!("{}.manifest", base));
    provider.download_blocking(bucket, &format!("{}.manifest", base), &manifest_tmp)?;
    let total_parts: usize = serde_json::from_reader(File::open(&manifest_tmp)?)?;
    std::fs::remove_file(&manifest_tmp)?;

    let mut out = if completed.completed == 0 {
        File::create(dest)?
    } else {
        OpenOptions::new().append(true).open(dest)?
    };

    for part in completed.completed..total_parts {
        let tmp = dir.join(format!("{}.part{}", base, part));
        provider.download_blocking(bucket, &format!("{}.part{}", base, part), &tmp)?;
        let mut chunk = File::open(&tmp)?;
        std::io::copy(&mut chunk, &mut out)?;
        std::fs::remove_file(&tmp)?;
        completed.completed = part + 1;
        let mut s = File::create(&state_path)?;
        serde_json::to_writer(&mut s, &completed)?;
    }
    let _ = std::fs::remove_file(&state_path);
    Ok(())
}
