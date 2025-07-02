use crate::backup::{
    auto_select_compression, restore_backup, run_backup, BackupMode, CompressionType,
};
use crate::config::{decrypt_config, encrypt_config, Config};
use crate::remote::show_remote_history_blocking;
use crate::remote::StorageProvider;
use crate::remote::{download_from_backblaze_blocking, upload_to_backblaze_blocking};
use crate::transfer::{download_file, upload_file, TransferOpts};
use filetime::FileTime;
use serial_test::serial;
use sha2::{Digest, Sha256};
use std::fs;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use tempfile::tempdir;

#[test]
fn test_encrypt_decrypt_config_roundtrip() {
    let cfg = Config {
        account_id: "test_id".into(),
        application_key: "test_key".into(),
    };
    let password = "secret";
    let enc = encrypt_config(&cfg, password).expect("encrypt");
    let dec = decrypt_config(&enc, password).expect("decrypt");
    assert_eq!(dec.account_id, cfg.account_id);
    assert_eq!(dec.application_key, cfg.application_key);
}

#[test]
fn test_encrypt_decrypt_wrong_password() {
    let cfg = Config {
        account_id: "id".into(),
        application_key: "key".into(),
    };
    let enc = encrypt_config(&cfg, "pw").expect("encrypt");
    assert!(decrypt_config(&enc, "wrong").is_err());
}

#[test]
#[serial]
fn test_run_and_restore_backup() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let src = dir.path().join("source");
    fs::create_dir(&src)?;
    fs::write(src.join("file1.txt"), b"hello")?;
    fs::create_dir(src.join("sub"))?;
    fs::write(src.join("sub/file2.txt"), b"world")?;

    let backup_path = dir.path().join("backup.tar");

    // isolate history in temp HOME
    let old_home = std::env::var("HOME").ok();
    std::env::set_var("HOME", dir.path());

    run_backup(
        src.to_str().unwrap(),
        backup_path.to_str().unwrap(),
        CompressionType::None,
        BackupMode::Full,
    )?;

    let restore = dir.path().join("restore");
    fs::create_dir(&restore)?;
    restore_backup(
        backup_path.to_str().unwrap(),
        restore.to_str().unwrap(),
        None,
    )?;

    let c1 = fs::read_to_string(restore.join("file1.txt"))?;
    let c2 = fs::read_to_string(restore.join("sub/file2.txt"))?;
    assert_eq!(c1, "hello");
    assert_eq!(c2, "world");

    if let Some(h) = old_home {
        std::env::set_var("HOME", h);
    }
    Ok(())
}

#[test]
#[serial]
fn test_local_upload_download() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let remote_root = dir.path().join("remote");
    std::env::set_var("LOCAL_B2_DIR", &remote_root);

    let src_file = dir.path().join("data.txt");
    fs::write(&src_file, b"testdata")?;

    upload_to_backblaze_blocking("id", "key", "bucket", src_file.to_str().unwrap())?;

    let stored = remote_root.join("bucket").join("data.txt");
    assert!(stored.exists());
    let expected = {
        let data = fs::read(&src_file)?;
        format!("{:x}", Sha256::digest(&data))
    };
    let remote_data = fs::read(&stored)?;
    let remote_sum = format!("{:x}", Sha256::digest(&remote_data));
    assert_eq!(expected, remote_sum);

    let dest_file = dir.path().join("out.txt");
    download_from_backblaze_blocking("id", "key", "bucket", "data.txt", &dest_file)?;

    let content = fs::read_to_string(dest_file)?;
    assert_eq!(content, "testdata");

    std::env::remove_var("LOCAL_B2_DIR");
    Ok(())
}

#[test]
#[serial]
fn test_download_missing_bucket() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let remote_root = dir.path().join("remote");
    std::env::set_var("LOCAL_B2_DIR", &remote_root);

    let dest_file = dir.path().join("out.txt");
    let res = download_from_backblaze_blocking("id", "key", "missing", "nope.txt", &dest_file);
    assert!(res.is_err());

    std::env::remove_var("LOCAL_B2_DIR");
    Ok(())
}

#[test]
#[serial]
fn test_retention_cleanup() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let remote_root = dir.path().join("remote");
    std::env::set_var("LOCAL_B2_DIR", &remote_root);
    let bucket_dir = remote_root.join("bucket");
    fs::create_dir_all(&bucket_dir)?;
    fs::write(bucket_dir.join("old.txt"), b"old")?;
    fs::write(bucket_dir.join("new.txt"), b"new")?;
    let old_time =
        FileTime::from_system_time(SystemTime::now() - Duration::from_secs(3 * 24 * 3600));
    filetime::set_file_mtime(bucket_dir.join("old.txt"), old_time)?;

    show_remote_history_blocking(
        "id",
        "key",
        "bucket",
        Some(Duration::from_secs(2 * 24 * 3600)),
    )?;
    assert!(!bucket_dir.join("old.txt").exists());
    assert!(bucket_dir.join("new.txt").exists());

    std::env::remove_var("LOCAL_B2_DIR");
    Ok(())
}

#[test]
fn test_auto_select_compression_override() {
    assert_eq!(auto_select_compression(Some(1500)), CompressionType::None);
    assert_eq!(auto_select_compression(Some(200)), CompressionType::Gzip);
    assert_eq!(auto_select_compression(Some(50)), CompressionType::Zstd);
}

struct FailingProvider {
    root: std::path::PathBuf,
    upload_calls: Mutex<usize>,
    fail_upload_at: usize,
    download_calls: Mutex<usize>,
    fail_download_at: usize,
}

impl FailingProvider {
    fn new(root: std::path::PathBuf, fail_upload_at: usize, fail_download_at: usize) -> Self {
        Self {
            root,
            upload_calls: Mutex::new(0),
            fail_upload_at,
            download_calls: Mutex::new(0),
            fail_download_at,
        }
    }
}

impl StorageProvider for FailingProvider {
    fn upload_blocking(
        &self,
        bucket: &str,
        file_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut c = self.upload_calls.lock().unwrap();
        if *c == self.fail_upload_at {
            *c += 1;
            return Err("upload fail".into());
        }
        let dest = self.root.join(bucket);
        std::fs::create_dir_all(&dest)?;
        let name = std::path::Path::new(file_path).file_name().unwrap();
        std::fs::copy(file_path, dest.join(name))?;
        *c += 1;
        Ok(())
    }

    fn download_blocking(
        &self,
        bucket: &str,
        file_name: &str,
        dest: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut c = self.download_calls.lock().unwrap();
        if *c == self.fail_download_at {
            *c += 1;
            return Err("download fail".into());
        }
        let src = self.root.join(bucket).join(file_name);
        std::fs::copy(src, dest)?;
        *c += 1;
        Ok(())
    }

    fn show_history_blocking(
        &self,
        _bucket: &str,
        _ret: Option<std::time::Duration>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

#[test]
#[serial]
fn test_chunked_upload_resume() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let provider = FailingProvider::new(dir.path().join("remote"), 1, usize::MAX);
    let bucket = "b";
    let src = dir.path().join("big.bin");
    std::fs::write(&src, vec![1u8; 2 * 1024 * 1024 + 10])?;
    let opts = TransferOpts {
        chunk_size: 1024 * 1024,
        resume: true,
    };
    assert!(upload_file(&provider, bucket, src.to_str().unwrap(), &opts).is_err());
    assert!(upload_file(&provider, bucket, src.to_str().unwrap(), &opts).is_ok());
    assert!(provider.root.join(bucket).join("big.bin.manifest").exists());
    Ok(())
}

#[test]
#[serial]
fn test_chunked_download_resume() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let remote = dir.path().join("remote");
    let bucket_dir = remote.join("b");
    std::fs::create_dir_all(&bucket_dir)?;
    std::fs::write(bucket_dir.join("file.part0"), b"hello")?;
    std::fs::write(bucket_dir.join("file.part1"), b"world")?;
    std::fs::write(
        bucket_dir.join("file.manifest"),
        serde_json::to_string(&2usize)?,
    )?;
    let provider = FailingProvider::new(remote.clone(), usize::MAX, 1);
    let dest = dir.path().join("out.txt");
    let opts = TransferOpts {
        chunk_size: 5,
        resume: true,
    };
    assert!(download_file(&provider, "b", "file", &dest, &opts).is_err());
    assert!(download_file(&provider, "b", "file", &dest, &opts).is_ok());
    let data = std::fs::read(&dest)?;
    assert_eq!(data, b"helloworld");
    Ok(())
}
