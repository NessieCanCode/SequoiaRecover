use crate::backup::{restore_backup, run_backup, BackupMode, CompressionType};
use crate::config::{decrypt_config, encrypt_config, Config};
use crate::remote::{download_from_backblaze_blocking, upload_to_backblaze_blocking};
use serial_test::serial;
use std::fs;
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
