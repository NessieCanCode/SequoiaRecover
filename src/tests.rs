use super::*;
use crate::backup::{run_backup, restore_backup, CompressionType, BackupMode};
use crate::config::{Config, encrypt_config, decrypt_config};
use tempfile::tempdir;
use std::fs;

#[test]
fn test_encrypt_decrypt_config_roundtrip() {
    let cfg = Config { account_id: "test_id".into(), application_key: "test_key".into() };
    let password = "secret";
    let enc = encrypt_config(&cfg, password).expect("encrypt");
    let dec = decrypt_config(&enc, password).expect("decrypt");
    assert_eq!(dec.account_id, cfg.account_id);
    assert_eq!(dec.application_key, cfg.application_key);
}

#[test]
fn test_encrypt_decrypt_wrong_password() {
    let cfg = Config { account_id: "id".into(), application_key: "key".into() };
    let enc = encrypt_config(&cfg, "pw").expect("encrypt");
    assert!(decrypt_config(&enc, "wrong").is_err());
}

#[test]
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

    if let Some(h) = old_home { std::env::set_var("HOME", h); }
    Ok(())
}
