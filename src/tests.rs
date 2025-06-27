use crate::backup::{
    auto_select_compression, restore_backup, run_backup, BackupMode, CompressionType,
};
use crate::config::{decrypt_config, encrypt_config, Config};
use crate::remote::show_remote_history_blocking;
use crate::remote::{download_from_backblaze_blocking, upload_to_backblaze_blocking};
use crate::server::{handle_rejection, make_routes};
use crate::server_client::upload_to_server_blocking;
use filetime::FileTime;
use serial_test::serial;
use sha2::{Digest, Sha256};
use std::fs;
use std::time::{Duration, SystemTime};
use tempfile::tempdir;
use warp::test::request as warp_request;
use warp::Filter;

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

#[tokio::test]
async fn test_server_rejects_malicious_paths() {
    let dir = tempdir().unwrap();
    let filter = make_routes(dir.path().into(), None).recover(handle_rejection);

    let resp = warp_request()
        .method("POST")
        .path("/upload/%2e%2e/file.txt")
        .body("data")
        .reply(&filter)
        .await;
    assert_eq!(resp.status(), 400);

    let resp = warp_request()
        .method("POST")
        .path("/upload/bucket/foo%2Fbar")
        .body("data")
        .reply(&filter)
        .await;
    assert_eq!(resp.status(), 400);

    let resp = warp_request()
        .method("GET")
        .path("/download/%2e%2e/file.txt")
        .reply(&filter)
        .await;
    assert_eq!(resp.status(), 400);

    let resp = warp_request()
        .method("GET")
        .path("/list/%2e%2e")
        .reply(&filter)
        .await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_server_stream_upload() {
    use tokio::io::AsyncReadExt;

    let dir = tempdir().unwrap();
    let filter = make_routes(dir.path().into(), None).recover(handle_rejection);

    let data = vec![0u8; 5 * 1024 * 1024];
    let resp = warp_request()
        .method("POST")
        .path("/upload/bucket/large.bin")
        .body(data.clone())
        .reply(&filter)
        .await;
    assert_eq!(resp.status(), 200);

    let mut f = tokio::fs::File::open(dir.path().join("bucket/large.bin"))
        .await
        .unwrap();
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf.len(), data.len());
}

#[tokio::test]
async fn test_upload_to_server_blocking_large_file() -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::AsyncWriteExt;
    use tokio::task;

    let dir = tempdir()?;
    let storage_dir = dir.path().join("storage");
    let filter = make_routes(storage_dir.clone(), None).recover(handle_rejection);
    let (addr, server) = warp::serve(filter).bind_ephemeral(([127, 0, 0, 1], 0));
    let srv_handle = task::spawn(server);

    let data_path = dir.path().join("data.bin");
    {
        let mut f = tokio::fs::File::create(&data_path).await?;
        f.write_all(&vec![1u8; 5 * 1024 * 1024]).await?;
    }

    task::spawn_blocking(move || {
        upload_to_server_blocking(
            &format!("http://{}", addr),
            "bucket",
            data_path.to_str().unwrap(),
        )
        .map_err(|e| e.to_string())
    })
    .await??;

    srv_handle.abort();

    let stored = storage_dir.join("bucket").join("data.bin");
    assert!(stored.exists());
    assert_eq!(std::fs::metadata(stored)?.len(), 5 * 1024 * 1024);
    Ok(())
}
