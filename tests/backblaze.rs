use sequoiarecover::remote::{download_from_backblaze_blocking, upload_to_backblaze_blocking};
use serial_test::serial;
use std::fs;
use tempfile::tempdir;

#[test]
#[serial]
fn backblaze_upload_download() -> Result<(), Box<dyn std::error::Error>> {
    let id = match std::env::var("B2_ACCOUNT_ID") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("Skipping Backblaze test: B2_ACCOUNT_ID not set");
            return Ok(());
        }
    };
    let key = match std::env::var("B2_APPLICATION_KEY") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("Skipping Backblaze test: B2_APPLICATION_KEY not set");
            return Ok(());
        }
    };
    let bucket = match std::env::var("B2_BUCKET") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("Skipping Backblaze test: B2_BUCKET not set");
            return Ok(());
        }
    };

    let dir = tempdir()?;
    let src_file = dir.path().join("data.txt");
    fs::write(&src_file, b"b2test")?;

    upload_to_backblaze_blocking(&id, &key, &bucket, src_file.to_str().unwrap())?;

    let dest_file = dir.path().join("out.txt");
    download_from_backblaze_blocking(&id, &key, &bucket, "data.txt", &dest_file)?;

    let content = fs::read_to_string(dest_file)?;
    assert_eq!(content, "b2test");

    Ok(())
}
