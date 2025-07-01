use std::error::Error;
use std::path::Path;
use walkdir::WalkDir;

/// Scan the given directory for ransomware indicators.
/// Returns `Ok(Some(message))` when suspicious patterns are found.
pub fn scan_for_ransomware<P: AsRef<Path>>(path: P) -> Result<Option<String>, Box<dyn Error>> {
    let ransom_notes = [
        "readme_for_decrypt.txt",
        "readme.txt",
        "how_to_decrypt.txt",
        "how_to_recover.txt",
        "decrypt_instructions.txt",
        "_readme.txt",
    ];
    let suspicious_ext = [
        "encrypted", "locked", "enc", "cry", "crypt", "crypt1", "crypt2",
    ];

    let mut total = 0u64;
    let mut suspect = 0u64;

    for entry in WalkDir::new(path) {
        let entry = entry?;
        if entry.file_type().is_file() {
            total += 1;
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if ransom_notes.iter().any(|n| n == &name) {
                return Ok(Some(format!("ransom note detected: {}", entry.path().display())));
            }
            if let Some(ext) = entry.path().extension().and_then(|e| e.to_str()) {
                let ext = ext.to_lowercase();
                if suspicious_ext.iter().any(|s| s == &ext) {
                    suspect += 1;
                }
            }
        }
    }

    if total > 0 && suspect as f64 / total as f64 > 0.3 {
        return Ok(Some("high ratio of encrypted files".into()));
    }

    Ok(None)
}

/// Send an alert message to the management console.
pub fn send_alert(msg: &str) {
    if let Ok(url) = std::env::var("MGMT_CONSOLE_URL") {
        let _ = reqwest::blocking::Client::new()
            .post(format!("{}/alert", url.trim_end_matches('/')))
            .json(&serde_json::json!({ "message": msg }))
            .send();
    }
}

