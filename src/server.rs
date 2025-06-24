use warp::Filter;
use serde::{Serialize, Deserialize};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
pub struct FileInfo {
    pub name: String,
    pub modified: i64,
}

pub async fn run_server(addr: std::net::SocketAddr, storage: PathBuf) -> Result<(), Box<dyn Error>> {
    let storage_filter = warp::any().map(move || storage.clone());

    let upload = warp::path!("upload" / String / String)
        .and(warp::post())
        .and(warp::body::bytes())
        .and(storage_filter.clone())
        .and_then(|bucket: String, name: String, data: bytes::Bytes, storage: PathBuf| async move {
            let dir = storage.join(&bucket);
            if fs::create_dir_all(&dir).is_err() {
                return Err(warp::reject());
            }
            if fs::write(dir.join(&name), &data).is_err() {
                return Err(warp::reject());
            }
            Ok::<_, warp::Rejection>(warp::reply())
        });

    let download = warp::path!("download" / String / String)
        .and(warp::get())
        .and(storage_filter.clone())
        .and_then(|bucket: String, name: String, storage: PathBuf| async move {
            let path = storage.join(&bucket).join(&name);
            match tokio::fs::read(path).await {
                Ok(data) => Ok::<_, warp::Rejection>(data),
                Err(_) => Err(warp::reject::not_found()),
            }
        });

    let list = warp::path!("list" / String)
        .and(warp::get())
        .and(storage_filter.clone())
        .and_then(|bucket: String, storage: PathBuf| async move {
            let dir = storage.join(&bucket);
            let mut out = Vec::new();
            if let Ok(entries) = fs::read_dir(&dir) {
                for e in entries.flatten() {
                    if let Ok(meta) = e.metadata() {
                        if meta.is_file() {
                            let ts = meta
                                .modified()
                                .unwrap_or(SystemTime::UNIX_EPOCH)
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs() as i64;
                            out.push(FileInfo {
                                name: e.file_name().to_string_lossy().into(),
                                modified: ts,
                            });
                        }
                    }
                }
            }
            Ok::<_, warp::Rejection>(warp::reply::json(&out))
        });

    let routes = upload.or(download).or(list);
    warp::serve(routes).run(addr).await;
    Ok(())
}
