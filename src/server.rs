use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use warp::{Filter, Rejection, Reply};

#[derive(Debug)]
pub(crate) struct Unauthorized;

impl warp::reject::Reject for Unauthorized {}

#[derive(Debug)]
pub(crate) struct BadPath;

impl warp::reject::Reject for BadPath {}

fn valid_segment(seg: &str) -> bool {
    let decoded = percent_decode_str(seg).decode_utf8_lossy();
    if decoded.contains("..") || decoded.contains('/') || decoded.contains('\\') {
        return false;
    }
    PathBuf::from(&*decoded)
        .file_name()
        .map(|f| f.to_string_lossy() == decoded)
        .unwrap_or(false)
}

pub(crate) async fn handle_rejection(
    err: Rejection,
) -> Result<impl Reply, std::convert::Infallible> {
    if err.find::<BadPath>().is_some() {
        return Ok(warp::reply::with_status(
            "Invalid path",
            warp::http::StatusCode::BAD_REQUEST,
        ));
    }
    if err.find::<Unauthorized>().is_some() {
        return Ok(warp::reply::with_status(
            "Unauthorized",
            warp::http::StatusCode::UNAUTHORIZED,
        ));
    }
    if err.is_not_found() {
        return Ok(warp::reply::with_status(
            "Not Found",
            warp::http::StatusCode::NOT_FOUND,
        ));
    }
    Ok(warp::reply::with_status(
        "Internal Server Error",
        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
    ))
}

#[derive(Serialize, Deserialize)]
pub struct FileInfo {
    pub name: String,
    pub modified: i64,
}

fn auth_filter(
    token: Option<String>,
) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    warp::any()
        .and(warp::header::optional::<String>("authorization"))
        .and_then(move |header: Option<String>| {
            let expected = token.clone();
            async move {
                if let Some(expected) = expected {
                    if header.as_deref() == Some(expected.as_str()) {
                        Ok(())
                    } else {
                        Err(warp::reject::custom(Unauthorized))
                    }
                } else {
                    Ok(())
                }
            }
        })
        .untuple_one()
}

pub fn make_routes(
    storage: PathBuf,
    token: Option<String>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let storage_filter = warp::any().map(move || storage.clone());
    let auth = auth_filter(token);

    async fn save_stream<S, B>(
        bucket: String,
        name: String,
        mut stream: S,
        storage: PathBuf,
    ) -> Result<impl Reply, Rejection>
    where
        S: futures::Stream<Item = Result<B, warp::Error>> + Unpin,
        B: bytes::Buf,
    {
        use futures::StreamExt;
        use tokio::io::AsyncWriteExt;

        if !valid_segment(&bucket) || !valid_segment(&name) {
            return Err(warp::reject::custom(BadPath));
        }
        let dir = storage.join(&bucket);
        if fs::create_dir_all(&dir).is_err() {
            return Err(warp::reject());
        }
        let path = dir.join(&name);
        let mut file = match tokio::fs::File::create(&path).await {
            Ok(f) => f,
            Err(_) => return Err(warp::reject()),
        };
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(_) => return Err(warp::reject()),
            };
            if file.write_all(chunk.chunk()).await.is_err() {
                return Err(warp::reject());
            }
        }
        Ok::<_, warp::Rejection>(warp::reply())
    }

    let upload = warp::path!("upload" / String / String)
        .and(auth.clone())
        .and(warp::post())
        .and(warp::body::stream())
        .and(storage_filter.clone())
        .and_then(save_stream);

    let download = warp::path!("download" / String / String)
        .and(auth.clone())
        .and(warp::get())
        .and(storage_filter.clone())
        .and_then(
            |bucket: String, name: String, storage: PathBuf| async move {
                if !valid_segment(&bucket) || !valid_segment(&name) {
                    return Err(warp::reject::custom(BadPath));
                }
                let path = storage.join(&bucket).join(&name);
                match tokio::fs::read(path).await {
                    Ok(data) => Ok::<_, warp::Rejection>(data),
                    Err(_) => Err(warp::reject::not_found()),
                }
            },
        );

    let list = warp::path!("list" / String)
        .and(auth)
        .and(warp::get())
        .and(storage_filter.clone())
        .and_then(|bucket: String, storage: PathBuf| async move {
            if !valid_segment(&bucket) {
                return Err(warp::reject::custom(BadPath));
            }
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

    upload.or(download).or(list)
}

pub async fn run_server(
    addr: std::net::SocketAddr,
    storage: PathBuf,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    token: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let routes = make_routes(storage, token).recover(handle_rejection);
    if let (Some(cert), Some(key)) = (cert, key) {
        warp::serve(routes)
            .tls()
            .cert_path(cert)
            .key_path(key)
            .run(addr)
            .await;
    } else {
        warp::serve(routes).run(addr).await;
    }
    Ok(())
}
