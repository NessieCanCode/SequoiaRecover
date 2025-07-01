use once_cell::sync::Lazy;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use sysinfo::Networks;

#[derive(Debug)]
struct ThrottleState {
    networks: Networks,
    last_instant: Instant,
    last_tx: u64,
    last_rx: u64,
    max_upload: Option<u64>,    // Mbps
    max_download: Option<u64>,  // Mbps
}

impl ThrottleState {
    fn new() -> Self {
        let mut networks = Networks::new_with_refreshed_list();
        networks.refresh(true);
        let (tx, rx) = totals(&networks);
        Self {
            networks,
            last_instant: Instant::now(),
            last_tx: tx,
            last_rx: rx,
            max_upload: None,
            max_download: None,
        }
    }
}

static STATE: Lazy<Mutex<ThrottleState>> = Lazy::new(|| Mutex::new(ThrottleState::new()));

fn totals(nets: &Networks) -> (u64, u64) {
    let mut tx = 0u64;
    let mut rx = 0u64;
    for (name, data) in nets {
        if name.starts_with("lo") { continue; }
        tx += data.total_transmitted();
        rx += data.total_received();
    }
    (tx, rx)
}

/// Configure maximum upload and download rates in megabits per second.
pub fn set_limits(upload_mbps: Option<u64>, download_mbps: Option<u64>) {
    let mut s = STATE.lock().unwrap();
    s.max_upload = upload_mbps;
    s.max_download = download_mbps;
}

/// Check current network throughput and sleep if limits are exceeded.
/// Should be called periodically between transfer chunks.
pub fn check() {
    let mut s = STATE.lock().unwrap();
    if s.max_upload.is_none() && s.max_download.is_none() {
        return;
    }

    s.networks.refresh(true);
    let now = Instant::now();
    let elapsed = now.duration_since(s.last_instant).as_secs_f64();
    if elapsed == 0.0 {
        return;
    }

    let (tx, rx) = totals(&s.networks);
    let tx_diff = tx.saturating_sub(s.last_tx);
    let rx_diff = rx.saturating_sub(s.last_rx);
    s.last_tx = tx;
    s.last_rx = rx;
    s.last_instant = now;

    let mut delay = Duration::ZERO;

    if let Some(limit) = s.max_upload {
        let rate_mbps = tx_diff as f64 * 8.0 / 1_000_000.0 / elapsed;
        if rate_mbps > limit as f64 && limit > 0 {
            let needed = tx_diff as f64 * 8.0 / (limit as f64 * 1_000_000.0);
            if needed > elapsed {
                let extra = needed - elapsed;
                delay = delay.max(Duration::from_secs_f64(extra));
            }
        }
    }

    if let Some(limit) = s.max_download {
        let rate_mbps = rx_diff as f64 * 8.0 / 1_000_000.0 / elapsed;
        if rate_mbps > limit as f64 && limit > 0 {
            let needed = rx_diff as f64 * 8.0 / (limit as f64 * 1_000_000.0);
            if needed > elapsed {
                let extra = needed - elapsed;
                delay = delay.max(Duration::from_secs_f64(extra));
            }
        }
    }

    if delay > Duration::ZERO {
        std::thread::sleep(delay);
    }
}
