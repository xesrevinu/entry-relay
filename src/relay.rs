use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::auth::{self, FRAME_LEN, PURPOSE_MUX2, PURPOSE_OPEN, PURPOSE_PING, STATUS_OK, STATUS_QUOTA, STATUS_UPSTREAM};
use crate::mux;
use crate::copy::copy_count;
use crate::tlsutil::{load_certs, load_key, server_config};
use crate::usage::Usage;

#[derive(Debug, Clone, Deserialize)]
pub struct RelayConfig {
    pub listen: SocketAddr,
    pub upstream: String,
    pub psk_file: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub quota_bytes: u64,
    pub state: PathBuf,
    /// Per-stream receive window in KiB (default 4096).
    #[serde(default)]
    pub window_kb: Option<u32>,
}

struct Shared {
    upstream: String,
    psk: Vec<u8>,
    quota_bytes: u64,
    state: PathBuf,
    used: Arc<AtomicU64>,
    window: u32,
    acceptor: TlsAcceptor,
}

pub async fn serve(config: RelayConfig, bound: oneshot::Sender<SocketAddr>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(config.listen).await?;
    serve_on(config, listener, bound, crate::reload::Gate::forever()).await
}

pub async fn serve_on(
    config: RelayConfig,
    listener: TcpListener,
    bound: oneshot::Sender<SocketAddr>,
    gate: Arc<crate::reload::Gate>,
) -> anyhow::Result<()> {
    let psk = std::fs::read(&config.psk_file)?;
    let certs = load_certs(&config.cert)?;
    let key = load_key(&config.key)?;
    let server = server_config(certs, key)?;
    let usage = Usage::load(&config.state, SystemTime::now());
    let shared = Arc::new(Shared {
        upstream: config.upstream,
        psk,
        quota_bytes: config.quota_bytes,
        state: config.state,
        used: Arc::new(AtomicU64::new(usage.bytes)),
        window: mux::clamp_window(config.window_kb),
        acceptor: TlsAcceptor::from(server),
    });
    let addr = listener.local_addr()?;
    let _ = bound.send(addr);
    info!(%addr, upstream = %shared.upstream, "relay listening");
    while let Some((sock, peer, ticket)) = crate::reload::accept_one(&listener, &gate).await {
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let _ticket = ticket;
            if let Err(err) = handle(sock, peer, shared).await {
                warn!(%peer, %err, "relay connection closed");
            }
        });
    }
    gate.wait_idle().await;
    Ok(())
}

async fn read_preface(tls: &mut tokio_rustls::server::TlsStream<TcpStream>) -> Vec<u8> {
    let mut buf = vec![0u8; FRAME_LEN];
    let mut filled = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while filled < FRAME_LEN {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        match timeout(left, tls.read(&mut buf[filled..])).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => filled += n,
        }
    }
    buf.truncate(filled);
    buf
}

async fn handle(sock: TcpStream, peer: SocketAddr, shared: Arc<Shared>) -> anyhow::Result<()> {
    crate::mux::tune(&sock);
    let mut tls = match timeout(Duration::from_secs(8), shared.acceptor.accept(sock)).await {
        Ok(Ok(tls)) => tls,
        _ => return Ok(()),
    };
    let mut exporter = [0u8; 32];
    tls.get_ref().1.export_keying_material(&mut exporter, auth::LABEL, None)?;
    let preface = read_preface(&mut tls).await;
    let now = SystemTime::now();
    let now_secs = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let purpose = if preface.len() == FRAME_LEN { auth::verify(&shared.psk, &exporter, &preface, now_secs, 120).ok() } else { None };
    let Some(purpose) = purpose else {
        if let Some(page) = auth::public_http_response(&preface, now) {
            let _ = tls.write_all(&page).await;
        }
        return Ok(());
    };
    if purpose == PURPOSE_PING {
        tls.write_all(&[STATUS_OK]).await?;
        return Ok(());
    }
    if purpose != PURPOSE_OPEN && purpose != PURPOSE_MUX2 {
        if let Some(page) = auth::public_http_response(&preface, now) {
            let _ = tls.write_all(&page).await;
        }
        return Ok(());
    }
    if shared.used.load(Ordering::Relaxed) >= shared.quota_bytes {
        tls.write_all(&[STATUS_QUOTA]).await?;
        return Ok(());
    }
    if purpose == PURPOSE_MUX2 {
        tls.write_all(&[STATUS_OK]).await?;
        mux::serve(tls, shared.upstream.clone(), Arc::clone(&shared.used), shared.window).await?;
        let used = shared.used.load(Ordering::Relaxed);
        let usage = Usage { period: crate::usage::period_key(SystemTime::now()), bytes: used };
        if let Err(err) = usage.store(&shared.state) {
            warn!(%err, "failed to store relay usage");
        }
        info!(%peer, used, "mux session finished");
        return Ok(());
    }
    let upstream = match timeout(Duration::from_secs(10), TcpStream::connect(&shared.upstream)).await {
        Ok(Ok(stream)) => stream,
        _ => {
            tls.write_all(&[STATUS_UPSTREAM]).await?;
            return Ok(());
        }
    };
    upstream.set_nodelay(true)?;
    tls.write_all(&[STATUS_OK]).await?;
    let counter = Arc::new(AtomicU64::new(0));
    let (client_r, client_w) = tokio::io::split(tls);
    let (up_r, up_w) = tokio::io::split(upstream);
    let down = copy_count(client_r, up_w, Arc::clone(&counter));
    let up = copy_count(up_r, client_w, Arc::clone(&counter));
    let _ = tokio::try_join!(down, up);
    let bytes = counter.load(Ordering::Relaxed);
    let used = shared.used.fetch_add(bytes, Ordering::Relaxed) + bytes;
    let usage = Usage {
        period: crate::usage::period_key(SystemTime::now()),
        bytes: used,
    };
    if let Err(err) = usage.store(&shared.state) {
        warn!(%err, "failed to store relay usage");
    }
    info!(%peer, bytes, used, "relay session finished");
    Ok(())
}
