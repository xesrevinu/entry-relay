use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Mutex, RwLock};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

use crate::auth::{self, PURPOSE_MUX2, STATUS_OK, STATUS_QUOTA};
use crate::mux::{self, Session};
use crate::schedule::{pick, Candidate};
use crate::socks::{self, allowed, endpoint};
use crate::tlsutil::{self, client_config};

#[derive(Debug, Clone, Deserialize)]
pub struct BalanceConfig {
    pub listen: SocketAddr,
    pub psk_file: PathBuf,
    pub state: PathBuf,
    pub max_rtt_ms: u32,
    pub probe_secs: u64,
    pub allow: Vec<String>,
    pub relay: Vec<RelayConfig>,
    /// Parallel TLS mux sessions kept per relay (default 4; 1 = one session).
    #[serde(default)]
    pub sessions: Option<usize>,
    /// Per-stream receive window in KiB (default 4096).
    #[serde(default)]
    pub window_kb: Option<u32>,
}

pub const DEFAULT_SESSIONS: usize = 4;

#[derive(Debug, Clone, Deserialize)]
pub struct RelayConfig {
    pub name: String,
    pub addr: String,
    pub sni: String,
    pub pin_sha256: String,
    pub quota_bytes: u64,
}

struct Live {
    cfg: RelayConfig,
    pin: [u8; 32],
    used: AtomicU64,
    rtt_ms: RwLock<Option<u32>>,
    up: RwLock<bool>,
    slots: Vec<Slot>,
    /// Next slot to try for a new stream. Wraps; not a hard affinity.
    rr: AtomicUsize,
}

/// One mux session slot: dialed, health-checked and redialed on its own.
struct Slot {
    dial: Mutex<()>,
    current: std::sync::RwLock<Option<Arc<Session>>>,
    /// TCP+TLS+auth time of the current session (~3 RTT). Per-flow path RTT
    /// is fixed for the life of a TCP, so this ranks sessions by path.
    dial_ms: AtomicU64,
}

impl Slot {
    fn get(&self) -> Option<Arc<Session>> {
        self.current.read().unwrap().clone().filter(|s| s.alive())
    }
}

struct Shared {
    psk: Vec<u8>,
    max_rtt_ms: u32,
    allow: Vec<String>,
    state: PathBuf,
    relays: Vec<Arc<Live>>,
    window: u32,
}

pub async fn serve(config: BalanceConfig, bound: oneshot::Sender<SocketAddr>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(config.listen).await?;
    serve_on(config, listener, bound, crate::reload::Gate::forever()).await
}

/// Accept on an already-bound listener. The worker side of a reload passes
/// the inherited socket and a gate that stops the loop on SIGQUIT.
pub async fn serve_on(
    config: BalanceConfig,
    listener: TcpListener,
    bound: oneshot::Sender<SocketAddr>,
    gate: Arc<crate::reload::Gate>,
) -> anyhow::Result<()> {
    let psk = std::fs::read(&config.psk_file)?;
    let period = crate::usage::period_key(SystemTime::now());
    let sessions = config.sessions.unwrap_or(DEFAULT_SESSIONS).clamp(1, 64);
    let relays = config
        .relay
        .into_iter()
        .map(|cfg| {
            let pin = decode_pin(&cfg.pin_sha256)?;
            let used = load_relay_used(&config.state, &cfg.name, &period);
            Ok::<_, anyhow::Error>(Arc::new(Live {
                cfg,
                pin,
                used: AtomicU64::new(used),
                rtt_ms: RwLock::new(None),
                up: RwLock::new(true),
                slots: (0..sessions)
                    .map(|_| Slot { dial: Mutex::new(()), current: std::sync::RwLock::new(None), dial_ms: AtomicU64::new(0) })
                    .collect(),
                rr: AtomicUsize::new(0),
            }))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let shared = Arc::new(Shared {
        psk,
        max_rtt_ms: config.max_rtt_ms,
        allow: config.allow,
        state: config.state,
        relays,
        window: mux::clamp_window(config.window_kb),
    });
    let addr = listener.local_addr()?;
    let _ = bound.send(addr);
    info!(%addr, relays = shared.relays.len(), sessions, "balance listening");
    for relay in &shared.relays {
        for index in 0..relay.slots.len() {
            tokio::spawn(keep_slot(Arc::clone(&shared), Arc::clone(relay), index));
        }
    }
    let probe = Arc::clone(&shared);
    tokio::spawn(async move { probe_loop(probe, Duration::from_secs(config.probe_secs.max(5))).await });
    while let Some((sock, peer, ticket)) = crate::reload::accept_one(&listener, &gate).await {
        if !peer.ip().is_loopback() {
            warn!(%peer, "rejected non-loopback socks client");
            drop(ticket);
            continue;
        }
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let _ticket = ticket;
            if let Err(err) = handle_socks(sock, shared).await {
                warn!(%err, "socks session failed");
            }
        });
    }
    gate.wait_idle().await;
    Ok(())
}

#[derive(serde::Deserialize)]
struct SavedRelay {
    name: String,
    bytes: u64,
}

fn load_relay_used(path: &PathBuf, name: &str, period: &str) -> u64 {
    let Ok(raw) = std::fs::read(path) else {
        return 0;
    };
    #[derive(serde::Deserialize)]
    struct File {
        period: String,
        relays: Vec<SavedRelay>,
    }
    let Ok(file) = serde_json::from_slice::<File>(&raw) else {
        return 0;
    };
    if file.period != period {
        return 0;
    }
    file.relays.into_iter().find(|item| item.name == name).map(|item| item.bytes).unwrap_or(0)
}

fn decode_pin(text: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = tlsutil::decode_hex(text).map_err(|_| anyhow::anyhow!("pin_sha256 is not hex"))?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("pin_sha256 must be 32 bytes"))
}

async fn probe_loop(shared: Arc<Shared>, every: Duration) {
    loop {
        for relay in &shared.relays {
            let started = Instant::now();
            let ok = ping_relay(&shared, relay).await.is_ok();
            let rtt = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
            *relay.up.write().await = ok;
            if ok {
                *relay.rtt_ms.write().await = Some(rtt);
            }
        }
        persist(&shared);
        tokio::time::sleep(every).await;
    }
}

/// Healthy if at least one slot answers. Each slot is pinged and redialed
/// independently; a dead slot never takes the others down.
async fn ping_relay(shared: &Shared, relay: &Live) -> anyhow::Result<()> {
    let mut last = None;
    let mut ok = false;
    for index in 0..relay.slots.len() {
        match ping_slot(shared, relay, index).await {
            Ok(()) => ok = true,
            Err(err) => {
                warn!(relay = %relay.cfg.name, slot = index, %err, "mux slot unhealthy");
                last = Some(err);
            }
        }
    }
    if ok {
        Ok(())
    } else {
        Err(last.unwrap_or_else(|| anyhow::anyhow!("no slots")))
    }
}

async fn ping_slot(shared: &Shared, relay: &Live, index: usize) -> anyhow::Result<()> {
    let session = ensure_slot(shared, relay, index).await?;
    if let Err(err) = session.ping().await {
        // A pong that misses the timeout is not proof of death: on a session
        // that is still delivering data it only means the writer had to drain
        // its queue first (1 MB send budget plus the kernel send queue on a
        // slow path). The heartbeat already declares a session dead after
        // DEAD_AFTER of silence, so replacing a busy-but-alive session only
        // leaks its socket: its data keeps flowing and its heartbeats keep it
        // alive on the relay, forever.
        if session.alive() && session.silent_for() < mux::DEAD_AFTER {
            warn!(
                relay = %relay.cfg.name,
                slot = index,
                silent_ms = session.silent_for().as_millis() as u64,
                %err,
                "pong late on a busy session, keeping it"
            );
            return Ok(());
        }
        // Really dead: drop the slot and close the socket instead of waiting
        // for FIN.
        let mut cur = relay.slots[index].current.write().unwrap();
        if cur.as_ref().is_some_and(|s| Arc::ptr_eq(s, &session)) {
            *cur = None;
        }
        drop(cur);
        session.close();
        return Err(err);
    }
    Ok(())
}

async fn ensure_slot(shared: &Shared, relay: &Live, index: usize) -> anyhow::Result<Arc<Session>> {
    let slot = &relay.slots[index];
    if let Some(session) = slot.get() {
        return Ok(session);
    }
    let _dial = slot.dial.lock().await;
    if let Some(session) = slot.get() {
        return Ok(session);
    }
    let started = Instant::now();
    let session = dial_mux_checked(&shared.psk, relay, shared.window, index).await?;
    slot.dial_ms.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
    *slot.current.write().unwrap() = Some(Arc::clone(&session));
    Ok(session)
}

/// Keeps one slot dialed: waits for the session to die (TCP error, keepalive,
/// user timeout or heartbeat silence) and redials at once, backing off only
/// while dials fail.
async fn keep_slot(shared: Arc<Shared>, relay: Arc<Live>, index: usize) {
    let mut backoff = Duration::from_millis(250);
    loop {
        match ensure_slot(&shared, &relay, index).await {
            Ok(session) => {
                backoff = Duration::from_millis(250);
                session.closed().await;
                warn!(relay = %relay.cfg.name, slot = index, "mux session died, redialing");
            }
            Err(err) => {
                warn!(relay = %relay.cfg.name, slot = index, %err, "mux dial failed");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(4));
            }
        }
    }
}

/// Spread new opens across live sessions, skipping any that already have a
/// stream while another idle session exists.
///
/// Least-loaded stacking put a whole burst on one TCP congestion window.
/// Plain round-robin still lands one of every N opens on the session that is
/// already draining a video. An idle warm session costs one RTT (~40 ms on
/// the home path); the busy one costs that plus whatever DATA is in flight.
/// Dead slots are redialed in the background.
async fn pick_session(shared: &Arc<Shared>, relay: &Arc<Live>, skip: &[Arc<Session>]) -> anyhow::Result<Arc<Session>> {
    // Freshness first (a silent session may be half dead), then the DATA still
    // waiting for that session's TLS writer, then stream count.
    //
    // Stream count alone says nothing about latency: a video stream is one
    // stream and a multi-megabyte queue. A burst has more streams than
    // sessions, so "prefer an idle session" runs out of idle sessions; the
    // remainder must not be queued behind a download.
    let n = relay.slots.len();
    // Rotation gives ties (everything idle and empty) to the next slot, so a
    // batch of parallel bulk streams still spreads across the pool.
    let start = relay.rr.fetch_add(1, Ordering::Relaxed) % n;
    // A session dialed on the slow per-flow path (dial time > 2x the best
    // live one) is only used when every fast one is busy.
    let fastest = relay
        .slots
        .iter()
        .filter(|slot| slot.get().is_some())
        .map(|slot| slot.dial_ms.load(Ordering::Relaxed))
        .min()
        .filter(|_| std::env::var("ENTRY_RANK_DIAL").map(|v| v != "0").unwrap_or(true))
        .unwrap_or(0);
    let mut best: Option<((u8, u8, u8, usize, usize), Arc<Session>)> = None;
    for step in 0..n {
        let index = (start + step) % n;
        let slot = &relay.slots[index];
        match slot.get() {
            Some(s) if skip.iter().any(|skipped| Arc::ptr_eq(skipped, &s)) => {}
            Some(s) => {
                let slow = u8::from(fastest > 0 && slot.dial_ms.load(Ordering::Relaxed) > fastest * 2);
                // A slow-route session (5x RTT) costs more than a small
                // queue on a fast one: only a real backlog (a video
                // draining) outranks the route. Prod 2026-10-21: with
                // `queued()` first, every OPEN went to the idle 218 ms
                // session while two 35 ms sessions carried light traffic.
                let backlog = u8::from(s.queued() > BACKLOG_BYTES);
                let key = (u8::from(!s.fresh()), backlog, slow, s.queued(), s.active());
                if best.as_ref().map(|(k, _)| key < *k).unwrap_or(true) {
                    best = Some((key, s));
                }
            }
            None => {
                if relay.slots[index].dial.try_lock().is_ok() {
                    let shared = Arc::clone(shared);
                    let relay = Arc::clone(relay);
                    tokio::spawn(async move {
                        if let Err(err) = ensure_slot(&shared, &relay, index).await {
                            warn!(relay = %relay.cfg.name, slot = index, %err, "mux redial failed");
                        }
                    });
                }
            }
        }
    }
    match best {
        Some((_, s)) => Ok(s),
        // Every live session already refused this attempt. Dialing slot 0
        // again would hand back that same session.
        None if !skip.is_empty() => anyhow::bail!("no other mux session"),
        None => ensure_slot(shared, relay, 0).await,
    }
}

/// Parallel dials per slot. On a per-flow ECMP path a new 5-tuple can stick
/// to a slow route for the life of the TCP, and SYNs are sometimes lost
/// (Linux initial SYN RTO is 1 s). The first finished TCP+TLS+auth handshake
/// is kept; the others are dropped.
pub const DIAL_RACE: usize = 3;

/// `ENTRY_DIAL_RACE` / `ENTRY_HEDGE_MS` override the defaults (lab A/B; 1 and 0 disable).
fn dial_race() -> usize {
    static V: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *V.get_or_init(|| std::env::var("ENTRY_DIAL_RACE").ok().and_then(|v| v.parse().ok()).unwrap_or(DIAL_RACE))
}

fn hedge_after() -> Option<Duration> {
    static V: std::sync::OnceLock<Option<Duration>> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        let ms = std::env::var("ENTRY_HEDGE_MS").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(HEDGE_AFTER.as_millis() as u64);
        (ms > 0).then(|| Duration::from_millis(ms))
    })
}

/// Default per-session path RTT above which a fresh session is dropped and
/// redialed on a new source port (the 226 ms per-flow path; 35/97 pass).
pub const RTT_REJECT_MS: u64 = 150;
/// Extra dial rounds after a slow one. Each round is itself `dial_race()` wide.
pub const RTT_RETRIES: u32 = 3;

/// `ENTRY_RTT_REJECT_MS` (0 = off) and `ENTRY_RTT_RETRIES`.
fn rtt_reject() -> (u64, u32) {
    static V: std::sync::OnceLock<(u64, u32)> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        let ms = std::env::var("ENTRY_RTT_REJECT_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(RTT_REJECT_MS);
        let n = std::env::var("ENTRY_RTT_RETRIES").ok().and_then(|v| v.parse().ok()).unwrap_or(RTT_RETRIES).min(10);
        (ms, n)
    })
}

/// Outcome of one slow-path check round, kept pure for tests.
fn keep_better(best: Option<(Arc<Session>, u64)>, next: (Arc<Session>, u64)) -> (Arc<Session>, u64) {
    match best {
        Some(b) if b.1 <= next.1 => {
            next.0.close();
            b
        }
        Some(b) => {
            b.0.close();
            next
        }
        None => next,
    }
}

/// Dial, and if the session's path RTT (handshake estimate, plus TCP_INFO
/// srtt on Linux) exceeds the threshold, redial on a fresh source port.
/// Bounded: at most 1 + retries rounds with 100/200/400.. ms backoff, only
/// under the slot's dial lock. If every round is slow (or a retry fails),
/// the best session seen is kept rather than failing the slot.
async fn dial_mux_checked(psk: &[u8], relay: &Live, window: u32, index: usize) -> anyhow::Result<Arc<Session>> {
    let (limit, retries) = rtt_reject();
    let mut best: Option<(Arc<Session>, u64)> = None;
    for round in 0..=retries {
        if round > 0 {
            tokio::time::sleep(Duration::from_millis(100 << (round - 1).min(4))).await;
        }
        match dial_mux_raced(psk, relay, window).await {
            Ok(got) => {
                let rtt = got.1;
                let b = keep_better(best.take(), got);
                if limit == 0 || rtt <= limit {
                    return Ok(b.0);
                }
                warn!(relay = %relay.cfg.name, slot = index, rtt_ms = rtt, limit_ms = limit, round, "slow path session, redialing");
                best = Some(b);
            }
            Err(err) if best.is_none() => return Err(err),
            Err(err) => {
                warn!(relay = %relay.cfg.name, slot = index, %err, "redial after slow path failed, keeping best");
                break;
            }
        }
    }
    let (session, rtt) = best.expect("at least one round succeeded");
    info!(relay = %relay.cfg.name, slot = index, rtt_ms = rtt, "all redials slow, keeping best");
    Ok(session)
}

async fn dial_mux_raced(psk: &[u8], relay: &Live, window: u32) -> anyhow::Result<(Arc<Session>, u64)> {
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..dial_race().max(1) {
        let psk = psk.to_vec();
        let cfg = relay.cfg.clone();
        let pin = relay.pin;
        set.spawn(async move { dial_mux_parts(&psk, &cfg, pin, window).await });
    }
    let mut last = None;
    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(session)) => {
                set.abort_all();
                // A loser that finished in the same instant must not leak.
                while let Some(rest) = set.join_next().await {
                    if let Ok(Ok((extra, _))) = rest {
                        extra.close();
                    }
                }
                return Ok(session);
            }
            Ok(Err(err)) => {
                if err.is::<OverQuota>() {
                    relay.used.store(relay.cfg.quota_bytes, Ordering::Relaxed);
                }
                last = Some(err)
            }
            Err(err) => last = Some(err.into()),
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("no dial attempted")))
}

/// Connect with the IPv6 flow label pinned to 0 (Linux `IPV6_AUTOFLOWLABEL`
/// off). Some networks include the flow label in the ECMP hash: automatic
/// labels re-roll the path on every new socket, retransmission, and RTO
/// (`net.core.txrehash`). With label 0 the path is a function of the ports,
/// so a session that dialed fast stays fast.
async fn connect_pinned(addr: &str) -> std::io::Result<TcpStream> {
    let mut last = None;
    for target in tokio::net::lookup_host(addr).await? {
        let socket = if target.is_ipv6() { tokio::net::TcpSocket::new_v6()? } else { tokio::net::TcpSocket::new_v4()? };
        #[cfg(target_os = "linux")]
        if target.is_ipv6() {
            let off: libc::c_int = 0;
            // SAFETY: valid fd, option value is a c_int.
            unsafe {
                use std::os::fd::AsRawFd;
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    70, // IPV6_AUTOFLOWLABEL
                    &off as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
        match socket.connect(target).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last = Some(err),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("no address")))
}

#[derive(Debug)]
struct OverQuota(String);
impl std::fmt::Display for OverQuota {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "relay {} is over quota", self.0)
    }
}
impl std::error::Error for OverQuota {}

/// Smoothed RTT of an established socket (Linux TCP_INFO), in ms.
#[cfg(target_os = "linux")]
fn tcp_srtt_ms(fd: std::os::fd::RawFd) -> Option<u64> {
    // SAFETY: tcp_info is plain data; len is its size.
    unsafe {
        let mut info: libc::tcp_info = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
        let rc = libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_INFO, &mut info as *mut _ as *mut libc::c_void, &mut len);
        (rc == 0 && info.tcpi_rtt > 0).then(|| u64::from(info.tcpi_rtt) / 1000)
    }
}

/// Returns the session and its path RTT estimate in ms: max of TCP connect
/// (1 RTT) and TLS 1.3 handshake (1 RTT), and on Linux the kernel srtt after
/// auth. A lost SYN inflates it too, which is also worth a redial.
async fn dial_mux_parts(psk: &[u8], cfg: &RelayConfig, pin: [u8; 32], window: u32) -> anyhow::Result<(Arc<Session>, u64)> {
    let t0 = Instant::now();
    let sock = timeout(Duration::from_secs(8), connect_pinned(&cfg.addr)).await??;
    let connect_ms = t0.elapsed().as_millis() as u64;
    #[cfg(target_os = "linux")]
    let fd = std::os::fd::AsRawFd::as_raw_fd(&sock);
    mux::tune(&sock);
    let connector = TlsConnector::from(client_config(pin));
    let name = ServerName::try_from(cfg.sni.clone())?;
    let t1 = Instant::now();
    let mut tls = timeout(Duration::from_secs(8), connector.connect(name, sock)).await??;
    #[allow(unused_mut)]
    let mut rtt = connect_ms.max(t1.elapsed().as_millis() as u64);
    let mut exporter = [0u8; 32];
    tls.get_ref().1.export_keying_material(&mut exporter, auth::LABEL, None)?;
    let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    tls.write_all(&auth::frame(psk, &exporter, PURPOSE_MUX2, now)).await?;
    let mut status = [0u8; 1];
    timeout(Duration::from_secs(10), tls.read_exact(&mut status)).await??;
    if status[0] == STATUS_QUOTA {
        return Err(OverQuota(cfg.name.clone()).into());
    }
    if status[0] != STATUS_OK {
        anyhow::bail!("relay {} rejected mux ({})", cfg.name, status[0]);
    }
    #[cfg(target_os = "linux")]
    if let Some(srtt) = tcp_srtt_ms(fd) {
        rtt = rtt.max(srtt);
    }
    let (read, write) = tokio::io::split(tls);
    Ok((mux::adopt(read, write, window), rtt))
}

use rustls::pki_types::ServerName;

async fn handle_socks(mut sock: TcpStream, shared: Arc<Shared>) -> anyhow::Result<()> {
    sock.set_nodelay(true)?;
    let request = match socks::accept(&mut sock).await {
        Ok(request) => request,
        Err(err) => return Err(err.into()),
    };
    if !allowed(&request, &shared.allow) {
        socks::reject(&mut sock, 0x02).await?;
        anyhow::bail!("destination {} is not allowed", endpoint(&request.host, request.port));
    }
    let mut order = choose(&shared).await;
    if order.is_empty() {
        order = shared.relays.iter().cloned().collect();
    }
    for relay in order {
        let opened_at = Instant::now();
        // One session refusing (or sitting behind a full send queue for 8s)
        // is not the relay being down. Try the other slots before telling
        // the user the destination is unreachable. `probe_loop` would flip
        // `up` back on the next ping anyway, so a single failure also made
        // the flag flap.
        let mut skipped = Vec::new();
        let attempts = relay.slots.len().max(1);
        let mut failed: Option<anyhow::Error> = None;
        for _ in 0..attempts {
            let session = match pick_session(&shared, &relay, &skipped).await {
                Ok(session) => session,
                Err(err) => {
                    failed = Some(err);
                    break;
                }
            };
            match hedged_open(&shared, &relay, &session).await {
                Ok(mut pipe) => {
                    info!(relay = %relay.cfg.name, open_ms = opened_at.elapsed().as_millis() as u64, "mux open ok");
                    socks::reply_ok(&mut sock).await?;
                    let bytes = pipe.copy(sock).await;
                    relay.used.fetch_add(bytes, Ordering::Relaxed);
                    persist(&shared);
                    info!(relay = %relay.cfg.name, bytes, open_ms = opened_at.elapsed().as_millis() as u64, "balanced session finished");
                    return Ok(());
                }
                Err(err) => {
                    warn!(relay = %relay.cfg.name, %err, "session open failed, trying another");
                    skipped.push(session);
                    failed = Some(err);
                }
            }
        }
        if let Some(err) = failed {
            warn!(relay = %relay.cfg.name, %err, "relay open failed");
        }
        *relay.up.write().await = false;
    }
    socks::reject(&mut sock, 0x05).await?;
    anyhow::bail!("no usable relay");
}

/// A quiet mux session that loses the OPEN segment waits for TLP/RTO
/// (prod: rto 243-490 ms, observed OPENs of 0.8-1.9 s on a 40 ms path).
/// If no OK arrives within HEDGE_AFTER, send a second OPEN on another session
/// and keep whichever answers first; the loser's Pipe drop sends CLOSE.
/// Queued bytes above which a session counts as busy for OPEN placement.
const BACKLOG_BYTES: usize = 256 * 1024;

pub const HEDGE_AFTER: Duration = Duration::from_millis(250);

async fn hedged_open(shared: &Arc<Shared>, relay: &Arc<Live>, first: &Arc<Session>) -> anyhow::Result<mux::Pipe> {
    let Some(hedge) = hedge_after() else { return first.open().await };
    let a = first.open();
    tokio::pin!(a);
    tokio::select! {
        res = &mut a => return res,
        _ = tokio::time::sleep(hedge) => {}
    }
    let second = match pick_session(shared, relay, std::slice::from_ref(first)).await {
        Ok(second) => second,
        Err(_) => return a.await,
    };
    let b = second.open();
    tokio::pin!(b);
    tokio::select! {
        res = &mut a => match res { Ok(p) => Ok(p), Err(_) => b.await },
        res = &mut b => match res { Ok(p) => Ok(p), Err(_) => a.await },
    }
}

async fn choose(shared: &Shared) -> Vec<Arc<Live>> {
    let mut candidates = Vec::new();
    for (index, relay) in shared.relays.iter().enumerate() {
        if !*relay.up.read().await {
            continue;
        }
        let used = relay.used.load(Ordering::Relaxed);
        let remaining = relay.cfg.quota_bytes.saturating_sub(used);
        candidates.push(Candidate {
            index,
            remaining,
            rtt_ms: *relay.rtt_ms.read().await,
        });
    }
    let Some(index) = pick(candidates, random_u64(), shared.max_rtt_ms) else {
        return Vec::new();
    };
    let mut order = vec![Arc::clone(&shared.relays[index])];
    for (other, relay) in shared.relays.iter().enumerate() {
        if other != index {
            order.push(Arc::clone(relay));
        }
    }
    order
}

fn random_u64() -> u64 {
    let mut buf = [0u8; 8];
    getrandom_u64(&mut buf);
    u64::from_ne_bytes(buf)
}

fn getrandom_u64(buf: &mut [u8; 8]) {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
    let mixed = hasher.finish();
    buf.copy_from_slice(&mixed.to_ne_bytes());
}

fn persist(shared: &Shared) {
    #[derive(serde::Serialize)]
    struct File<'a> {
        period: &'a str,
        relays: Vec<Item<'a>>,
    }
    #[derive(serde::Serialize)]
    struct Item<'a> {
        name: &'a str,
        bytes: u64,
    }
    let period = crate::usage::period_key(SystemTime::now());
    let relays = shared
        .relays
        .iter()
        .map(|relay| Item { name: &relay.cfg.name, bytes: relay.used.load(Ordering::Relaxed) })
        .collect();
    let body = serde_json::to_vec(&File { period: &period, relays }).expect("state serializes");
    if let Some(dir) = shared.state.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let tmp = shared.state.with_extension("json.tmp");
    if std::fs::write(&tmp, body).is_ok() {
        let _ = std::fs::rename(tmp, &shared.state);
    }
}
