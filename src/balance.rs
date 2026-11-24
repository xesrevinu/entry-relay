use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
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
    /// Path RTT of the current session (handshake estimate / TCP_INFO srtt).
    /// Per-flow path RTT is fixed for the life of a TCP, so this ranks sessions by path.
    dial_ms: AtomicU64,
    /// Consecutive probes where live TCP_INFO showed high loss or degraded RTT.
    bad_probes: AtomicU32,
}

/// Retransmission ratio (permille) above which a slot is deprioritized.
const LOSS_DEGRADED_PM: u64 = 50;
/// Sustained retransmission ratio (permille) above which a slot is gracefully retired.
const LOSS_RETIRE_PM: u64 = 80;

fn slot_rtt_ms(slot: &Slot, session: &Session) -> u64 {
    let live = session.live_rtt_ms();
    if live > 0 { live } else { slot.dial_ms.load(Ordering::Relaxed) }
}

fn rank_dial() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| std::env::var("ENTRY_RANK_DIAL").map(|v| v != "0").unwrap_or(true))
}

impl Slot {
    fn get(&self) -> Option<Arc<Session>> {
        self.current.read().unwrap().clone().filter(|s| s.alive())
    }
}

pub(crate) struct Shared {
    psk: Vec<u8>,
    max_rtt_ms: u32,
    allow: Vec<String>,
    state: PathBuf,
    period: std::sync::Mutex<String>,
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
                    .map(|_| Slot {
                        dial: Mutex::new(()),
                        current: std::sync::RwLock::new(None),
                        dial_ms: AtomicU64::new(0),
                        bad_probes: AtomicU32::new(0),
                    })
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
        period: std::sync::Mutex::new(period),
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
            if let Err(err) = dispatch(sock, shared).await {
                warn!(%err, "session failed");
            }
        });
    }
    gate.wait_idle().await;
    persist(&shared);
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
        probe_once(&shared).await;
        tokio::time::sleep(every).await;
    }
}

async fn probe_once(shared: &Arc<Shared>) {
    rollover_if_needed(shared, SystemTime::now());
    for relay in &shared.relays {
        match ping_relay(shared, relay).await {
            Ok(rtt) => {
                *relay.up.write().await = true;
                *relay.rtt_ms.write().await = Some(rtt);
            }
            Err(_) => {
                *relay.up.write().await = false;
            }
        }
    }
    persist(shared);
}

/// Healthy if at least one slot answers. Each slot is pinged and redialed
/// independently; a dead slot never takes the others down. Returns the lowest
/// observed path RTT across healthy slots (not the sum of sequential pings).
async fn ping_relay(shared: &Arc<Shared>, relay: &Arc<Live>) -> anyhow::Result<u32> {
    let mut last = None;
    let mut ok = false;
    let mut best_ping: Option<u32> = None;
    let mut best_dial: Option<u32> = None;
    for index in 0..relay.slots.len() {
        match ping_slot(shared, relay, index).await {
            Ok(maybe_rtt) => {
                ok = true;
                if let Some(rtt) = maybe_rtt {
                    best_ping = Some(best_ping.map_or(rtt, |b| b.min(rtt)));
                } else {
                    let dial = u32::try_from(relay.slots[index].dial_ms.load(Ordering::Relaxed)).unwrap_or(u32::MAX);
                    if dial > 0 {
                        best_dial = Some(best_dial.map_or(dial, |b| b.min(dial)));
                    }
                }
            }
            Err(err) => {
                warn!(relay = %relay.cfg.name, slot = index, %err, "mux slot unhealthy");
                last = Some(err);
            }
        }
    }
    if ok {
        Ok(best_ping.or(best_dial).unwrap_or(0))
    } else {
        Err(last.unwrap_or_else(|| anyhow::anyhow!("no slots")))
    }
}

async fn ping_slot(shared: &Arc<Shared>, relay: &Arc<Live>, index: usize) -> anyhow::Result<Option<u32>> {
    let session = ensure_slot(shared, relay, index).await?;
    let slot = &relay.slots[index];
    // Evaluate live TCP_INFO health even while streams are active: if a single
    // slot degrades into a high-loss or slow path while at least one healthy
    // sibling exists, gracefully retire it (existing streams finish intact)
    // and dial a fresh replacement in the background.
    let (limit, _) = rtt_reject();
    let live_rtt = slot_rtt_ms(slot, &session);
    let loss_pm = session.loss_permille();
    let fastest = relay
        .slots
        .iter()
        .filter_map(|s| s.get().map(|sess| (s, sess)))
        .filter(|(_, sess)| sess.loss_permille() < LOSS_DEGRADED_PM)
        .map(|(s, sess)| slot_rtt_ms(s, &sess))
        .filter(|ms| *ms > 0)
        .min()
        .unwrap_or(0);
    let cap = rtt_cap(limit, fastest);
    let degraded = loss_pm >= LOSS_RETIRE_PM || (cap > 0 && live_rtt > cap);
    let healthy_others = relay
        .slots
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != index)
        .filter_map(|(_, s)| s.get().map(|sess| (s, sess)))
        .filter(|(s, sess)| {
            sess.loss_permille() < LOSS_DEGRADED_PM && (cap == 0 || slot_rtt_ms(s, sess) <= cap)
        })
        .count();
    if degraded && healthy_others > 0 {
        let strikes = slot.bad_probes.fetch_add(1, Ordering::Relaxed) + 1;
        if strikes >= 2 {
            warn!(
                relay = %relay.cfg.name,
                slot = index,
                live_rtt_ms = live_rtt,
                loss_pm = session.local_loss_permille(),
                peer_loss_pm = session.peer_loss_permille(),
                fastest_ms = fastest,
                limit_ms = cap,
                active = session.active(),
                "degraded mux slot, retiring and redialing"
            );
            slot.bad_probes.store(0, Ordering::Relaxed);
            let mut cur = slot.current.write().unwrap();
            if cur.as_ref().is_some_and(|s| Arc::ptr_eq(s, &session)) {
                *cur = None;
            }
            drop(cur);
            session.retire_within(Duration::from_secs(20));
            let shared = Arc::clone(shared);
            let relay = Arc::clone(relay);
            tokio::spawn(async move {
                let _ = ensure_slot(&shared, &relay, index).await;
            });
            return Ok(None);
        }
    } else {
        slot.bad_probes.store(0, Ordering::Relaxed);
    }
    // OPEN/PING share the TLS writer with DATA. Waiting out a pong on a session
    // that is already copying only stalls probe_loop; liveness is the
    // heartbeat (DEAD_AFTER of inbound silence).
    if session.queued() > 0 || session.active() > 0 {
        return Ok(None);
    }
    let started = Instant::now();
    if let Err(err) = session.ping().await {
        // A pong that misses the timeout is not proof of death: on a session
        // that is still delivering data it only means the writer had to drain
        // its queue first (the send budget plus the kernel send queue on a
        // high-latency path). The heartbeat already declares a session dead after
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
            return Ok(None);
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
    let ping_rtt = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
    // Idle session stuck on a slow per-flow path: drop it so keep_slot redials.
    // Never kick while streams or queued DATA are present.
    let dial_ms = relay.slots[index].dial_ms.load(Ordering::Relaxed);
    if cap > 0 && dial_ms > cap && session.active() == 0 && session.queued() == 0 {
        warn!(
            relay = %relay.cfg.name,
            slot = index,
            dial_ms,
            fastest_ms = fastest,
            limit_ms = cap,
            "idle slow-path session, redialing"
        );
        let mut cur = relay.slots[index].current.write().unwrap();
        if cur.as_ref().is_some_and(|s| Arc::ptr_eq(s, &session)) {
            *cur = None;
        }
        drop(cur);
        session.close();
    }
    Ok(Some(ping_rtt))
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
    let (session, rtt) = dial_mux_checked(&shared.psk, relay, shared.window, index).await?;
    // Path RTT from the handshake (not wall-clock dial time): reject backoff
    // must not pollute pick_session's slow ranking.
    slot.dial_ms.store(rtt, Ordering::Relaxed);
    slot.bad_probes.store(0, Ordering::Relaxed);
    *slot.current.write().unwrap() = Some(Arc::clone(&session));
    Ok(session)
}

/// Keeps one slot dialed: waits for the session to die (TCP error, keepalive,
/// user timeout or heartbeat silence) and redials at once, backing off only
/// while dials fail.
async fn keep_slot(shared: Arc<Shared>, relay: Arc<Live>, index: usize) {
    // Stagger the first dial so later slots see a live fastest-RTT and can
    // reject a much slower path instead of all racing blind.
    if index > 0 {
        tokio::time::sleep(Duration::from_millis(80 * index as u64)).await;
    }
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
/// already draining a bulk transfer. An idle warm session costs one RTT; the
/// busy one costs that plus whatever DATA is in flight.
/// Dead slots are redialed in the background.
async fn pick_session(shared: &Arc<Shared>, relay: &Arc<Live>, skip: &[Arc<Session>]) -> anyhow::Result<Arc<Session>> {
    // Freshness first (a silent session may be half dead), then the DATA still
    // waiting for that session's TLS writer, then stream count.
    //
    // Stream count alone says nothing about latency: one bulk stream can fill
    // a multi-megabyte queue. A burst has more streams than sessions, so
    // "prefer an idle session" runs out of idle sessions; the remainder must
    // not be queued behind a download.
    let n = relay.slots.len();
    // Rotation gives ties (everything idle and empty) to the next slot, so a
    // batch of parallel bulk streams still spreads across the pool.
    let start = relay.rr.fetch_add(1, Ordering::Relaxed) % n;
    // A session on a slow per-flow path (live/dial RTT > 2x best) or with
    // elevated TCP retransmissions is only used when every healthy one is busy.
    let fastest = if rank_dial() {
        let healthy_min = relay
            .slots
            .iter()
            .filter_map(|slot| slot.get().map(|s| (slot, s)))
            .filter(|(_, s)| s.loss_permille() < LOSS_DEGRADED_PM)
            .map(|(slot, s)| slot_rtt_ms(slot, &s))
            .filter(|ms| *ms > 0)
            .min();
        healthy_min
            .or_else(|| {
                relay
                    .slots
                    .iter()
                    .filter_map(|slot| slot.get().map(|s| slot_rtt_ms(slot, &s)))
                    .filter(|ms| *ms > 0)
                    .min()
            })
            .unwrap_or(0)
    } else {
        0
    };
    let mut best: Option<((u8, u8, u8, usize, usize), Arc<Session>)> = None;
    for step in 0..n {
        let index = (start + step) % n;
        let slot = &relay.slots[index];
        match slot.get() {
            Some(s) if skip.iter().any(|skipped| Arc::ptr_eq(skipped, &s)) => {}
            Some(s) => {
                let rtt = slot_rtt_ms(slot, &s);
                let slow = (fastest > 0 && rtt > fastest * 2) || s.loss_permille() >= LOSS_DEGRADED_PM;
                // Prefer a fast path over a short queue. Putting every new OPEN
                // onto the slow sessions whenever the fast one is busy is worse:
                // a fast TCP with some data queued still beats an idle slow path.
                let key = rank_key(s.fresh(), slow, s.queued(), s.active());
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
/// to a high-latency route for the life of the TCP, and SYNs are sometimes lost.
/// The retransmit wait is long next to a low-latency path. After the first finished TCP+TLS+auth
/// handshake, a short gather window collects other finishers and the lowest
/// path RTT wins; losers are closed. `ENTRY_DIAL_GATHER_MS=0` restores
/// first-finisher-wins.
pub const DIAL_RACE: usize = 3;
/// Default gather window after the first raced dial succeeds (ms).
pub const DIAL_GATHER_MS: u64 = 80;

/// `ENTRY_DIAL_RACE` / `ENTRY_HEDGE_MS` override the defaults (lab A/B; 1 and 0 disable).
fn dial_race() -> usize {
    static V: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *V.get_or_init(|| std::env::var("ENTRY_DIAL_RACE").ok().and_then(|v| v.parse().ok()).unwrap_or(DIAL_RACE))
}

/// `ENTRY_DIAL_GATHER_MS` overrides `DIAL_GATHER_MS` (0 = first success wins).
fn dial_gather() -> Duration {
    static V: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        let ms = std::env::var("ENTRY_DIAL_GATHER_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(DIAL_GATHER_MS);
        Duration::from_millis(ms)
    })
}

fn hedge_after() -> Option<Duration> {
    static V: std::sync::OnceLock<Option<Duration>> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        let ms = std::env::var("ENTRY_HEDGE_MS").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(HEDGE_AFTER.as_millis() as u64);
        (ms > 0).then(|| Duration::from_millis(ms))
    })
}

/// Default per-session path RTT above which a fresh session is dropped and
/// redialed on a new source port. A high-latency per-flow path is rejected;
/// a low-latency path is kept.
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

/// Outcome of one slow-path / gather check, kept pure for tests. Closes the loser.
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

/// Fold raced finishers into the lowest-RTT survivor; every loser is closed.
fn gather_best(
    mut best: Option<(Arc<Session>, u64)>,
    finishers: impl IntoIterator<Item = (Arc<Session>, u64)>,
) -> Option<(Arc<Session>, u64)> {
    for next in finishers {
        best = Some(keep_better(best.take(), next));
    }
    best
}

/// Abort remaining raced dials and close any that still finished (no leak).
async fn close_race_losers(set: &mut tokio::task::JoinSet<anyhow::Result<(Arc<Session>, u64)>>) {
    set.abort_all();
    while let Some(rest) = set.join_next().await {
        if let Ok(Ok((extra, _))) = rest {
            extra.close();
        }
    }
}

/// Dial, and if the session's path RTT (handshake estimate, plus TCP_INFO
/// srtt on Linux) exceeds the threshold, redial on a fresh source port.
/// Bounded: at most 1 + retries rounds with exponential backoff, only
/// under the slot's dial lock. If every round is slow (or a retry fails),
/// the best session seen is kept rather than failing the slot.
/// Returns the kept session and its path RTT (for `slot.dial_ms`).
async fn dial_mux_checked(psk: &[u8], relay: &Live, window: u32, index: usize) -> anyhow::Result<(Arc<Session>, u64)> {
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
                let fastest = fastest_other(relay, index);
                let cap = rtt_cap(limit, fastest);
                if accept_rtt(rtt, cap) {
                    return Ok(b);
                }
                warn!(relay = %relay.cfg.name, slot = index, rtt_ms = rtt, limit_ms = cap, fastest_ms = fastest, round, "slow path session, redialing");
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
    Ok((session, rtt))
}

/// Race `dial_race()` dials. The first success starts a gather window
/// (`dial_gather()`); among finishers in that window the lowest path RTT is
/// kept via `keep_better`, and every other session is closed. Gather of 0 ms
/// keeps first-finisher-wins (abort the rest immediately).
async fn dial_mux_raced(psk: &[u8], relay: &Live, window: u32) -> anyhow::Result<(Arc<Session>, u64)> {
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..dial_race().max(1) {
        let psk = psk.to_vec();
        let cfg = relay.cfg.clone();
        let pin = relay.pin;
        set.spawn(async move { dial_mux_parts(&psk, &cfg, pin, window).await });
    }
    let mut last = None;
    let gather = dial_gather();
    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(got)) => {
                let mut finishers = vec![got];
                if !gather.is_zero() {
                    let deadline = tokio::time::Instant::now() + gather;
                    loop {
                        match tokio::time::timeout_at(deadline, set.join_next()).await {
                            Ok(Some(res)) => match res {
                                Ok(Ok(got)) => finishers.push(got),
                                Ok(Err(err)) => {
                                    if err.is::<OverQuota>() {
                                        relay.used.store(relay.cfg.quota_bytes, Ordering::Relaxed);
                                    }
                                    // Already have a finisher; gather errors only matter if
                                    // we somehow return none (we do not).
                                    let _ = err;
                                }
                                Err(_) => {}
                            },
                            Ok(None) | Err(_) => break,
                        }
                    }
                }
                close_race_losers(&mut set).await;
                return Ok(gather_best(None, finishers).expect("at least one finisher"));
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
            use std::os::fd::AsRawFd;
            mux::pin_v6_flowlabel(socket.as_raw_fd());
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
    #[cfg(target_os = "linux")]
    let session = mux::adopt_with_probe(read, write, window, move || mux::tcp_sample(fd));
    #[cfg(not(target_os = "linux"))]
    let session = mux::adopt(read, write, window);
    Ok((session, rtt))
}

use rustls::pki_types::ServerName;

async fn dispatch(sock: TcpStream, shared: Arc<Shared>) -> anyhow::Result<()> {
    let mut head = [0u8; 1];
    if sock.peek(&mut head).await? == 0 {
        return Ok(());
    }
    if head[0] == 5 {
        handle_socks(sock, shared).await
    } else {
        crate::api::serve(sock, shared).await
    }
}

impl Shared {
    /// Mux OPEN RTT on the session a SOCKS CONNECT would use.
    /// Does not fetch an external URL.
    pub(crate) async fn delay_ms(self: &Arc<Self>, budget: Duration) -> Option<u32> {
        let start = Instant::now();
        let mut order = choose(self).await;
        if order.is_empty() {
            order = self.relays.iter().cloned().collect();
        }
        for relay in order {
            let left = budget.saturating_sub(start.elapsed());
            if left.is_zero() {
                return None;
            }
            let session = match timeout(left, pick_session(self, &relay, &[])).await {
                Ok(Ok(session)) => session,
                _ => continue,
            };
            let left = budget.saturating_sub(start.elapsed());
            if left.is_zero() {
                return None;
            }
            match timeout(left, hedged_open(self, &relay, &session)).await {
                Ok(Ok(_pipe)) => return Some(start.elapsed().as_millis().max(1) as u32),
                _ => continue,
            }
        }
        None
    }

    pub(crate) async fn group_delay(self: &Arc<Self>, budget: Duration) -> Vec<(String, u32)> {
        let mut out = Vec::new();
        for live in &self.relays {
            if !*live.up.read().await {
                continue;
            }
            let start = Instant::now();
            let session = match timeout(budget, pick_session(self, live, &[])).await {
                Ok(Ok(session)) => session,
                _ => continue,
            };
            let left = budget.saturating_sub(start.elapsed());
            if left.is_zero() {
                continue;
            }
            if timeout(left, hedged_open(self, live, &session)).await.ok().and_then(|r| r.ok()).is_none() {
                continue;
            }
            out.push((live.cfg.name.clone(), start.elapsed().as_millis().max(1) as u32));
        }
        out
    }

    pub(crate) fn status_json(&self) -> String {
        let mut relays = String::from("[");
        for (i, live) in self.relays.iter().enumerate() {
            if i > 0 {
                relays.push(',');
            }
            let up = live.up.try_read().map(|g| *g).unwrap_or(false);
            let rtt = live.rtt_ms.try_read().ok().and_then(|g| *g).unwrap_or(0);
            let used = live.used.load(Ordering::Relaxed);
            let mut slots = String::from("[");
            for (j, slot) in live.slots.iter().enumerate() {
                if j > 0 {
                    slots.push(',');
                }
                let session = slot.get();
                let (alive, active, queued, live_rtt, loss_pm, peer_loss_pm) = match &session {
                    Some(s) => (
                        true,
                        s.active(),
                        s.queued(),
                        s.live_rtt_ms(),
                        s.local_loss_permille(),
                        s.peer_loss_permille(),
                    ),
                    None => (false, 0, 0, 0, 0, 0),
                };
                let dial = slot.dial_ms.load(Ordering::Relaxed);
                slots.push_str(&format!(
                    "{{\"i\":{j},\"dial_ms\":{dial},\"live_rtt_ms\":{live_rtt},\"loss_pm\":{loss_pm},\"peer_loss_pm\":{peer_loss_pm},\"alive\":{alive},\"active\":{active},\"queued\":{queued}}}"
                ));
            }
            slots.push(']');
            relays.push_str(&format!(
                "{{\"name\":\"{}\",\"up\":{up},\"rtt_ms\":{rtt},\"used\":{used},\"quota\":{},\"slots\":{slots}}}",
                live.cfg.name.replace('"', ""),
                live.cfg.quota_bytes
            ));
        }
        relays.push(']');
        format!("{{\"relays\":{relays}}}")
    }
}

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
                    rollover_if_needed(&shared, SystemTime::now());
                    relay.used.fetch_add(bytes, Ordering::Relaxed);
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

/// A quiet mux session that loses the OPEN segment waits for TLP/RTO.
/// If no OK arrives within HEDGE_AFTER, send a second OPEN on another session
/// and keep whichever answers first; the loser's Pipe drop sends CLOSE.
/// Queued bytes above which a session counts as busy for OPEN placement.
const BACKLOG_BYTES: usize = 256 * 1024;

pub const HEDGE_AFTER: Duration = Duration::from_millis(250);

fn fastest_other(relay: &Live, except: usize) -> u64 {
    relay
        .slots
        .iter()
        .enumerate()
        .filter(|(i, slot)| *i != except && slot.get().is_some())
        .map(|(_, slot)| slot.dial_ms.load(Ordering::Relaxed))
        .filter(|ms| *ms > 0)
        .min()
        .unwrap_or(0)
}

/// Absolute cap, or 2× the best already-live slot, whichever is lower.
fn rtt_cap(limit: u64, fastest_other: u64) -> u64 {
    if limit == 0 {
        0
    } else if fastest_other > 0 {
        limit.min(fastest_other.saturating_mul(2))
    } else {
        limit
    }
}

fn accept_rtt(rtt: u64, cap: u64) -> bool {
    cap == 0 || rtt <= cap
}

/// Lower is better. `slow` outranks `backlog`, so a busy fast session
/// keeps winning against an idle slow one.
fn rank_key(fresh: bool, slow: bool, queued: usize, active: usize) -> (u8, u8, u8, usize, usize) {
    (
        u8::from(!fresh),
        u8::from(slow),
        u8::from(queued > BACKLOG_BYTES),
        queued,
        active,
    )
}

async fn hedged_open(shared: &Arc<Shared>, relay: &Arc<Live>, first: &Arc<Session>) -> anyhow::Result<mux::Pipe> {
    let Some(hedge) = hedge_after() else { return first.open().await };
    // A queued writer means OPEN/OK sits behind DATA; do not wait 250 ms
    // before trying another session.
    let wait = if first.queued() > BACKLOG_BYTES / 8 { Duration::ZERO } else { hedge };
    let a = first.open();
    tokio::pin!(a);
    if !wait.is_zero() {
        tokio::select! {
            res = &mut a => return res,
            _ = tokio::time::sleep(wait) => {}
        }
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
    rollover_if_needed(shared, SystemTime::now());
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

fn rollover_if_needed(shared: &Shared, now: SystemTime) {
    let current = crate::usage::period_key(now);
    let mut period = shared.period.lock().unwrap();
    if *period != current {
        for relay in &shared.relays {
            relay.used.store(0, Ordering::Relaxed);
        }
        *period = current;
    }
}

fn persist(shared: &Shared) {
    persist_at(shared, SystemTime::now());
}

fn persist_at(shared: &Shared, now: SystemTime) {
    rollover_if_needed(shared, now);
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
    let period = shared.period.lock().unwrap().clone();
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Peer half must be kept alive: dropping it EOFs the session.
    fn dummy_session() -> (Arc<Session>, tokio::io::DuplexStream) {
        let (ours, peer) = tokio::io::duplex(64 * 1024);
        let (r, w) = tokio::io::split(ours);
        (mux::adopt(r, w, 64 * 1024), peer)
    }

    #[tokio::test]
    async fn keep_better_prefers_lower_rtt() {
        let (slow, _ps) = dummy_session();
        let (fast, _pf) = dummy_session();
        let (winner, rtt) = keep_better(Some((Arc::clone(&slow), 80)), (Arc::clone(&fast), 40));
        assert_eq!(rtt, 40);
        assert!(Arc::ptr_eq(&winner, &fast));
        assert!(!slow.alive());
        assert!(fast.alive());
        winner.close();
    }

    #[tokio::test]
    async fn keep_better_keeps_equal_incumbent() {
        let (a, _pa) = dummy_session();
        let (b, _pb) = dummy_session();
        let (winner, rtt) = keep_better(Some((Arc::clone(&a), 40)), (Arc::clone(&b), 40));
        assert_eq!(rtt, 40);
        assert!(Arc::ptr_eq(&winner, &a));
        assert!(a.alive());
        assert!(!b.alive());
        winner.close();
    }

    #[tokio::test]
    async fn gather_best_picks_lowest_and_closes_losers() {
        let (a, _pa) = dummy_session();
        let (b, _pb) = dummy_session();
        let (c, _pc) = dummy_session();
        let winner = gather_best(None, [(Arc::clone(&a), 90), (Arc::clone(&b), 35), (Arc::clone(&c), 50)]).expect("winner");
        assert_eq!(winner.1, 35);
        assert!(Arc::ptr_eq(&winner.0, &b));
        assert!(!a.alive());
        assert!(b.alive());
        assert!(!c.alive());
        winner.0.close();
    }

    fn pong_session(delay: Duration) -> Arc<Session> {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let (r, w) = tokio::io::split(ours);
        let session = mux::adopt(r, w, 64 * 1024);
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut tr, mut tw) = tokio::io::split(theirs);
            let mut hdr = [0u8; 9];
            while tr.read_exact(&mut hdr).await.is_ok() {
                let kind = hdr[0];
                let len = u32::from_be_bytes(hdr[5..9].try_into().unwrap()) as usize;
                if len > 0 {
                    let mut payload = vec![0u8; len];
                    if tr.read_exact(&mut payload).await.is_err() {
                        break;
                    }
                }
                if kind == 6 {
                    // PING -> PONG (kind 7) after simulated path RTT
                    tokio::time::sleep(delay).await;
                    let mut resp = hdr;
                    resp[0] = 7;
                    resp[5..9].copy_from_slice(&0u32.to_be_bytes());
                    if tw.write_all(&resp).await.is_err() {
                        break;
                    }
                }
            }
        });
        session
    }

    #[tokio::test]
    async fn probe_does_not_sum_sequential_slot_pings() {
        let dir = std::env::temp_dir().join(format!("entry-probe-rtt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let slots = (0..4)
            .map(|_| {
                let sess = pong_session(Duration::from_millis(40));
                Slot {
                    dial: Mutex::new(()),
                    current: std::sync::RwLock::new(Some(sess)),
                    dial_ms: AtomicU64::new(40),
                    bad_probes: AtomicU32::new(0),
                }
            })
            .collect();
        let relay = Arc::new(Live {
            cfg: RelayConfig {
                name: "relay-a".into(),
                addr: "127.0.0.1:1".into(),
                sni: "relay.example".into(),
                pin_sha256: "00".repeat(32),
                quota_bytes: 1_000_000,
            },
            pin: [0u8; 32],
            used: AtomicU64::new(0),
            rtt_ms: RwLock::new(None),
            up: RwLock::new(true),
            slots,
            rr: AtomicUsize::new(0),
        });
        let shared = Arc::new(Shared {
            psk: Vec::new(),
            max_rtt_ms: 150,
            allow: Vec::new(),
            state: dir.join("state.json"),
            period: std::sync::Mutex::new(crate::usage::period_key(SystemTime::now())),
            relays: vec![Arc::clone(&relay)],
            window: 64 * 1024,
        });
        probe_once(&shared).await;
        assert!(*relay.up.read().await);
        let rtt = relay.rtt_ms.read().await.expect("rtt recorded");
        assert!(rtt <= 150, "sequential slot pings must not be summed (got {rtt}ms)");
        let picked = pick(
            vec![Candidate { index: 0, remaining: 1_000_000, rtt_ms: Some(rtt) }],
            0,
            shared.max_rtt_ms,
        );
        assert_eq!(picked, Some(0));
        for slot in &relay.slots {
            if let Some(s) = slot.get() {
                s.close();
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rank_prefers_busy_fast_over_idle_slow() {
        let fast_busy = rank_key(true, false, BACKLOG_BYTES + 1, 5);
        let slow_idle = rank_key(true, true, 0, 0);
        assert!(fast_busy < slow_idle, "busy fast session must beat an idle slow one");
        let fast_idle = rank_key(true, false, 0, 0);
        assert!(fast_idle < fast_busy);
    }

    #[test]
    fn relative_rtt_cap_rejects_slow_once_fast_exists() {
        assert!(accept_rtt(98, rtt_cap(150, 0)));
        assert!(!accept_rtt(98, rtt_cap(150, 38)));
        assert!(accept_rtt(38, rtt_cap(150, 38)));
        assert!(accept_rtt(226, 0));
        assert!(!accept_rtt(226, rtt_cap(150, 0)));
    }

    #[test]
    fn monthly_rollover_resets_used_and_persists_new_period() {
        let dir = std::env::temp_dir().join(format!("entry-rollover-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = dir.join("state.json");
        let oct = std::time::UNIX_EPOCH + Duration::from_secs(1_792_000_000);
        let nov = oct + Duration::from_secs(32 * 86_400);
        let oct_key = crate::usage::period_key(oct);
        let nov_key = crate::usage::period_key(nov);
        assert_ne!(oct_key, nov_key);
        let relay = Arc::new(Live {
            cfg: RelayConfig {
                name: "relay-a".into(),
                addr: "127.0.0.1:1".into(),
                sni: "relay.example".into(),
                pin_sha256: "00".repeat(32),
                quota_bytes: 1_000_000,
            },
            pin: [0u8; 32],
            used: AtomicU64::new(750_000),
            rtt_ms: RwLock::new(Some(40)),
            up: RwLock::new(true),
            slots: Vec::new(),
            rr: AtomicUsize::new(0),
        });
        let shared = Shared {
            psk: Vec::new(),
            max_rtt_ms: 150,
            allow: Vec::new(),
            state: state.clone(),
            period: std::sync::Mutex::new(oct_key),
            relays: vec![Arc::clone(&relay)],
            window: 64 * 1024,
        };
        persist_at(&shared, nov);
        assert_eq!(relay.used.load(Ordering::Relaxed), 0);
        assert_eq!(*shared.period.lock().unwrap(), nov_key);
        assert_eq!(load_relay_used(&state, "relay-a", &nov_key), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
