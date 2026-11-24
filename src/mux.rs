//! Many upstream streams over one already-open TLS session (mux protocol v2).
//!
//! Frame: kind u8 | stream id u32 BE | payload len u32 BE | payload.
//!
//! Flow control, per stream and per direction:
//! * The sender starts with `BASE_CREDIT` bytes. The receiver immediately
//!   grants `window - BASE_CREDIT` more, so each side picks its own receive
//!   window (default 4 MiB, enough for ~160 Mbps at 200 ms RTT).
//! * The receiver returns credit (WINDOW frame) only after the bytes were
//!   written to the local socket, batched in steps of `window / 8`.
//! * The session reader never blocks on a stream: inbound queues are
//!   unbounded but credit caps them; a peer that overruns its credit gets
//!   the stream closed.
//!
//! Ordering: OPEN/OK/FAIL/WINDOW/PING/PONG go on the control queue. The TLS
//! writer drains that queue before every further data frame and again before
//! flush, so a saturated session cannot leave a new OPEN behind a batch of
//! DATA (one extra RTT, or several, when the link is slower than the readers).
//! CLOSE goes on the data queue so it can never overtake data of the same
//! stream. Data in flight to the TLS writer is capped by a byte budget so a
//! slow TLS link pushes back on the sockets.
//!
//! v2 is negotiated with `PURPOSE_MUX2`; an old relay answers with the decoy
//! and an old balance gets the decoy from a new relay, so a mixed pair fails
//! fast instead of stalling. Upgrade both ends together.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

const HEADER: usize = 9;
/// Header + payload fits one 16 KiB TLS record.
const MAX_PAYLOAD: usize = 16 * 1024 - HEADER;
const BASE_CREDIT: u32 = 256 * 1024;
pub const DEFAULT_WINDOW: u32 = 4 * 1024 * 1024;
/// Bytes of DATA allowed between the stream readers and the TLS writer.
const SEND_BUDGET: usize = 1024 * 1024;
const BATCH: usize = 256 * 1024;
/// Socket read size per syscall on the stream side.
const READ_CHUNK: usize = 64 * 1024;
const OPEN: u8 = 1;
const OK: u8 = 2;
const FAIL: u8 = 3;
const DATA: u8 = 4;
const CLOSE: u8 = 5;
const PING: u8 = 6;
const PONG: u8 = 7;
const WINDOW: u8 = 8;

fn header(kind: u8, id: u32, len: usize) -> [u8; HEADER] {
    let mut h = [0u8; HEADER];
    h[0] = kind;
    h[1..5].copy_from_slice(&id.to_be_bytes());
    h[5..9].copy_from_slice(&(len as u32).to_be_bytes());
    h
}

fn encode(kind: u8, id: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER + payload.len());
    frame.extend_from_slice(&header(kind, id, payload.len()));
    frame.extend_from_slice(payload);
    frame
}

fn encode_window(id: u32, n: u32) -> Vec<u8> {
    encode(WINDOW, id, &n.to_be_bytes())
}

/// Keepalive probes start after this much idle time.
pub const KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
pub const KEEPALIVE_RETRIES: u32 = 3;
/// Unacked data older than this kills the socket (Linux TCP_USER_TIMEOUT).
pub const USER_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap unsent kernel TCP buffer so OPEN/PING control frames never sit behind
/// megabytes of queued DATA on the mux socket (Linux TCP_NOTSENT_LOWAT).
pub const NOTSENT_LOWAT: u32 = 128 * 1024;
/// Client heartbeat: a PING every HEARTBEAT; no inbound frame for DEAD_AFTER
/// means the session is gone even if TCP has not noticed yet.
const HEARTBEAT: Duration = Duration::from_secs(2);
pub const DEAD_AFTER: Duration = Duration::from_secs(8);
/// Silent longer than this: still alive, but new streams avoid it.
const STALE_AFTER: Duration = Duration::from_millis(4500);
/// Server side: a balance pings every HEARTBEAT (old ones every probe_secs);
/// a session silent this long is dropped.
const SERVER_IDLE: Duration = Duration::from_secs(90);

/// Pin IPv6 flow label to 0 and disable kernel TX rehash on RTO/loss.
/// On per-flow ECMP paths, default auto_flowlabels=1 + txrehash=1 re-rolls
/// the flow label on packet loss and can trap a mux socket on a high-loss path.
#[cfg(target_os = "linux")]
pub fn pin_v6_flowlabel(fd: std::os::fd::RawFd) {
    let off: libc::c_int = 0;
    // SAFETY: valid fd, option value is a c_int.
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_AUTOFLOWLABEL,
            &off as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            const SO_TXREHASH: libc::c_int = 74;
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_TXREHASH,
                &off as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
}

/// Live kernel TCP_INFO snapshot for slot health monitoring.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpSample {
    pub srtt_ms: u64,
    pub total_retrans: u32,
    pub segs_out: u32,
}

#[cfg(target_os = "linux")]
pub fn tcp_sample(fd: std::os::fd::RawFd) -> Option<TcpSample> {
    // SAFETY: tcp_info is plain data; len is its size.
    unsafe {
        let mut info: libc::tcp_info = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            &mut info as *mut _ as *mut libc::c_void,
            &mut len,
        );
        (rc == 0 && info.tcpi_rtt > 0).then(|| TcpSample {
            srtt_ms: u64::from(info.tcpi_rtt) / 1000,
            total_retrans: info.tcpi_total_retrans,
            segs_out: info.tcpi_segs_out,
        })
    }
}

/// TCP_NODELAY, keepalive, TCP_USER_TIMEOUT, TCP_NOTSENT_LOWAT, and IPv6
/// flowlabel pinning. Socket buffers are left to kernel autotuning: a fixed
/// SO_RCVBUF/SO_SNDBUF disables it and caps the whole session at buf/RTT.
pub fn tune(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let sock = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL)
        .with_retries(KEEPALIVE_RETRIES);
    let _ = sock.set_tcp_keepalive(&ka);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let _ = sock.set_tcp_user_timeout(Some(USER_TIMEOUT));
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let fd = stream.as_raw_fd();
        let lowat: libc::c_uint = NOTSENT_LOWAT;
        // SAFETY: valid fd, option value is a u32.
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_NOTSENT_LOWAT,
                &lowat as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
            );
        }
        let is_v6 = stream.local_addr().is_ok_and(|a| a.is_ipv6())
            || stream.peer_addr().is_ok_and(|a| a.is_ipv6());
        if is_v6 {
            pin_v6_flowlabel(fd);
        }
    }
}

pub fn clamp_window(kb: Option<u32>) -> u32 {
    kb.map(|kb| kb.saturating_mul(1024)).unwrap_or(DEFAULT_WINDOW).clamp(BASE_CREDIT, 1 << 30)
}

struct Credit {
    left: AtomicU64,
    closed: AtomicBool,
    wake: Notify,
}

impl Credit {
    fn new(n: u32) -> Arc<Self> {
        Arc::new(Self { left: AtomicU64::new(n as u64), closed: AtomicBool::new(false), wake: Notify::new() })
    }

    /// Reserve between 1 and `want` bytes. None once the stream is gone.
    async fn take_upto(&self, want: usize) -> Option<usize> {
        loop {
            let notified = self.wake.notified();
            if self.closed.load(Ordering::Acquire) {
                return None;
            }
            let left = self.left.load(Ordering::Acquire);
            if left > 0 {
                let k = left.min(want as u64);
                if self.left.compare_exchange(left, left - k, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                    return Some(k as usize);
                }
                continue;
            }
            notified.await;
        }
    }

    /// Returns false if the grant would overflow (protocol violation).
    fn grant(&self, n: u64) -> bool {
        let ok = self
            .left
            .try_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(n).filter(|s| *s <= 1 << 32))
            .is_ok();
        self.wake.notify_waiters();
        ok
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.wake.notify_waiters();
    }
}

struct Entry {
    tx: mpsc::UnboundedSender<Bytes>,
    credit: Arc<Credit>,
    /// Bytes received but not yet written to the local socket.
    inflight: Arc<AtomicU64>,
}

type DataFrame = (Vec<u8>, Option<OwnedSemaphorePermit>);

struct Shared {
    ctrl: mpsc::UnboundedSender<Vec<u8>>,
    data: mpsc::UnboundedSender<DataFrame>,
    budget: Arc<Semaphore>,
    /// Total permits in `budget` (for `queued()`).
    budget_size: usize,
    streams: Mutex<HashMap<u32, Entry>>,
    pending: Mutex<HashMap<u32, oneshot::Sender<bool>>>,
    pongs: Mutex<HashMap<u32, oneshot::Sender<()>>>,
    alive: AtomicBool,
    retire: AtomicBool,
    dead: Notify,
    born: std::time::Instant,
    /// Millis since `born` of the last inbound frame.
    last_rx: AtomicU64,
    /// Live TCP_INFO smoothed RTT in ms (0 if unavailable).
    live_rtt_ms: AtomicU64,
    /// Local (upload) EWMA retransmission ratio in permille (0..1000).
    loss_pm: AtomicU64,
    /// Peer-reported (download) EWMA retransmission ratio in permille (0..1000).
    peer_loss_pm: AtomicU64,
    window: u32,
}

impl Shared {
    fn new(window: u32) -> (Arc<Self>, mpsc::UnboundedReceiver<Vec<u8>>, mpsc::UnboundedReceiver<DataFrame>) {
        let (ctrl, ctrl_rx) = mpsc::unbounded_channel();
        let (data, data_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Self {
            ctrl,
            data,
            budget: Arc::new(Semaphore::new(SEND_BUDGET)),
            budget_size: SEND_BUDGET,
            streams: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            pongs: Mutex::new(HashMap::new()),
            alive: AtomicBool::new(true),
            retire: AtomicBool::new(false),
            dead: Notify::new(),
            born: std::time::Instant::now(),
            last_rx: AtomicU64::new(0),
            live_rtt_ms: AtomicU64::new(0),
            loss_pm: AtomicU64::new(0),
            peer_loss_pm: AtomicU64::new(0),
            window,
        });
        (shared, ctrl_rx, data_rx)
    }

    fn ctrl(&self, frame: Vec<u8>) {
        let _ = self.ctrl.send(frame);
    }

    /// CLOSE rides the data queue so it lands after the stream's data.
    fn close_frame(&self, id: u32) {
        let _ = self.data.send((encode(CLOSE, id, &[]), None));
    }

    fn insert(&self, id: u32) -> (mpsc::UnboundedReceiver<Bytes>, Arc<Credit>, Arc<AtomicU64>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let credit = Credit::new(BASE_CREDIT);
        let inflight = Arc::new(AtomicU64::new(0));
        self.streams
            .lock()
            .unwrap()
            .insert(id, Entry { tx, credit: Arc::clone(&credit), inflight: Arc::clone(&inflight) });
        (rx, credit, inflight)
    }

    fn remove(&self, id: u32) {
        if let Some(entry) = self.streams.lock().unwrap().remove(&id) {
            entry.credit.close();
        }
    }

    fn announce_window(&self, id: u32) {
        if self.window > BASE_CREDIT {
            self.ctrl(encode_window(id, self.window - BASE_CREDIT));
        }
    }

    fn touch(&self) {
        self.last_rx.store(self.born.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    fn silent_for(&self) -> Duration {
        let last = self.last_rx.load(Ordering::Relaxed);
        self.born.elapsed().saturating_sub(Duration::from_millis(last))
    }

    fn shutdown(&self) {
        self.alive.store(false, Ordering::Release);
        self.dead.notify_waiters();
        self.dead.notify_one();
        self.budget.close();
        for (_, entry) in self.streams.lock().unwrap().drain() {
            entry.credit.close();
        }
        for (_, tx) in self.pending.lock().unwrap().drain() {
            let _ = tx.send(false);
        }
        self.pongs.lock().unwrap().clear();
    }
}

/// One accepted stream. Dropping it asks the relay to close the upstream.
pub struct Pipe {
    id: u32,
    rx: Option<mpsc::UnboundedReceiver<Bytes>>,
    credit: Arc<Credit>,
    inflight: Arc<AtomicU64>,
    shared: Arc<Shared>,
    active: Arc<AtomicUsize>,
}

impl Drop for Pipe {
    fn drop(&mut self) {
        let prev = self.active.fetch_sub(1, Ordering::AcqRel);
        if self.rx.is_some() {
            self.shared.close_frame(self.id);
            self.shared.remove(self.id);
        }
        if prev == 1 && self.shared.retire.load(Ordering::Acquire) {
            self.shared.shutdown();
        }
    }
}

impl Pipe {
    pub async fn copy(&mut self, sock: TcpStream) -> u64 {
        let mut rx = self.rx.take().expect("pipe copied once");
        let total = splice_socket(sock, &mut rx, &self.shared, &self.credit, &self.inflight, self.id).await;
        self.shared.remove(self.id);
        self.shared.close_frame(self.id);
        total
    }
}

/// Client side of a warm mux session.
pub struct Session {
    shared: Arc<Shared>,
    next_id: AtomicU32,
    next_ping: AtomicU32,
    active: Arc<AtomicUsize>,
}

impl Drop for Session {
    /// Last handle gone (e.g. a dial future cancelled mid-reject): nobody can
    /// open on it any more, so close it unless streams are still copying.
    fn drop(&mut self) {
        if self.active() == 0 {
            self.shared.shutdown();
        }
    }
}

struct MapGuard<'a, V> {
    map: &'a Mutex<HashMap<u32, V>>,
    id: u32,
}

impl<V> Drop for MapGuard<'_, V> {
    fn drop(&mut self) {
        self.map.lock().unwrap().remove(&self.id);
    }
}

impl Session {
    pub fn alive(&self) -> bool {
        self.shared.alive.load(Ordering::Acquire)
    }

    /// Resolves once the session is dead.
    pub async fn closed(&self) {
        loop {
            let notified = self.shared.dead.notified();
            if !self.alive() {
                return;
            }
            notified.await;
        }
    }

    /// Heard from the peer within STALE_AFTER (a pong is due every HEARTBEAT).
    pub fn fresh(&self) -> bool {
        self.alive() && self.shared.silent_for() < STALE_AFTER
    }

    /// Time since the last inbound frame from the peer.
    pub fn silent_for(&self) -> Duration {
        self.shared.silent_for()
    }

    /// Tear the session down now (used when a slot is replaced).
    pub fn close(&self) {
        self.shared.shutdown()
    }

    /// Gracefully retire this session: stop accepting new streams and close
    /// the TCP transport as soon as the last active stream finishes (or now if
    /// already idle).
    pub fn retire(&self) {
        self.retire_within(Duration::ZERO);
    }

    /// Like `retire()`, but also caps how long long-lived tunnels (e.g. HTTP/2
    /// streams) may linger on a degraded TCP socket before forcing shutdown.
    pub fn retire_within(&self, grace: Duration) {
        self.shared.retire.store(true, Ordering::Release);
        if self.active() == 0 {
            self.shared.shutdown();
            return;
        }
        if !grace.is_zero() {
            let shared = Arc::clone(&self.shared);
            tokio::spawn(async move {
                tokio::select! {
                    _ = wait_dead(&shared) => {}
                    _ = tokio::time::sleep(grace) => {
                        if shared.alive.load(Ordering::Acquire) {
                            tracing::warn!(grace_ms = grace.as_millis() as u64, "retired degraded session grace elapsed, closing");
                            shared.shutdown();
                        }
                    }
                }
            });
        }
    }

    /// Live TCP_INFO smoothed RTT in ms (0 if unavailable).
    pub fn live_rtt_ms(&self) -> u64 {
        self.shared.live_rtt_ms.load(Ordering::Relaxed)
    }

    /// Worst of local (upload) and peer-reported (download) retransmission
    /// ratio in permille (0..1000).
    pub fn loss_permille(&self) -> u64 {
        self.local_loss_permille().max(self.peer_loss_permille())
    }

    /// Local (upload) retransmission ratio in permille (0..1000).
    pub fn local_loss_permille(&self) -> u64 {
        self.shared.loss_pm.load(Ordering::Relaxed)
    }

    /// Peer-reported (download) retransmission ratio in permille (0..1000).
    pub fn peer_loss_permille(&self) -> u64 {
        self.shared.peer_loss_pm.load(Ordering::Relaxed)
    }

    /// DATA bytes accepted from stream readers but not yet handed to the TLS
    /// writer. This is the queue that an OPEN/OK frame has to wait behind.
    pub fn queued(&self) -> usize {
        self.shared.budget_size.saturating_sub(self.shared.budget.available_permits())
    }

    /// Streams currently open on this session.
    pub fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    pub async fn open(&self) -> anyhow::Result<Pipe> {
        if !self.alive() {
            anyhow::bail!("mux session is dead");
        }
        let id = self.next_id.fetch_add(2, Ordering::Relaxed);
        let (ack_tx, ack_rx) = oneshot::channel();
        self.shared.pending.lock().unwrap().insert(id, ack_tx);
        let _pending_guard = MapGuard { map: &self.shared.pending, id };
        let (rx, credit, inflight) = self.shared.insert(id);
        self.active.fetch_add(1, Ordering::Relaxed);
        let mut pipe = Pipe {
            id,
            rx: Some(rx),
            credit,
            inflight,
            shared: Arc::clone(&self.shared),
            active: Arc::clone(&self.active),
        };
        self.shared.ctrl(encode(OPEN, id, &[]));
        self.shared.announce_window(id);
        let res = timeout(Duration::from_secs(8), ack_rx).await;
        let ok = match res {
            Ok(Ok(ok)) => ok,
            Ok(Err(_)) => false,
            Err(_) => anyhow::bail!("mux open timed out"),
        };
        if !ok {
            // Relay already dropped it; no CLOSE needed.
            pipe.rx = None;
            self.shared.remove(id);
            anyhow::bail!("relay refused stream {id}");
        }
        Ok(pipe)
    }

    pub async fn ping(&self) -> anyhow::Result<()> {
        let id = self.next_ping.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.shared.pongs.lock().unwrap().insert(id, tx);
        let _pong_guard = MapGuard { map: &self.shared.pongs, id };
        self.shared.ctrl(encode(PING, id, &[]));
        let res = timeout(Duration::from_secs(5), rx).await;
        res?.map_err(|_| anyhow::anyhow!("ping failed"))?;
        Ok(())
    }
}

pub fn adopt<R, W>(read: R, write: W, window: u32) -> Arc<Session>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    adopt_with_probe(read, write, window, || None)
}

pub fn adopt_with_probe<R, W, F>(read: R, write: W, window: u32, probe: F) -> Arc<Session>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    F: Fn() -> Option<TcpSample> + Send + 'static,
{
    let (shared, ctrl_rx, data_rx) = Shared::new(window);
    LIVE_SESSIONS.fetch_add(1, Ordering::Relaxed);
    let session = Arc::new(Session {
        shared: Arc::clone(&shared),
        next_id: AtomicU32::new(1),
        next_ping: AtomicU32::new(1),
        active: Arc::new(AtomicUsize::new(0)),
    });
    tokio::spawn(async move {
        tokio::select! {
            _ = write_loop(write, ctrl_rx, data_rx) => {}
            _ = read_loop(read, Arc::clone(&shared), None) => {}
            _ = heartbeat(&shared, probe) => {
                tracing::warn!(silent_ms = shared.silent_for().as_millis() as u64, "mux session silent, dropping");
            }
            // `Session::close()` (slot replaced, slow-path reject, race
            // loser): stop the loops so the TLS halves drop and the TCP
            // closes. Without this branch a closed session kept its socket
            // and heartbeat alive forever.
            _ = wait_dead(&shared) => {}
        }
        shared.shutdown();
        LIVE_SESSIONS.fetch_sub(1, Ordering::Relaxed);
    });
    session
}

/// Server mux. `used` counts bytes copied to and from the upstream.
pub async fn serve<S>(tls: S, upstream: String, used: Arc<AtomicU64>, window: u32) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_with_probe(tls, upstream, used, window, || None).await
}

/// Server mux with a Linux TCP_INFO sampler whose `(segs_out, total_retrans)`
/// counters are piggybacked on PONG frames so clients detect download-path loss.
pub async fn serve_with_probe<S, F>(
    tls: S,
    upstream: String,
    used: Arc<AtomicU64>,
    window: u32,
    probe: F,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn() -> Option<TcpSample> + Send + Sync + 'static,
{
    let (read, write) = tokio::io::split(tls);
    let (shared, ctrl_rx, data_rx) = Shared::new(window);
    let server = Server { upstream, used, probe: Box::new(probe) };
    tokio::select! {
        _ = write_loop(write, ctrl_rx, data_rx) => {}
        _ = read_loop(read, Arc::clone(&shared), Some(&server)) => {}
    }
    // Drops every stream: upstream sockets close instead of lingering.
    shared.shutdown();
    Ok(())
}

/// Client sessions whose I/O task (and so TCP socket) is still running.
static LIVE_SESSIONS: AtomicUsize = AtomicUsize::new(0);

/// Client mux sessions whose socket is still open (tests, leak checks).
pub fn live_sessions() -> usize {
    LIVE_SESSIONS.load(Ordering::Relaxed)
}

async fn wait_dead(shared: &Shared) {
    loop {
        let notified = shared.dead.notified();
        if !shared.alive.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

struct LossTracker {
    prev: Option<(u32, u32)>,
    ewma_pm: u64,
}

impl LossTracker {
    fn new() -> Self {
        Self { prev: None, ewma_pm: 0 }
    }

    fn record(&mut self, segs_out: u32, total_retrans: u32) -> u64 {
        if let Some((p_segs, p_ret)) = self.prev {
            let d_segs = u64::from(segs_out.wrapping_sub(p_segs));
            let d_ret = u64::from(total_retrans.wrapping_sub(p_ret));
            if d_segs >= 8 {
                let inst = (d_ret.saturating_mul(1000) / d_segs).min(1000);
                self.ewma_pm = (self.ewma_pm * 3 + inst) / 4;
                self.prev = Some((segs_out, total_retrans));
            } else if d_segs >= 2 && d_ret == 0 {
                self.ewma_pm = (self.ewma_pm * 3) / 4;
                self.prev = Some((segs_out, total_retrans));
            }
        } else {
            self.prev = Some((segs_out, total_retrans));
        }
        self.ewma_pm
    }
}

/// Sends PING (id 0, pong ignored), refreshes live TCP_INFO telemetry, and
/// returns once nothing arrived for DEAD_AFTER.
async fn heartbeat<F>(shared: &Shared, probe: F)
where
    F: Fn() -> Option<TcpSample>,
{
    let mut loss = LossTracker::new();
    loop {
        tokio::time::sleep(HEARTBEAT).await;
        if let Some(sample) = probe() {
            shared.live_rtt_ms.store(sample.srtt_ms, Ordering::Relaxed);
            let pm = loss.record(sample.segs_out, sample.total_retrans);
            shared.loss_pm.store(pm, Ordering::Relaxed);
        }
        if shared.silent_for() >= DEAD_AFTER {
            return;
        }
        shared.ctrl(encode(PING, 0, &[]));
    }
}

struct Server {
    upstream: String,
    used: Arc<AtomicU64>,
    probe: Box<dyn Fn() -> Option<TcpSample> + Send + Sync>,
}

async fn write_loop<W>(
    write: W,
    mut ctrl_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    mut data_rx: mpsc::UnboundedReceiver<DataFrame>,
) where
    W: AsyncWrite + Unpin,
{
    let mut write = BufWriter::with_capacity(BATCH, write);
    loop {
        let mut batch = 0usize;
        let mut saw_ctrl = false;
        tokio::select! {
            biased;
            frame = ctrl_rx.recv() => {
                let Some(frame) = frame else { break };
                batch += frame.len();
                saw_ctrl = true;
                if write.write_all(&frame).await.is_err() { break; }
            }
            frame = data_rx.recv() => {
                let Some((frame, _permit)) = frame else { break };
                batch += frame.len();
                if write.write_all(&frame).await.is_err() { break; }
            }
        }
        // Control frames that arrived while the frame above was being written
        // go out before any further DATA. Otherwise OPEN/PING sit behind up to
        // BATCH bytes on a session that already has a fat stream.
        loop {
            match ctrl_rx.try_recv() {
                Ok(frame) => {
                    batch += frame.len();
                    saw_ctrl = true;
                    if write.write_all(&frame).await.is_err() {
                        return;
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => return,
            }
        }
        // OPEN/OK/PING must not share a TLS record with 256 KB of DATA.
        // Under load that delay was 2–6 s and x.com hung after CONNECT.
        if saw_ctrl {
            if write.flush().await.is_err() {
                break;
            }
            continue;
        }
        while batch < BATCH {
            if let Ok((frame, _permit)) = data_rx.try_recv() {
                batch += frame.len();
                if write.write_all(&frame).await.is_err() {
                    return;
                }
                loop {
                    match ctrl_rx.try_recv() {
                        Ok(frame) => {
                            batch += frame.len();
                            if write.write_all(&frame).await.is_err() {
                                return;
                            }
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => return,
                    }
                }
            } else {
                break;
            }
        }
        if write.flush().await.is_err() {
            break;
        }
    }
    let _ = write.shutdown().await;
}

async fn read_loop<R>(mut read: R, shared: Arc<Shared>, server: Option<&Server>)
where
    R: AsyncRead + Unpin,
{
    // Zero-copy BytesMut buffer: avoids intermediate BufReader/tmp copies and
    // O(N) Vec::drain shifts on every 16 KiB frame.
    let mut buf = BytesMut::with_capacity(64 * 1024);
    let mut peer_loss = LossTracker::new();
    let limit = shared.window as u64 + MAX_PAYLOAD as u64;
    loop {
        while buf.len() < HEADER {
            if buf.capacity() - buf.len() < 16 * 1024 {
                buf.reserve(64 * 1024);
            }
            let n = if server.is_some() {
                match timeout(SERVER_IDLE, read.read_buf(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => n,
                    _ => return,
                }
            } else {
                match read.read_buf(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => return,
                }
            };
            let _ = n;
        }
        let kind = buf[0];
        let id = u32::from_be_bytes(buf[1..5].try_into().unwrap());
        let len = u32::from_be_bytes(buf[5..9].try_into().unwrap()) as usize;
        if len > 16 * 1024 {
            break;
        }
        while buf.len() < HEADER + len {
            if buf.capacity() - buf.len() < 16 * 1024 {
                buf.reserve(64 * 1024);
            }
            match read.read_buf(&mut buf).await {
                Ok(n) if n > 0 => {}
                _ => return,
            }
        }
        shared.touch();
        let _ = buf.split_to(HEADER);
        let payload = if len > 0 { buf.split_to(len).freeze() } else { Bytes::new() };
        match kind {
            DATA => {
                let mut overrun = false;
                {
                    let streams = shared.streams.lock().unwrap();
                    if let Some(entry) = streams.get(&id) {
                        let now = entry.inflight.fetch_add(len as u64, Ordering::AcqRel) + len as u64;
                        if now > limit {
                            overrun = true;
                        } else {
                            let _ = entry.tx.send(payload);
                        }
                    }
                }
                if overrun {
                    shared.remove(id);
                    shared.close_frame(id);
                }
            }
            WINDOW => {
                if payload.len() == 4 {
                    let n = u32::from_be_bytes(payload.as_ref().try_into().unwrap());
                    let credit = shared.streams.lock().unwrap().get(&id).map(|e| Arc::clone(&e.credit));
                    if let Some(credit) = credit {
                        if !credit.grant(n as u64) {
                            shared.remove(id);
                            shared.close_frame(id);
                        }
                    }
                }
            }
            CLOSE => {
                // Dropping the sender lets the writer drain what is queued.
                shared.remove(id);
            }
            PING => {
                // Optionally attach 8 bytes of server-side TCP_INFO counters
                // (segs_out u32 BE | total_retrans u32 BE). Backward compatible:
                // older clients ignore PONG payload bytes.
                if let Some(sample) = server.and_then(|s| (s.probe)()) {
                    let mut stats = [0u8; 8];
                    stats[0..4].copy_from_slice(&sample.segs_out.to_be_bytes());
                    stats[4..8].copy_from_slice(&sample.total_retrans.to_be_bytes());
                    shared.ctrl(encode(PONG, id, &stats));
                } else {
                    shared.ctrl(encode(PONG, id, &[]));
                }
            }
            PONG => {
                if payload.len() == 8 {
                    let segs_out = u32::from_be_bytes(payload[0..4].try_into().unwrap());
                    let total_retrans = u32::from_be_bytes(payload[4..8].try_into().unwrap());
                    let pm = peer_loss.record(segs_out, total_retrans);
                    shared.peer_loss_pm.store(pm, Ordering::Relaxed);
                }
                if let Some(tx) = shared.pongs.lock().unwrap().remove(&id) {
                    let _ = tx.send(());
                }
            }
            OK | FAIL => {
                if let Some(tx) = shared.pending.lock().unwrap().remove(&id) {
                    let _ = tx.send(kind == OK);
                }
            }
            OPEN => {
                if let Some(server) = server {
                    // Register now so an early WINDOW from the client lands.
                    let (rx, credit, inflight) = shared.insert(id);
                    let shared = Arc::clone(&shared);
                    let upstream = server.upstream.clone();
                    let used = Arc::clone(&server.used);
                    tokio::spawn(open_upstream(id, upstream, shared, rx, credit, inflight, used));
                }
            }
            _ => {}
        }
    }
}

async fn open_upstream(
    id: u32,
    upstream: String,
    shared: Arc<Shared>,
    mut rx: mpsc::UnboundedReceiver<Bytes>,
    credit: Arc<Credit>,
    inflight: Arc<AtomicU64>,
    used: Arc<AtomicU64>,
) {
    let stream = match timeout(Duration::from_secs(8), TcpStream::connect(&upstream)).await {
        Ok(Ok(stream)) => stream,
        _ => {
            shared.remove(id);
            shared.ctrl(encode(FAIL, id, &[]));
            return;
        }
    };
    tune(&stream);
    shared.ctrl(encode(OK, id, &[]));
    shared.announce_window(id);
    let total = splice_socket(stream, &mut rx, &shared, &credit, &inflight, id).await;
    used.fetch_add(total, Ordering::Relaxed);
    shared.remove(id);
    shared.close_frame(id);
}

/// Copy until either direction finishes, then drop the socket.
async fn splice_socket(
    sock: TcpStream,
    rx: &mut mpsc::UnboundedReceiver<Bytes>,
    shared: &Arc<Shared>,
    credit: &Credit,
    inflight: &AtomicU64,
    id: u32,
) -> u64 {
    let (mut reader, mut writer) = sock.into_split();
    let read_total = AtomicU64::new(0);
    let write_total = AtomicU64::new(0);
    let step = (shared.window / 8).max(64 * 1024) as u64;
    let read_side = async {
        // Read up to READ_CHUNK per syscall, then acquire send-budget permits
        // only for the bytes actually read. Acquiring before `reader.read`
        // would pin 64 KiB per idle stream, starving SEND_BUDGET at 16 idle
        // streams and falsely inflating Session::queued() for hedged_open.
        let mut tmp = vec![0u8; READ_CHUNK];
        loop {
            let Some(want) = credit.take_upto(READ_CHUNK).await else { break };
            let n = match reader.read(&mut tmp[..want]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if n < want {
                credit.grant((want - n) as u64);
            }
            let Ok(permit) = Arc::clone(&shared.budget).acquire_many_owned(n as u32).await else {
                break;
            };
            let frames = n.div_ceil(MAX_PAYLOAD);
            let mut buf = Vec::with_capacity(n + frames * HEADER);
            for chunk in tmp[..n].chunks(MAX_PAYLOAD) {
                buf.extend_from_slice(&header(DATA, id, chunk.len()));
                buf.extend_from_slice(chunk);
            }
            read_total.fetch_add(n as u64, Ordering::Relaxed);
            if shared.data.send((buf, Some(permit))).is_err() {
                break;
            }
        }
    };
    let write_side = async {
        let mut unacked = 0u64;
        let mut out: Vec<u8> = Vec::with_capacity(READ_CHUNK * 4);
        while let Some(first) = rx.recv().await {
            out.clear();
            out.extend_from_slice(&first);
            while out.len() < READ_CHUNK * 4 {
                match rx.try_recv() {
                    Ok(more) => out.extend_from_slice(&more),
                    Err(_) => break,
                }
            }
            let len = out.len() as u64;
            inflight.fetch_sub(len, Ordering::AcqRel);
            write_total.fetch_add(len, Ordering::Relaxed);
            if writer.write_all(&out).await.is_err() {
                break;
            }
            unacked += len;
            if unacked >= step || (rx.is_empty() && unacked >= 16 * 1024) {
                shared.ctrl(encode_window(id, unacked as u32));
                unacked = 0;
            }
        }
        let _ = writer.shutdown().await;
    };
    tokio::select! {
        _ = read_side => {}
        _ = write_side => {}
    }
    read_total.load(Ordering::Relaxed) + write_total.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_header() {
        let frame = encode(DATA, 7, b"abc");
        assert_eq!(frame[0], DATA);
        assert_eq!(u32::from_be_bytes(frame[1..5].try_into().unwrap()), 7);
        assert_eq!(u32::from_be_bytes(frame[5..9].try_into().unwrap()), 3);
        assert_eq!(&frame[9..], b"abc");
        assert_eq!(HEADER + MAX_PAYLOAD, 16 * 1024);
    }

    #[tokio::test]
    async fn credit_wakes_a_waiter() {
        let credit = Credit::new(0);
        let waiter = {
            let credit = Arc::clone(&credit);
            tokio::spawn(async move { credit.take_upto(4).await })
        };
        tokio::task::yield_now().await;
        credit.grant(4);
        let got = tokio::time::timeout(Duration::from_secs(1), waiter).await.unwrap().unwrap();
        assert_eq!(got, Some(4));
    }

    #[tokio::test]
    async fn credit_close_releases_waiter() {
        let credit = Credit::new(0);
        let waiter = {
            let credit = Arc::clone(&credit);
            tokio::spawn(async move { credit.take_upto(4).await })
        };
        tokio::task::yield_now().await;
        credit.close();
        let got = tokio::time::timeout(Duration::from_secs(1), waiter).await.unwrap().unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn credit_overflow_is_rejected() {
        let credit = Credit::new(BASE_CREDIT);
        assert!(credit.grant(1 << 20));
        assert!(!credit.grant(u64::MAX));
        assert!(!credit.grant(1 << 33));
    }

    #[test]
    fn window_is_clamped() {
        assert_eq!(clamp_window(None), DEFAULT_WINDOW);
        assert_eq!(clamp_window(Some(1)), BASE_CREDIT);
        assert_eq!(clamp_window(Some(8192)), 8 * 1024 * 1024);
    }

    async fn expect_eof(peer: &mut tokio::io::DuplexStream) {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 1024];
        tokio::time::timeout(Duration::from_secs(5), async {
            while peer.read(&mut buf).await.map(|n| n > 0).unwrap_or(false) {}
        })
        .await
        .expect("closed session must drop its transport");
    }

    #[tokio::test]
    async fn close_drops_transport() {
        let (ours, mut peer) = tokio::io::duplex(64 * 1024);
        let (r, w) = tokio::io::split(ours);
        let session = adopt(r, w, DEFAULT_WINDOW);
        session.close();
        expect_eof(&mut peer).await;
        assert!(!session.alive());
    }

    #[tokio::test]
    async fn dropping_last_idle_handle_closes() {
        let (ours, mut peer) = tokio::io::duplex(64 * 1024);
        let (r, w) = tokio::io::split(ours);
        drop(adopt(r, w, DEFAULT_WINDOW));
        expect_eof(&mut peer).await;
    }

    #[tokio::test]
    async fn cancelled_open_and_ping_clean_up_maps() {
        let (ours, _peer) = tokio::io::duplex(64 * 1024);
        let (r, w) = tokio::io::split(ours);
        let session = adopt(r, w, DEFAULT_WINDOW);
        // Cancel open() and ping() before any reply arrives (e.g. hedged_open loser).
        let _ = tokio::time::timeout(Duration::from_millis(20), session.open()).await;
        let _ = tokio::time::timeout(Duration::from_millis(20), session.ping()).await;
        assert!(session.shared.pending.lock().unwrap().is_empty());
        assert!(session.shared.streams.lock().unwrap().is_empty());
        assert!(session.shared.pongs.lock().unwrap().is_empty());
        assert_eq!(session.active(), 0);
        session.close();
    }

    #[tokio::test]
    async fn retired_session_closes_after_last_pipe_drops() {
        let (ours, mut peer) = tokio::io::duplex(64 * 1024);
        let (r, w) = tokio::io::split(ours);
        let session = adopt(r, w, DEFAULT_WINDOW);
        let id = 1;
        let (rx, credit, inflight) = session.shared.insert(id);
        session.active.fetch_add(1, Ordering::AcqRel);
        let pipe = Pipe {
            id,
            rx: Some(rx),
            credit,
            inflight,
            shared: Arc::clone(&session.shared),
            active: Arc::clone(&session.active),
        };
        session.retire();
        assert!(session.alive(), "retired session must stay alive while active pipes remain");
        drop(pipe);
        expect_eof(&mut peer).await;
        assert!(!session.alive(), "retired session must shut down once last pipe drops");
    }

    #[test]
    fn loss_tracker_detects_high_retrans_and_decays() {
        let mut t = LossTracker::new();
        assert_eq!(t.record(100, 0), 0);
        // 30% loss bursts push EWMA above 80 permille within 2 intervals.
        let pm1 = t.record(200, 30);
        assert!(pm1 >= 70, "pm1={pm1}");
        let pm2 = t.record(300, 60);
        assert!(pm2 >= 120, "pm2={pm2}");
        // Clean traffic decays EWMA back down.
        let mut pm = pm2;
        for step in 1..=10u32 {
            pm = t.record(300 + step * 100, 60);
        }
        assert!(pm < 15, "loss should decay on clean traffic, got {pm}");
    }

    #[tokio::test]
    async fn retire_within_closes_long_lived_pipe_after_grace() {
        let (ours, mut peer) = tokio::io::duplex(64 * 1024);
        let (r, w) = tokio::io::split(ours);
        let session = adopt(r, w, DEFAULT_WINDOW);
        let id = 1;
        let (rx, credit, inflight) = session.shared.insert(id);
        session.active.fetch_add(1, Ordering::AcqRel);
        let _pipe = Pipe {
            id,
            rx: Some(rx),
            credit,
            inflight,
            shared: Arc::clone(&session.shared),
            active: Arc::clone(&session.active),
        };
        session.retire_within(Duration::from_millis(80));
        assert!(session.alive());
        expect_eof(&mut peer).await;
        assert!(!session.alive(), "retire_within must close stuck pipe after grace");
    }

    #[tokio::test]
    async fn pong_carries_peer_download_loss_telemetry() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (cr, cw) = tokio::io::split(client_io);
        let session = adopt(cr, cw, DEFAULT_WINDOW);
        let step = Arc::new(AtomicU32::new(0));
        let step_srv = Arc::clone(&step);
        let used = Arc::new(AtomicU64::new(0));
        let srv = tokio::spawn(async move {
            let _ = serve_with_probe(server_io, "127.0.0.1:1".into(), used, DEFAULT_WINDOW, move || {
                let k = step_srv.fetch_add(1, Ordering::Relaxed);
                Some(TcpSample { srtt_ms: 40, segs_out: 100 + k * 100, total_retrans: k * 35 })
            })
            .await;
        });
        for _ in 0..4 {
            session.ping().await.unwrap();
        }
        assert!(
            session.peer_loss_permille() >= 150,
            "expected peer download loss >=150pm, got {}",
            session.peer_loss_permille()
        );
        assert_eq!(session.loss_permille(), session.peer_loss_permille());
        session.close();
        let _ = tokio::time::timeout(Duration::from_secs(2), srv).await;
    }
}
