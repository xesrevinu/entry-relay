//! Cold-start lab for a lossy per-flow path.
//! In-process: fake upstream, real relay, a link emulator, real balance.
//! Each TCP through the link gets, at accept time:
//!   * a path: fast (rtt_fast) or slow (rtt_slow) with probability p_slow,
//!     fixed for the connection's life (per-flow ECMP);
//!   * a lost-SYN penalty: first byte delayed by syn_rto with probability p_syn;
//!   * per-chunk tail loss: each chunk with probability p_loss is delayed by
//!     rto (ordered pipe, so later chunks wait too: head-of-line).
//!
//!   coldlab <opens> <gap_ms> [rtt_fast rtt_slow p_slow p_syn syn_rto p_loss rto]
//! Defaults: 40 226 0.5 0.35 1000 0.03 300.
//! A/B with ENTRY_DIAL_RACE=1 ENTRY_HEDGE_MS=0 (old behaviour) vs defaults.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::net::{SocketAddr, TcpListener as StdListener, TcpStream as StdStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use entry_net::balance::{serve as serve_balance, BalanceConfig, RelayConfig as BalanceRelay};
use entry_net::relay::{serve as serve_relay, RelayConfig};
use entry_net::tlsutil::{self, encode_hex, write_self_signed};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioStream;
use tokio::sync::oneshot;

#[derive(Clone, Copy)]
struct Net {
    rtt_fast: f64,
    rtt_slow: f64,
    p_slow: f64,
    p_syn: f64,
    syn_rto: f64,
    p_loss: f64,
    rto: f64,
}

/// Flows currently open through the link (one per mux session TCP).
static LIVE: AtomicU64 = AtomicU64::new(0);
static MAX_LIVE: AtomicU64 = AtomicU64::new(0);
static SEED: AtomicU64 = AtomicU64::new(0x9e3779b97f4a7c15);
fn rnd() -> f64 {
    let mut x = SEED.fetch_add(0x9e3779b97f4a7c15, Ordering::Relaxed);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    (x >> 11) as f64 / (1u64 << 53) as f64
}

fn spawn_upstream() -> SocketAddr {
    let listener = StdListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { break };
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = conn.shutdown(Shutdown::Both);
            });
        }
    });
    addr
}

fn spawn_link(right: SocketAddr, net: Net, slow_flows: Arc<AtomicU64>) -> SocketAddr {
    let listener = StdListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(client) = client else { break };
            let Ok(server) = StdStream::connect(right) else { break };
            let _ = client.set_nodelay(true);
            let _ = server.set_nodelay(true);
            let rtt = match paths() {
                // ECMP-style: path is a pure hash of the client source port
                // (flow label pinned to 0), so a redial on a new port re-rolls.
                Some(p) => {
                    let port = client.peer_addr().map(|a| a.port()).unwrap_or(0) as u64;
                    let mut h = port.wrapping_mul(0x9e3779b97f4a7c15) ^ SEED.load(Ordering::Relaxed).rotate_left(17);
                    h ^= h >> 29;
                    p[(h % p.len() as u64) as usize]
                }
                None => if rnd() < net.p_slow { net.rtt_slow } else { net.rtt_fast },
            };
            if rtt >= 150.0 {
                slow_flows.fetch_add(1, Ordering::Relaxed);
            }
            if let Some(life) = std::env::var("LAB_LIFE_MS").ok().and_then(|v| v.parse::<f64>().ok()) {
                // Emulate loss-triggered session deaths so the pool redials.
                let (c, s) = (client.try_clone().unwrap(), server.try_clone().unwrap());
                let ms = life * (0.5 + rnd());
                thread::spawn(move || {
                    thread::sleep(Duration::from_secs_f64(ms / 1000.0));
                    let _ = c.shutdown(Shutdown::Both);
                    let _ = s.shutdown(Shutdown::Both);
                });
            }
            let one_way = Duration::from_secs_f64(rtt / 2000.0);
            let syn = if rnd() < net.p_syn { Duration::from_secs_f64(net.syn_rto / 1000.0) } else { Duration::ZERO };
            let (c2, s2) = (client.try_clone().unwrap(), server.try_clone().unwrap());
            LIVE.fetch_add(1, Ordering::Relaxed);
            thread::spawn(move || {
                let a = thread::spawn(move || pipe(c2, s2, one_way, syn, net));
                let b = thread::spawn(move || pipe(server, client, one_way, Duration::ZERO, net));
                let _ = a.join();
                let _ = b.join();
                LIVE.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });
    addr
}

/// `LAB_PATHS=35,97,226`: per-source-port hashed paths instead of p_slow.
fn paths() -> Option<Vec<f64>> {
    let v: Vec<f64> = std::env::var("LAB_PATHS").ok()?.split(',').filter_map(|x| x.trim().parse().ok()).collect();
    (!v.is_empty()).then_some(v)
}

fn pipe(mut from: StdStream, to: StdStream, one_way: Duration, first_extra: Duration, net: Net) {
    let (tx, rx) = std::sync::mpsc::channel::<(Instant, Vec<u8>)>();
    let writer = thread::spawn(move || {
        let mut to = to;
        let mut last = Instant::now();
        for (due, data) in rx {
            // Ordered delivery: a delayed (lost) chunk holds back the rest.
            let due = due.max(last);
            let now = Instant::now();
            if due > now {
                thread::sleep(due - now);
            }
            last = due;
            if to.write_all(&data).is_err() {
                break;
            }
        }
        let _ = to.shutdown(Shutdown::Both);
    });
    let mut buf = vec![0u8; 16 * 1024];
    let mut first = true;
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let mut due = Instant::now() + one_way;
        if first {
            due += first_extra;
            first = false;
        }
        if rnd() < net.p_loss {
            due += Duration::from_secs_f64(net.rto / 1000.0);
        }
        if tx.send((due, buf[..n].to_vec())).is_err() {
            break;
        }
    }
    drop(tx);
    let _ = writer.join();
}

async fn socks_open(socks: SocketAddr) -> Option<TokioStream> {
    let mut s = TokioStream::connect(socks).await.ok()?;
    let _ = s.set_nodelay(true);
    s.write_all(&[5, 1, 0]).await.ok()?;
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.ok()?;
    s.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0x30, 0x39]).await.ok()?;
    let mut r = [0u8; 10];
    s.read_exact(&mut r).await.ok()?;
    (r[1] == 0).then_some(s)
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let i = ((v.len() - 1) as f64 * p).round() as usize;
    (v[i] * 10.0).round() / 10.0
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let f = |i: usize, d: f64| a.get(i).and_then(|s| s.parse().ok()).unwrap_or(d);
    let opens = f(1, 200.0) as usize;
    let gap = f(2, 300.0);
    let net = Net { rtt_fast: f(3, 40.0), rtt_slow: f(4, 226.0), p_slow: f(5, 0.5), p_syn: f(6, 0.35), syn_rto: f(7, 1000.0), p_loss: f(8, 0.03), rto: f(9, 300.0) };
    if let Ok(seed) = std::env::var("LAB_SEED") {
        SEED.store(seed.parse().unwrap_or(1), Ordering::Relaxed);
    }

    tlsutil::install_provider();
    let dir = std::env::temp_dir().join(format!("coldlab-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pin = write_self_signed(&dir, "relay.example").unwrap();
    let psk = dir.join("psk");
    std::fs::write(&psk, b"coldlab-psk-32-bytes-padding!!!!").unwrap();
    let upstream = spawn_upstream();
    let (rtx, rrx) = oneshot::channel();
    let relay_cfg = RelayConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        upstream: upstream.to_string(),
        psk_file: psk.clone(),
        cert: dir.join("cert.pem"),
        key: dir.join("key.pem"),
        quota_bytes: u64::MAX / 4,
        state: dir.join("relay.json"),
        window_kb: None,
    };
    tokio::spawn(async move { serve_relay(relay_cfg, rtx).await.unwrap() });
    let relay = rrx.await.unwrap();
    let slow_flows = Arc::new(AtomicU64::new(0));
    let link = spawn_link(relay, net, Arc::clone(&slow_flows));
    let (btx, brx) = oneshot::channel();
    let cfg = BalanceConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        psk_file: psk,
        state: dir.join("bal.json"),
        max_rtt_ms: 600_000,
        probe_secs: 30,
        allow: vec!["127.0.0.1".into()],
        sessions: Some(4),
        window_kb: None,
        relay: vec![BalanceRelay {
            name: "lab".into(),
            addr: link.to_string(),
            sni: "relay.example".into(),
            pin_sha256: encode_hex(&pin),
            quota_bytes: u64::MAX / 4,
        }],
    };
    tokio::spawn(async move { serve_balance(cfg, btx).await.unwrap() });
    let socks = brx.await.unwrap();
    // Let the 4 slots dial (as after a restart/redial), then measure quiet opens.
    tokio::time::sleep(Duration::from_secs(5)).await;

    let mut open = Vec::new();
    let mut first_byte = Vec::new();
    let mut fails = 0;
    let mut slow_opens = 0;
    for _ in 0..opens {
        let t = Instant::now();
        match tokio::time::timeout(Duration::from_secs(10), socks_open(socks)).await {
            Ok(Some(mut s)) => {
                open.push(t.elapsed().as_secs_f64() * 1000.0);
                // One request/response round trip on the new stream (≈ ClientHello -> ServerHello).
                let _ = s.write_all(b"x").await;
                let mut b = [0u8; 1];
                if s.read_exact(&mut b).await.is_ok() {
                    let ms = t.elapsed().as_secs_f64() * 1000.0;
                    // open + echo ~ 2 RTT: 226 ms path => ~450 ms, 97 => ~200.
                    if ms > 400.0 {
                        slow_opens += 1;
                    }
                    first_byte.push(ms);
                }
            }
            _ => fails += 1,
        }
        tokio::time::sleep(Duration::from_secs_f64(gap / 1000.0)).await;
        MAX_LIVE.fetch_max(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
    }
    // Let in-flight redials settle, then count TCPs the pool still holds.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let live_end = LIVE.load(Ordering::Relaxed);
    let race = std::env::var("ENTRY_DIAL_RACE").unwrap_or_else(|_| "default".into());
    let reject = std::env::var("ENTRY_RTT_REJECT_MS").unwrap_or_else(|_| "default".into());
    let hedge = std::env::var("ENTRY_HEDGE_MS").unwrap_or_else(|_| "default".into());
    println!(
        "{{\"race\":\"{race}\",\"reject\":\"{reject}\",\"slow_opens\":{slow_opens},\"hedge\":\"{hedge}\",\"n\":{},\"fails\":{fails},\"link_flows\":\"slow {} total\",\"open_p50\":{},\"open_p90\":{},\"open_p99\":{},\"open_max\":{},\"rt_p50\":{},\"rt_p90\":{},\"rt_p99\":{},\"live_end\":{live_end},\"live_max\":{},\"sessions\":4}}",
        open.len(),
        slow_flows.load(Ordering::Relaxed),
        pct(&mut open, 0.5),
        pct(&mut open, 0.9),
        pct(&mut open, 0.99),
        pct(&mut open, 1.0),
        pct(&mut first_byte, 0.5),
        pct(&mut first_byte, 0.9),
        pct(&mut first_byte, 0.99),
        MAX_LIVE.load(Ordering::Relaxed),
    );
    if std::env::var("LAB_ASSERT_SESSIONS").is_ok() && std::env::var("LAB_LIFE_MS").is_err() {
        // 4 slots; allow one in-flight redial race (dial_race wide).
        assert!(live_end <= 4 + 3, "leaked mux sessions: {live_end} live TCPs for 4 slots");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
