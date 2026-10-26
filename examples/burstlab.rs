//! Lab harness for mux v2 burst behaviour. Everything runs in one process on
//! loopback: a fake upstream, the real relay, a rate+delay link emulator and
//! the real balance. Only the emulator makes the path look like a WAN.
//!
//!   burstlab burst   <sessions> <rtt_ms> <down_mbps> [up_mbps] [bulk:0|1]
//!   burstlab burst64 <sessions> <rtt_ms> <down_mbps> [up_mbps] [bulk:0|1]
//!   burstlab leak    <sessions> <rtt_ms> <down_mbps> <stall_s>
//!
//! One JSON object per phase on stdout.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::net::{SocketAddr, TcpListener as StdListener, TcpStream as StdStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use entry_net::balance::{serve as serve_balance, BalanceConfig, RelayConfig as BalanceRelay};
use entry_net::relay::{serve as serve_relay, RelayConfig};
use entry_net::tlsutil::{self, encode_hex, write_self_signed};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioStream;
use tokio::sync::oneshot;

/// Upstream stub. First byte: 1 = dump data forever, 2 = echo, else close.
fn spawn_upstream() -> SocketAddr {
    let listener = StdListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { break };
            thread::spawn(move || {
                let _ = conn.set_nodelay(true);
                let mut tag = [0u8; 1];
                if conn.read_exact(&mut tag).is_err() {
                    return;
                }
                match tag[0] {
                    1 => {
                        let buf = vec![0x5au8; 32 * 1024];
                        while conn.write_all(&buf).is_ok() {}
                    }
                    2 => {
                        let mut buf = [0u8; 8 * 1024];
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
                    }
                    _ => {}
                }
                let _ = conn.shutdown(Shutdown::Both);
            });
        }
    });
    addr
}

struct Link {
    addr: SocketAddr,
    live: Arc<AtomicUsize>,
    stalled: Arc<AtomicBool>,
}

impl Link {
    fn live(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }
}

/// Delays the first chunk of every connection by `one_way`, then paces chunks
/// by `rate_bps` so backpressure builds inside the mux writer the way it does
/// on a real access link. One thread per direction per connection.
fn spawn_link(right: SocketAddr, one_way: Duration, down_bps: u64, up_bps: u64) -> Link {
    let listener = StdListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let live = Arc::new(AtomicUsize::new(0));
    let stalled = Arc::new(AtomicBool::new(false));
    let live2 = Arc::clone(&live);
    let stalled2 = Arc::clone(&stalled);
    thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(client) = client else { break };
            let Ok(server) = StdStream::connect(right) else { break };
            let _ = client.set_nodelay(true);
            let _ = server.set_nodelay(true);
            live2.fetch_add(1, Ordering::Relaxed);
            let c2 = client.try_clone().unwrap();
            let s2 = server.try_clone().unwrap();
            let (st_up, st_down) = (Arc::clone(&stalled2), Arc::clone(&stalled2));
            let live_down = Arc::clone(&live2);
            // upstream direction (balance -> relay)
            thread::spawn(move || {
                pipe(c2, s2, one_way, up_bps, st_up);
            });
            // downstream direction (relay -> balance), so accept keeps going
            thread::spawn(move || {
                pipe(server, client, one_way, down_bps, st_down);
                live_down.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });
    Link { addr, live, stalled }
}

/// Constant-delay, rate-paced pipe with pipelining: the reader tags every
/// chunk with its arrival deadline and the writer drains them in order, so the
/// link behaves like a real one (BDP is filled, nothing stalls per chunk).
fn pipe(from: StdStream, to: StdStream, one_way: Duration, rate_bps: u64, stalled: Arc<AtomicBool>) {
    let (tx, rx) = std::sync::mpsc::sync_channel::<(Instant, Vec<u8>)>(48);
    let mut reader = from;
    let writer = thread::spawn(move || {
        let mut to = to;
        let mut next_slot = Instant::now();
        let mut queue: std::collections::VecDeque<(Instant, Vec<u8>)> = std::collections::VecDeque::new();
        loop {
            if queue.is_empty() {
                match rx.recv() {
                    Ok(item) => queue.push_back(item),
                    Err(_) => break,
                }

            }
            while stalled.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(20));
            }
            let (due, data) = queue.pop_front().unwrap();
            let now = Instant::now();
            if due > now {
                thread::sleep(due - now);
            }
            if rate_bps > 0 {
                let now = Instant::now();
                if next_slot > now {
                    thread::sleep(next_slot - now);
                }
                next_slot = Instant::now() + Duration::from_secs_f64(data.len() as f64 * 8.0 / rate_bps as f64);
            }
            if to.write_all(&data).is_err() {
                break;
            }
        }
        let _ = to.shutdown(Shutdown::Both);
    });
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if tx.send((Instant::now() + one_way, buf[..n].to_vec())).is_err() {
            break;
        }
    }
    drop(tx);
    let _ = writer.join();
}

struct Lab {
    socks: SocketAddr,
    link: Link,
}

async fn build(sessions: usize, rtt_ms: f64, down_mbps: f64, up_mbps: f64, probe_secs: u64) -> Lab {
    tlsutil::install_provider();
    let dir = std::env::temp_dir().join(format!("burstlab-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pin = write_self_signed(&dir, "relay.example").unwrap();
    let psk = dir.join("psk");
    std::fs::write(&psk, b"burstlab-psk-32-bytes-padding!!!").unwrap();
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

    let link = spawn_link(
        relay,
        Duration::from_secs_f64(rtt_ms / 2000.0),
        (down_mbps * 1e6) as u64,
        (up_mbps * 1e6) as u64,
    );

    let (btx, brx) = oneshot::channel();
    let cfg = BalanceConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        psk_file: psk,
        state: dir.join("bal.json"),
        max_rtt_ms: 600_000,
        probe_secs,
        allow: vec!["127.0.0.1".into()],
        sessions: Some(sessions),
        window_kb: None,
        relay: vec![BalanceRelay {
            name: "lab".into(),
            addr: link.addr.to_string(),
            sni: "relay.example".into(),
            pin_sha256: encode_hex(&pin),
            quota_bytes: u64::MAX / 4,
        }],
    };
    tokio::spawn(async move { serve_balance(cfg, btx).await.unwrap() });
    let socks = brx.await.unwrap();
    Lab { socks, link }
}

async fn socks_open(socks: SocketAddr) -> TokioStream {
    let mut s = TokioStream::connect(socks).await.unwrap();
    let _ = s.set_nodelay(true);
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    s.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0x30, 0x39]).await.unwrap();
    let mut r = [0u8; 10];
    s.read_exact(&mut r).await.unwrap();
    s
}

/// Just the SOCKS reply: OPEN/OK round trip plus the relay's upstream connect.
/// This is the production metric (open_ms).
async fn open_probe(socks: SocketAddr) -> f64 {
    let t = Instant::now();
    let s = socks_open(socks).await;
    drop(s);
    t.elapsed().as_secs_f64() * 1000.0
}

/// Echo round trips on one stream: what a short request pays for data when the
/// path already carries a fat stream.
async fn echo_probe(socks: SocketAddr, trips: usize) -> Vec<f64> {
    let mut s = socks_open(socks).await;
    s.write_all(&[2]).await.unwrap();
    let mut out = Vec::with_capacity(trips);
    for _ in 0..trips {
        let t = Instant::now();
        s.write_all(&[0x42]).await.unwrap();
        s.read_exact(&mut [0u8; 1]).await.unwrap();
        out.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    out
}

fn pct(vals: &mut [f64], p: f64) -> f64 {
    if vals.is_empty() {
        return f64::NAN;
    }
    vals.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let i = ((vals.len() - 1) as f64 * p).round() as usize;
    (vals[i] * 10.0).round() / 10.0
}

fn report(name: &str, vals: &mut Vec<f64>) {
    println!(
        "{{\"phase\":\"{name}\",\"n\":{},\"p50\":{},\"p90\":{},\"p99\":{},\"max\":{}}}",
        vals.len(),
        pct(vals, 0.5),
        pct(vals, 0.9),
        pct(vals, 0.99),
        pct(vals, 1.0)
    );
}

async fn bulk_task(socks: SocketAddr) -> (tokio::task::JoinHandle<u64>, Arc<AtomicBool>) {
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    let handle = tokio::spawn(async move {
        let mut s = socks_open(socks).await;
        s.write_all(&[1]).await.unwrap();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        while !stop2.load(Ordering::Relaxed) {
            match tokio::time::timeout(Duration::from_millis(300), s.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => break,
                Ok(Ok(n)) => total += n as u64,
                Err(_) => {}
            }
        }
        total
    });
    (handle, stop)
}

async fn wait_ready(socks: SocketAddr) {
    for _ in 0..100 {
        let ok = tokio::time::timeout(Duration::from_secs(3), open_probe(socks)).await;
        if ok.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("lab did not become ready");
}

async fn join_all(futs: Vec<impl std::future::Future<Output = f64> + Send + 'static>) -> Vec<f64> {
    let handles: Vec<_> = futs.into_iter().map(tokio::spawn).collect();
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(v) = h.await {
            out.push(v);
        }
    }
    out
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("burst");
    let num = |i: usize, d: f64| args.get(i).and_then(|v| v.parse::<f64>().ok()).unwrap_or(d);
    let sessions = num(2, 4.0) as usize;
    let rtt_ms = num(3, 200.0);
    let down = num(4, 60.0);
    let up = num(5, 30.0);
    let lab = build(sessions, rtt_ms, down, up, num(8, 60.0) as u64).await;
    let socks = lab.socks;
    wait_ready(socks).await;

    match mode {
        "kill" => {
            let stall_s = num(6, 12.0);
            println!("{{\"phase\":\"before\",\"link_conns\":{}}}", lab.link.live());
            lab.link.stalled.store(true, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_secs_f64(stall_s)).await;
            lab.link.stalled.store(false, Ordering::Relaxed);
            for i in 0..10 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                println!(
                    "{{\"phase\":\"after_kill\",\"t_s\":{},\"link_conns\":{}}}",
                    (i + 1) * 2,
                    lab.link.live()
                );
            }
        }
        "tput" => {
            let secs = num(6, 10.0);
            let streams = num(7, 1.0) as usize;
            let mut bulks = Vec::new();
            let mut stops = Vec::new();
            for _ in 0..streams {
                let (h, s) = bulk_task(socks).await;
                bulks.push(h);
                stops.push(s);
            }
            let t = Instant::now();
            tokio::time::sleep(Duration::from_secs_f64(secs)).await;
            for s in &stops {
                s.store(true, Ordering::Relaxed);
            }
            let mut bytes = 0u64;
            for h in bulks {
                bytes += h.await.unwrap_or(0);
            }
            let dt = t.elapsed().as_secs_f64();
            println!(
                "{{\"phase\":\"tput\",\"streams\":{streams},\"mbps\":{:.2},\"bytes\":{bytes},\"secs\":{:.1}}}",
                bytes as f64 * 8.0 / dt / 1e6,
                dt
            );
        }
        "leak" => {
            let _ = num(6, 6.0);
            let (bh, stop_bulk) = bulk_task(socks).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
            println!("{{\"phase\":\"before\",\"link_conns\":{}}}", lab.link.live());
            for i in 0..12 {
                tokio::time::sleep(Duration::from_secs(5)).await;
                println!(
                    "{{\"phase\":\"after_stall\",\"t_s\":{},\"link_conns\":{}}}",
                    (i + 1) * 5,
                    lab.link.live()
                );
                let _ = i;
            }
            stop_bulk.store(true, Ordering::Relaxed);
            let bytes = bh.await.unwrap_or(0);
            println!("{{\"phase\":\"bulk\",\"bytes\":{bytes}}}");
        }
        _ => {
            let burst = num(6, 16.0) as usize;
            let with_bulk = args.get(7).map(|v| v != "0").unwrap_or(true);
            let mut idle = Vec::new();
            for _ in 0..20 {
                idle.push(open_probe(socks).await);
            }
            report("idle_open", &mut idle);
            let (bulk, stop) = if with_bulk {
                let (h, s) = bulk_task(socks).await;
                tokio::time::sleep(Duration::from_millis((rtt_ms as u64).max(300))).await;
                (Some(h), Some(s))
            } else {
                (None, None)
            };
            let mut seq = Vec::new();
            for _ in 0..16 {
                seq.push(open_probe(socks).await);
            }
            report("bulk_seq_open", &mut seq);
            let futs: Vec<_> = (0..burst).map(|_| open_probe(socks)).collect();
            let mut conc = join_all(futs).await;
            report("bulk_conc_open", &mut conc);
            let mut rtts = echo_probe(socks, 10).await;
            report("bulk_echo_rtt", &mut rtts);
            if let (Some(h), Some(s)) = (bulk, stop) {
                s.store(true, Ordering::Relaxed);
                let bytes = h.await.unwrap_or(0);
                println!("{{\"phase\":\"bulk\",\"bytes\":{bytes}}}");
            }
        }
    }
}
