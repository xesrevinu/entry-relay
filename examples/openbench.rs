//! Open latency while one bulk stream already occupies the mux.
//!
//! `openbench <one_way_ms> <bulk_kib> <opens> [sessions]`
//!
//! A userspace pipe delays each direction between balance and relay, so this
//! runs without root or netem. One SOCKS client pulls `bulk_kib` (first byte
//! 0x01); the others open and close immediately (0x00). Prints one line:
//! `one_way_ms sessions bulk_kib opens p50 p90 max all`.
//!
//! The delay is per accepted connection. A single shared pipe would serialize
//! every mux session and hide the gain from spreading opens.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use entry_net::balance::{serve as serve_balance, BalanceConfig, RelayConfig as BalanceRelay};
use entry_net::relay::{serve as serve_relay, RelayConfig};
use entry_net::tlsutil::{self, encode_hex, write_self_signed};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioStream;
use tokio::sync::oneshot;

/// One delayed bridge per accepted connection, so mux sessions do not share a
/// single stall. Each direction sleeps `delay` once per read.
fn spawn_delay(right: SocketAddr, delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let left = listener.local_addr().unwrap();
    thread::spawn(move || {
        for client in listener.incoming() {
            let client = match client {
                Ok(c) => c,
                Err(_) => break,
            };
            let right = right;
            let delay = delay;
            thread::spawn(move || {
                let server = TcpStream::connect(right).unwrap();
                let _ = client.set_nodelay(true);
                let _ = server.set_nodelay(true);
                let c2 = client.try_clone().unwrap();
                let s2 = server.try_clone().unwrap();
                thread::spawn(move || pipe(c2, s2, delay));
                pipe(server, client, delay);
            });
        }
    });
    left
}

fn pipe(mut from: TcpStream, mut to: TcpStream, delay: Duration) {
    let mut buf = [0u8; 8 * 1024];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if !delay.is_zero() {
            thread::sleep(delay);
        }
        if to.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let _ = to.shutdown(Shutdown::Both);
}

/// First byte selects the behaviour: 0x01 dumps `chunks` of 16 KiB, anything
/// else accepts and closes.
fn spawn_upstream(chunks: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let mut conn = match conn {
                Ok(c) => c,
                Err(_) => break,
            };
            let _ = conn.set_nodelay(true);
            let chunks = chunks;
            thread::spawn(move || {
                let mut tag = [0u8; 1];
                if conn.read_exact(&mut tag).is_err() {
                    return;
                }
                if tag[0] == 1 {
                    let buf = vec![0x5au8; 16 * 1024];
                    for _ in 0..chunks {
                        if conn.write_all(&buf).is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    addr
}

async fn socks_open(socks: SocketAddr, dest: SocketAddr) -> TokioStream {
    let mut s = TokioStream::connect(socks).await.unwrap();
    let _ = s.set_nodelay(true);
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    let ip = match dest.ip() {
        std::net::IpAddr::V4(v) => v.octets(),
        _ => panic!("v4 only"),
    };
    let p = dest.port().to_be_bytes();
    s.write_all(&[5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], p[0], p[1]]).await.unwrap();
    let mut r = [0u8; 10];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r[1], 0, "socks failed {}", r[1]);
    s
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let one_way_ms: u64 = args.get(1).and_then(|v| v.parse().ok()).unwrap_or(20);
    let bulk_kib: usize = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(256);
    let opens: usize = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(8);
    let sessions: usize = args.get(4).and_then(|v| v.parse().ok()).unwrap_or(1);
    tlsutil::install_provider();

    let upstream = spawn_upstream(bulk_kib.div_ceil(16));
    let dir = std::env::temp_dir().join(format!("entry-openbench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pin = write_self_signed(&dir, "relay.example").unwrap();
    let psk = dir.join("psk");
    std::fs::write(&psk, b"openbench-psk-32-bytes-padding!!").unwrap();

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
    let relay_listen = rrx.await.unwrap();
    let delayed = spawn_delay(relay_listen, Duration::from_millis(one_way_ms));

    let (btx, brx) = oneshot::channel();
    let bal_cfg = BalanceConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        psk_file: psk,
        state: dir.join("bal.json"),
        max_rtt_ms: 60_000,
        probe_secs: 60,
        allow: vec![upstream.to_string()],
        sessions: Some(sessions),
        window_kb: None,
        relay: vec![BalanceRelay {
            name: "local".into(),
            addr: delayed.to_string(),
            sni: "relay.example".into(),
            pin_sha256: encode_hex(&pin),
            quota_bytes: u64::MAX / 4,
        }],
    };
    tokio::spawn(async move { serve_balance(bal_cfg, btx).await.unwrap() });
    let socks = brx.await.unwrap();

    // Warm the mux, then start the bulk stream and only then measure. With
    // more than one session the bulk occupies slot 0 and later opens move on.
    {
        let s = socks_open(socks, upstream).await;
        drop(s);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut bulk = socks_open(socks, upstream).await;
    bulk.write_all(&[1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(one_way_ms.saturating_mul(6).max(80))).await;

    let mut samples = Vec::with_capacity(opens);
    for _ in 0..opens {
        let t = Instant::now();
        let mut s = socks_open(socks, upstream).await;
        s.write_all(&[0]).await.unwrap();
        samples.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    drop(bulk);
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pct = |p: f64| samples[((samples.len() - 1) as f64 * p).round() as usize];
    let raw: Vec<String> = samples.iter().map(|v| format!("{v:.0}")).collect();
    println!(
        "one_way_ms={one_way_ms} sessions={sessions} bulk_kib={bulk_kib} opens={opens} p50={:.1} p90={:.1} max={:.1} all={}",
        pct(0.5),
        pct(0.9),
        samples.last().copied().unwrap_or(0.0),
        raw.join(",")
    );
    let _ = std::fs::remove_dir_all(&dir);
}
