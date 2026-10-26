//! Slow-path rejects, keep-best and dial-race losers must close their TCP.
//! Every flow through the link is ~200 ms RTT (> ENTRY_RTT_REJECT_MS=150), so
//! each slot rejects 3 rounds of 3 racing dials and keeps the best one. Before
//! the fix the 32 discarded sessions per slot stayed open on heartbeat.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener as StdListener, TcpStream as StdStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use entry_net::balance::{serve as serve_balance, BalanceConfig, RelayConfig as BalanceRelay};
use entry_net::relay::{serve as serve_relay, RelayConfig};
use entry_net::tlsutil::{self, encode_hex, write_self_signed};
use tokio::sync::oneshot;

fn pipe(mut from: StdStream, mut to: StdStream, delay: Duration) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                thread::sleep(delay);
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown(Shutdown::Both);
    let _ = from.shutdown(Shutdown::Both);
}

fn slow_link(right: SocketAddr, live: Arc<AtomicUsize>) -> SocketAddr {
    let listener = StdListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(client) = client else { break };
            let Ok(server) = StdStream::connect(right) else { break };
            live.fetch_add(1, Ordering::SeqCst);
            let live = Arc::clone(&live);
            let (c2, s2) = (client.try_clone().unwrap(), server.try_clone().unwrap());
            thread::spawn(move || {
                let d = Duration::from_millis(100);
                let a = thread::spawn(move || pipe(c2, s2, d));
                let b = thread::spawn(move || pipe(server, client, d));
                let _ = a.join();
                let _ = b.join();
                live.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discarded_sessions_close_their_sockets() {
    std::env::set_var("ENTRY_RTT_REJECT_MS", "150");
    std::env::set_var("ENTRY_RTT_RETRIES", "3");
    tlsutil::install_provider();
    let dir = std::env::temp_dir().join(format!("session-leak-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pin = write_self_signed(&dir, "relay.example").unwrap();
    let psk = dir.join("psk");
    std::fs::write(&psk, b"leaktest-psk-32-bytes-padding!!!").unwrap();
    let up = StdListener::bind("127.0.0.1:0").unwrap();
    let upstream = up.local_addr().unwrap();
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
    let live = Arc::new(AtomicUsize::new(0));
    let link = slow_link(relay, Arc::clone(&live));
    let (btx, brx) = oneshot::channel();
    let cfg = BalanceConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        psk_file: psk,
        state: dir.join("bal.json"),
        max_rtt_ms: 600_000,
        probe_secs: 3600,
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
    let _socks = brx.await.unwrap();
    // 4 rounds x (~3 RTT handshake + backoff) per slot, then heartbeats
    // (2 s) would keep any leaked session alive past this point.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut seen = usize::MAX;
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(1)).await;
        seen = live.load(Ordering::SeqCst);
        if seen == 4 && Instant::now() + Duration::from_secs(12) > deadline {
            break;
        }
    }
    tokio::time::sleep(Duration::from_secs(5)).await;
    let end = live.load(Ordering::SeqCst);
    assert_eq!(end, 4, "live mux TCPs {end} (last poll {seen}) for 4 configured sessions");
    let _ = std::fs::remove_dir_all(&dir);
}
