//! Mux v2 behaviour: integrity, no head-of-line across streams, no
//! truncation on close.
use std::net::SocketAddr;
use std::time::Duration;

use entry_net::balance::{serve as serve_balance, BalanceConfig, RelayConfig as BalanceRelay};
use entry_net::relay::{serve as serve_relay, RelayConfig};
use entry_net::tlsutil::{encode_hex, write_self_signed};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Upstream: client sends 9 bytes: seed u8 + len u64 BE. Server answers with
/// that many pattern bytes, then closes at once (tests CLOSE ordering).
async fn upstream() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { break };
            tokio::spawn(async move {
                let mut req = [0u8; 9];
                if s.read_exact(&mut req).await.is_err() {
                    return;
                }
                let len = u64::from_be_bytes(req[1..].try_into().unwrap()) as usize;
                let data = pattern(len, req[0] as u64 + 7);
                let _ = s.write_all(&data).await;
                // drop => FIN right after the last byte
            });
        }
    });
    addr
}

async fn stack(up: SocketAddr, sessions: usize, window_kb: Option<u32>) -> SocketAddr {
    let dir = std::env::temp_dir().join(format!("entry-mux-{}-{}", std::process::id(), up.port()));
    std::fs::create_dir_all(&dir).unwrap();
    let pin = write_self_signed(&dir, "relay.example").unwrap();
    let psk = dir.join("psk");
    std::fs::write(&psk, b"mux-test").unwrap();
    let (tx, rx) = oneshot::channel();
    let cfg = RelayConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        upstream: up.to_string(),
        psk_file: psk.clone(),
        cert: dir.join("cert.pem"),
        key: dir.join("key.pem"),
        quota_bytes: u64::MAX / 4,
        state: dir.join("relay.json"),
        window_kb,
    };
    tokio::spawn(async move { serve_relay(cfg, tx).await.unwrap() });
    let relay = rx.await.unwrap();
    let (tx, rx) = oneshot::channel();
    let cfg = BalanceConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        psk_file: psk,
        state: dir.join("bal.json"),
        max_rtt_ms: 60_000,
        probe_secs: 30,
        allow: vec![up.to_string()],
        sessions: Some(sessions),
        window_kb,
        relay: vec![BalanceRelay {
            name: "local".into(),
            addr: relay.to_string(),
            sni: "relay.example".into(),
            pin_sha256: encode_hex(&pin),
            quota_bytes: u64::MAX / 4,
        }],
    };
    tokio::spawn(async move { serve_balance(cfg, tx).await.unwrap() });
    rx.await.unwrap()
}

async fn request(socks: SocketAddr, up: SocketAddr, seed: u8, len: u64) -> TcpStream {
    let mut s = TcpStream::connect(socks).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    let p = up.port().to_be_bytes();
    s.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, p[0], p[1]]).await.unwrap();
    let mut r = [0u8; 10];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r[1], 0, "socks connect failed");
    let mut req = vec![seed];
    req.extend_from_slice(&len.to_be_bytes());
    s.write_all(&req).await.unwrap();
    s
}

async fn read_all(mut s: TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_transfer_is_intact() {
    let up = upstream().await;
    let socks = stack(up, 1, None).await;
    let len = 48 * 1024 * 1024 + 12345;
    let s = request(socks, up, 1, len as u64).await;
    let got = tokio::time::timeout(Duration::from_secs(60), read_all(s)).await.unwrap();
    assert_eq!(got.len(), len, "transfer truncated");
    assert_eq!(Sha256::digest(&got), Sha256::digest(pattern(len, 8)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_short_streams_are_not_truncated() {
    let up = upstream().await;
    let socks = stack(up, 2, Some(256)).await;
    let mut tasks = Vec::new();
    for i in 0..40u8 {
        let len = 1 + (i as u64) * 37_771;
        tasks.push(tokio::spawn(async move {
            let s = request(socks, up, i, len).await;
            let got = read_all(s).await;
            assert_eq!(got.len() as u64, len, "stream {i} truncated");
            assert_eq!(got, pattern(len as usize, i as u64 + 7));
        }));
    }
    for t in tasks {
        tokio::time::timeout(Duration::from_secs(30), t).await.unwrap().unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_consumer_does_not_stall_others() {
    let up = upstream().await;
    // One session, small window: the stalled stream must not block the TLS
    // reader for the others.
    let socks = stack(up, 1, Some(256)).await;
    let stalled = request(socks, up, 3, 64 * 1024 * 1024).await; // never read
    tokio::time::sleep(Duration::from_millis(300)).await;
    for round in 0..3u8 {
        let len = 8 * 1024 * 1024;
        let s = request(socks, up, 10 + round, len).await;
        let got = tokio::time::timeout(Duration::from_secs(20), read_all(s))
            .await
            .expect("healthy stream stalled behind a slow one");
        assert_eq!(got.len() as u64, len);
    }
    // The stalled stream still gets its data once it reads.
    let got = tokio::time::timeout(Duration::from_secs(60), read_all(stalled)).await.unwrap();
    assert_eq!(got.len(), 64 * 1024 * 1024);
    assert_eq!(Sha256::digest(&got), Sha256::digest(pattern(64 * 1024 * 1024, 10)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_peer_kills_session() {
    // Peer that accepts bytes but never answers: heartbeat must declare it dead.
    let (ours, theirs) = tokio::io::duplex(1 << 20);
    let (r, w) = tokio::io::split(ours);
    let session = entry_net::mux::adopt(r, w, entry_net::mux::DEFAULT_WINDOW);
    let _hold = tokio::spawn(async move {
        let (mut tr, _tw) = tokio::io::split(theirs);
        let mut sink = tokio::io::sink();
        let _ = tokio::io::copy(&mut tr, &mut sink).await;
    });
    let started = std::time::Instant::now();
    tokio::time::timeout(std::time::Duration::from_secs(20), session.closed()).await.expect("session detected dead");
    let took = started.elapsed();
    assert!(!session.alive());
    assert!(took >= std::time::Duration::from_secs(7) && took <= std::time::Duration::from_secs(12), "{took:?}");
}
