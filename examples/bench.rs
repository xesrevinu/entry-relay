//! Local throughput bench: raw TCP vs raw TLS vs mux (balance -> relay).
//! Usage: bench <tcp|tls|mux> <streams> <mb_per_stream> [sessions]
//! Fixed ports (for dummynet/netem delay rules): tcp 40001, tls 40002, relay 40003.
use std::sync::Arc;
use std::time::{Duration, Instant};

use entry_net::balance::{serve as serve_balance, BalanceConfig, RelayConfig as BalanceRelay};
use entry_net::relay::{serve as serve_relay, RelayConfig};
use entry_net::tlsutil::{self, encode_hex, write_self_signed};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

async fn source<S: AsyncWrite + Unpin>(mut s: S, bytes: u64) {
    let buf = vec![0x5au8; 256 * 1024];
    let mut left = bytes;
    while left > 0 {
        let n = left.min(buf.len() as u64) as usize;
        if s.write_all(&buf[..n]).await.is_err() {
            return;
        }
        left -= n as u64;
    }
    let _ = s.shutdown().await;
}

async fn sink<S: AsyncRead + Unpin>(mut s: S) -> u64 {
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        match s.read(&mut buf).await {
            Ok(0) | Err(_) => return total,
            Ok(n) => total += n as u64,
        }
    }
}

fn spawn_source(listener: TcpListener, bytes: u64) {
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = listener.accept().await else { break };
            let _ = s.set_nodelay(true);
            tokio::spawn(source(s, bytes));
        }
    });
}

async fn socks_connect(socks: std::net::SocketAddr, port: u16) -> TcpStream {
    let mut s = TcpStream::connect(socks).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    let p = port.to_be_bytes();
    s.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, p[0], p[1]]).await.unwrap();
    let mut r = [0u8; 10];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r[1], 0, "socks connect failed");
    s
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("mux").to_string();
    let streams: usize = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(1);
    let mb: u64 = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(200);
    let sessions: usize = args.get(4).and_then(|v| v.parse().ok()).unwrap_or(1);
    let bytes = mb * 1024 * 1024;
    tlsutil::install_provider();
    let dir = std::env::temp_dir().join(format!("entry-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pin = write_self_signed(&dir, "relay.example").unwrap();
    let psk = dir.join("psk");
    std::fs::write(&psk, b"bench-psk").unwrap();

    let started;
    let mut tasks = Vec::new();
    match mode.as_str() {
        "tcp" => {
            spawn_source(TcpListener::bind("127.0.0.1:40001").await.unwrap(), bytes);
            started = Instant::now();
            for _ in 0..streams {
                tasks.push(tokio::spawn(async move {
                    let s = TcpStream::connect("127.0.0.1:40001").await.unwrap();
                    s.set_nodelay(true).unwrap();
                    sink(s).await
                }));
            }
        }
        "tls" => {
            let certs = tlsutil::load_certs(&dir.join("cert.pem")).unwrap();
            let key = tlsutil::load_key(&dir.join("key.pem")).unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(tlsutil::server_config(certs, key).unwrap());
            let l = TcpListener::bind("127.0.0.1:40002").await.unwrap();
            tokio::spawn(async move {
                loop {
                    let Ok((s, _)) = l.accept().await else { break };
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let _ = s.set_nodelay(true);
                        if let Ok(t) = acceptor.accept(s).await {
                            source(t, bytes).await;
                        }
                    });
                }
            });
            let connector = tokio_rustls::TlsConnector::from(tlsutil::client_config(pin));
            started = Instant::now();
            for _ in 0..streams {
                let c = connector.clone();
                tasks.push(tokio::spawn(async move {
                    let s = TcpStream::connect("127.0.0.1:40002").await.unwrap();
                    s.set_nodelay(true).unwrap();
                    let t = c.connect(ServerName::try_from("relay.example").unwrap(), s).await.unwrap();
                    sink(t).await
                }));
            }
        }
        _ => {
            let src = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let src_addr = src.local_addr().unwrap();
            spawn_source(src, bytes);
            let (tx, rx) = oneshot::channel();
            let cfg = RelayConfig {
                listen: "127.0.0.1:40003".parse().unwrap(),
                upstream: src_addr.to_string(),
                psk_file: psk.clone(),
                cert: dir.join("cert.pem"),
                key: dir.join("key.pem"),
                quota_bytes: u64::MAX / 4,
                state: dir.join("relay.json"),
                window_kb: None,
            };
            tokio::spawn(async move { serve_relay(cfg, tx).await.unwrap() });
            let relay_addr = rx.await.unwrap();
            let (tx, rx) = oneshot::channel();
            let cfg = BalanceConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                psk_file: psk,
                state: dir.join("bal.json"),
                max_rtt_ms: 60_000,
                probe_secs: 30,
                allow: vec![src_addr.to_string()],
                sessions: Some(sessions),
                window_kb: std::env::var("WINDOW_KB").ok().and_then(|v| v.parse().ok()),
                relay: vec![BalanceRelay {
                    name: "local".into(),
                    addr: relay_addr.to_string(),
                    sni: "relay.example".into(),
                    pin_sha256: encode_hex(&pin),
                    quota_bytes: u64::MAX / 4,
                    //SESSIONS
                }],
            };
            tokio::spawn(async move { serve_balance(cfg, tx).await.unwrap() });
            let socks = rx.await.unwrap();
            // warm the mux session(s)
            tokio::time::sleep(Duration::from_millis(1500)).await;
            started = Instant::now();
            for _ in 0..streams {
                tasks.push(tokio::spawn(async move {
                    let s = socks_connect(socks, src_addr.port()).await;
                    sink(s).await
                }));
            }
        }
    }
    let mut total = 0u64;
    let mut short = 0;
    for t in tasks {
        let got = t.await.unwrap();
        if got != bytes {
            short += 1;
        }
        total += got;
    }
    let secs = started.elapsed().as_secs_f64();
    let _ = std::fs::remove_dir_all(&dir);
    println!(
        "mode={mode} streams={streams} sessions={sessions} MB={:.0} secs={secs:.2} MB/s={:.1} Mbps={:.0} short={short}",
        total as f64 / 1048576.0,
        total as f64 / 1048576.0 / secs,
        total as f64 * 8.0 / 1e6 / secs
    );
    if let Some(hold) = std::env::var("HOLD_SECS").ok().and_then(|v| v.parse().ok()) {
        // keep sessions up so `lsof`/`ss` can look for CLOSE_WAIT leftovers
        tokio::time::sleep(Duration::from_secs(hold)).await;
    }
    let _ = Arc::new(());
}
