use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use entry_net::auth::PURPOSE_OPEN;
use entry_net::balance::{serve as serve_balance, BalanceConfig, RelayConfig as BalanceRelay};
use entry_net::relay::{serve as serve_relay, RelayConfig};
use entry_net::tlsutil::{encode_hex, write_self_signed};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

#[tokio::test]
async fn socks_reaches_upstream_through_relay() {
    let dir = std::env::temp_dir().join(format!("entry-relay-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pin = write_self_signed(&dir, "relay.example").unwrap();
    let psk_path = dir.join("psk");
    std::fs::write(&psk_path, b"integration-test-psk").unwrap();

    let hits = Arc::new(AtomicUsize::new(0));
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let hits2 = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = echo.accept().await else { break };
            hits2.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4];
            if sock.read_exact(&mut buf).await.is_ok() {
                let _ = sock.write_all(b"pong").await;
            }
        }
    });

    let (relay_tx, relay_rx) = oneshot::channel();
    let relay_cfg = RelayConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        upstream: echo_addr.to_string(),
        psk_file: psk_path.clone(),
        cert: dir.join("cert.pem"),
        key: dir.join("key.pem"),
        quota_bytes: 10_000_000,
        state: dir.join("relay-state.json"),
        window_kb: None,
    };
    tokio::spawn(async move { serve_relay(relay_cfg, relay_tx).await.unwrap() });
    let relay_addr = relay_rx.await.unwrap();

    let (bal_tx, bal_rx) = oneshot::channel();
    let bal_cfg = BalanceConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        psk_file: psk_path,
        state: dir.join("balance-state.json"),
        max_rtt_ms: 5_000,
        probe_secs: 30,
        allow: vec![echo_addr.to_string()],
        sessions: Some(2),
        window_kb: None,
        relay: vec![BalanceRelay {
            name: "local".into(),
            addr: relay_addr.to_string(),
            sni: "relay.example".into(),
            pin_sha256: encode_hex(&pin),
            quota_bytes: 10_000_000,
        }],
    };
    tokio::spawn(async move { serve_balance(bal_cfg, bal_tx).await.unwrap() });
    let socks_addr = bal_rx.await.unwrap();

    let mut sock = TcpStream::connect(socks_addr).await.unwrap();
    sock.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    sock.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let ip = match echo_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        _ => panic!("expected ipv4"),
    };
    let port = echo_addr.port().to_be_bytes();
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&port);
    sock.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    sock.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "socks connect failed: {reply:?}");
    sock.write_all(b"ping").await.unwrap();
    let mut got = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut got)).await.unwrap().unwrap();
    assert_eq!(&got, b"pong");

    let mut again = TcpStream::connect(socks_addr).await.unwrap();
    again.write_all(&[5, 1, 0]).await.unwrap();
    again.read_exact(&mut method).await.unwrap();
    again.write_all(&req).await.unwrap();
    again.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "second socks connect failed: {reply:?}");
    again.write_all(b"ping").await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), again.read_exact(&mut got)).await.unwrap().unwrap();
    assert_eq!(&got, b"pong");
    assert!(hits.load(Ordering::SeqCst) >= 2);
    let _ = PURPOSE_OPEN;
    let _ = std::fs::remove_dir_all(&dir);
}
