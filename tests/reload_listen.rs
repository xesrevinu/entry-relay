//! The master keeps the listen port. SIGUSR2 starts a new worker; a socket
//! accepted by the old worker stays open, and a new handshake still succeeds.
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

fn children(pid: u32) -> Vec<u32> {
    let out = std::process::Command::new("pgrep").args(["-P", &pid.to_string()]).output().expect("pgrep");
    String::from_utf8_lossy(&out.stdout).split_whitespace().filter_map(|s| s.parse().ok()).collect()
}

fn greet(port: u16) -> std::io::Result<TcpStream> {
    let mut sock = TcpStream::connect(("127.0.0.1", port))?;
    sock.set_nodelay(true)?;
    sock.set_read_timeout(Some(Duration::from_secs(2)))?;
    sock.write_all(&[5, 1, 0])?;
    let mut reply = [0u8; 2];
    sock.read_exact(&mut reply)?;
    if reply != [5, 0] {
        return Err(std::io::Error::other(format!("socks greeting {reply:?}")));
    }
    Ok(sock)
}

#[test]
fn usr2_keeps_the_accepted_socket_and_the_port() {
    let dir = std::env::temp_dir().join(format!("entry-reload-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("psk"), b"reload-test-psk-32-bytes-padding!").unwrap();
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let pin = "00".repeat(32);
    let toml = format!(
        r#"
listen = "127.0.0.1:{port}"
psk_file = "{dir}/psk"
state = "{dir}/state.json"
max_rtt_ms = 1000
probe_secs = 60
allow = []
sessions = 1

[[relay]]
name = "local"
addr = "127.0.0.1:1"
sni = "relay.example"
pin_sha256 = "{pin}"
quota_bytes = 1000
"#,
        dir = dir.display()
    );
    let cfg = dir.join("balance.toml");
    std::fs::write(&cfg, toml).unwrap();

    let exe = env!("CARGO_BIN_EXE_entry-balance");
    let mut master = std::process::Command::new(exe)
        .arg("--config")
        .arg(&cfg)
        .env("ENTRY_DRAIN_SECS", "5")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn master");
    let pid = master.id();

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut held = loop {
        if Instant::now() > deadline {
            let _ = master.kill();
            panic!("worker never accepted");
        }
        if let Ok(sock) = greet(port) {
            break sock;
        }
        std::thread::sleep(Duration::from_millis(40));
    };
    let before = children(pid);
    assert!(!before.is_empty(), "master has no worker");

    let status = std::process::Command::new("kill").args(["-USR2", &pid.to_string()]).status().unwrap();
    assert!(status.success(), "SIGUSR2");

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut spawned = false;
    while Instant::now() < deadline {
        let now = children(pid);
        if now.iter().any(|p| !before.contains(p)) && before.iter().all(|p| now.contains(p)) {
            spawned = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    assert!(spawned, "reload did not keep the old worker and add a new one: before {before:?} now {:?}", children(pid));

    let _fresh = greet(port);
    held.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let mut buf = [0u8; 1];
    match held.read(&mut buf) {
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock || err.kind() == std::io::ErrorKind::TimedOut => {}
        other => panic!("held socket did not stay open: {other:?}"),
    }

    drop(held);
    let old = before[0];
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && children(pid).contains(&old) {
        std::thread::sleep(Duration::from_millis(40));
    }
    assert!(!children(pid).contains(&old), "drained worker still alive");

    let _ = master.kill();
    let _ = master.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
