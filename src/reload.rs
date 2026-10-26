//! Hitless binary upgrade for the two long-lived listeners.
//!
//! systemd and OpenRC track one pid. That process is the master: it binds the
//! port and never accepts. A child worker inherits the socket and accepts.
//! `SIGUSR2` tells the master to start a worker from the binary currently at
//! `argv[0]` (the path just installed) and `SIGQUIT` the previous worker.
//! The previous worker stops accepting, finishes the sockets it already has,
//! then exits. The listen port stays open the whole time, so the local
//! dialer is not restarted and in-flight streams are not reset.
//!
//! `ENTRY_WORKER=1` marks the child. It adopts fd 3. The first cutover from a
//! binary that has no master still needs one restart; every upgrade after that
//! is this signal.

use std::env;
use std::net::SocketAddr;
use std::os::fd::FromRawFd;
use std::os::unix::io::AsRawFd;

use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};


use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Notify;
use tracing::{info, warn};

const WORKER_FD: i32 = 3;
const WORKER_ENV: &str = "ENTRY_WORKER";

pub fn is_worker() -> bool {
    env::var(WORKER_ENV).ok().as_deref() == Some("1")
}

pub struct Gate {
    stop: AtomicBool,
    inflight: AtomicUsize,
    wake: Notify,
}

pub struct Ticket(Arc<Gate>);

impl Drop for Ticket {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::AcqRel);
        self.0.wake.notify_waiters();
    }
}

impl Gate {
    pub fn forever() -> Arc<Self> {
        Arc::new(Self { stop: AtomicBool::new(false), inflight: AtomicUsize::new(0), wake: Notify::new() })
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        self.wake.notify_waiters();
    }

    pub fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Acquire)
    }

    pub async fn wait_idle(&self) {
        let grace = drain_grace();
        let deadline = Instant::now() + grace;
        while self.inflight() > 0 && Instant::now() < deadline {
            let notified = self.wake.notified();
            if self.inflight() == 0 {
                return;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            let _ = tokio::time::timeout(left.min(Duration::from_millis(200)), notified).await;
        }
        if self.inflight() > 0 {
            warn!(left = self.inflight(), grace_ms = grace.as_millis() as u64, "drain grace elapsed, dropping leftover sockets");
        }
    }
}

fn drain_grace() -> Duration {
    let secs = env::var("ENTRY_DRAIN_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(30);
    Duration::from_secs(secs)
}

/// Next accepted socket, or `None` once the worker was told to drain.
pub async fn accept_one(listener: &TcpListener, gate: &Arc<Gate>) -> Option<(TcpStream, SocketAddr, Ticket)> {
    loop {
        if gate.stop.load(Ordering::Acquire) {
            return None;
        }
        let notified = gate.wake.notified();
        tokio::select! {
            biased;
            _ = notified => continue,
            acc = listener.accept() => {
                match acc {
                    Ok((sock, peer)) => {
                        gate.inflight.fetch_add(1, Ordering::AcqRel);
                        return Some((sock, peer, Ticket(Arc::clone(gate))));
                    }
                    Err(err) => {
                        if gate.stop.load(Ordering::Acquire) {
                            return None;
                        }
                        warn!(%err, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }
}

/// Worker: fd 3 is the inherited listener. Clears nothing else.
pub fn adopt_listener() -> std::io::Result<TcpListener> {
    let std_listener = unsafe { std::net::TcpListener::from_raw_fd(WORKER_FD) };
    std_listener.set_nonblocking(true)?;
    TcpListener::from_std(std_listener)
}

/// Stop accepting on SIGQUIT or SIGTERM. SIGUSR2 is swallowed so a signal
/// delivered to the process group does not kill a draining worker.
pub fn arm_drain(gate: Arc<Gate>) {
    tokio::spawn(async move {
        let mut quit = match signal(SignalKind::quit()) {
            Ok(s) => s,
            Err(err) => {
                warn!(%err, "SIGQUIT handler missing");
                return;
            }
        };
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(err) => {
                warn!(%err, "SIGTERM handler missing");
                return;
            }
        };
        let mut usr2 = signal(SignalKind::user_defined2()).ok();
        loop {
            tokio::select! {
                _ = quit.recv() => {
                    info!("worker draining");
                    gate.stop();
                    break;
                }
                _ = term.recv() => {
                    info!("worker draining");
                    gate.stop();
                    break;
                }
                _ = async {
                    match usr2.as_mut() {
                        Some(sig) => { sig.recv().await; }
                        None => std::future::pending().await,
                    }
                } => {}
            }
        }
    });
}

/// Master. Returns when SIGINT/SIGTERM asks the whole service to stop.
pub async fn master(listener: std::net::TcpListener) -> anyhow::Result<()> {
    listener.set_nonblocking(true)?;

    let mut worker = spawn_worker(&listener)?;
    info!(pid = worker.id().unwrap_or(0), "master started worker");
    let mut usr2 = signal(SignalKind::user_defined2())?;
    let mut term = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    loop {
        #[derive(Clone, Copy)]
        enum Action {
            Upgrade,
            Shutdown,
            Crashed,
        }
        let action = tokio::select! {
            _ = usr2.recv() => Action::Upgrade,
            _ = term.recv() => Action::Shutdown,
            _ = interrupt.recv() => Action::Shutdown,
            status = worker.wait() => {
                warn!(?status, "worker exited");
                Action::Crashed
            }
        };
        match action {
            Action::Upgrade => {
                if let Some(pid) = worker.id() {
                    signal_pid(pid, libc::SIGQUIT);
                }
                let mut draining = worker;
                tokio::spawn(async move {
                    let _ = draining.wait().await;
                });
                worker = match spawn_worker(&listener) {
                    Ok(child) => {
                        info!(pid = child.id().unwrap_or(0), "reloaded worker");
                        child
                    }
                    Err(err) => {
                        warn!(%err, "reload spawn failed");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        spawn_worker(&listener)?
                    }
                };
            }
            Action::Shutdown => {
                if let Some(pid) = worker.id() {
                    signal_pid(pid, libc::SIGQUIT);
                }
                let _ = tokio::time::timeout(drain_grace(), worker.wait()).await;
                info!("master exiting");
                return Ok(());
            }
            Action::Crashed => {
                tokio::time::sleep(Duration::from_millis(300)).await;
                worker = spawn_worker(&listener)?;
                info!(pid = worker.id().unwrap_or(0), "restarted worker");
            }
        }
    }
}

fn signal_pid(pid: u32, sig: i32) {
    let rc = unsafe { libc::kill(pid as i32, sig) };
    if rc != 0 {
        warn!(pid, sig, "signal failed");
    }
}

fn spawn_worker(listener: &std::net::TcpListener) -> std::io::Result<tokio::process::Child> {
    let exe = worker_binary();
    let src = listener.as_raw_fd();
    let mut cmd = tokio::process::Command::new(&exe);
    cmd.args(env::args().skip(1))
        .env(WORKER_ENV, "1")
        .stdin(Stdio::null())
        .kill_on_drop(false);
    unsafe {
        cmd.pre_exec(move || {
            if src != WORKER_FD && libc::dup2(src, WORKER_FD) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let flags = libc::fcntl(WORKER_FD, libc::F_GETFD);
            if flags >= 0 {
                libc::fcntl(WORKER_FD, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
            }
            Ok(())
        });
    }
    cmd.spawn()
}

/// Path that opens the binary just installed, not the inode this master was
/// exec'd from. `/proc/self/exe` keeps the old inode after `mv` onto the path.
fn worker_binary() -> std::path::PathBuf {
    env::args_os().next().filter(|p| Path::new(p).is_absolute()).map(std::path::PathBuf::from).unwrap_or_else(|| {
        env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("entry-balance"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn drain_waits_for_the_last_ticket() {
        let gate = Gate::forever();
        gate.inflight.fetch_add(1, Ordering::AcqRel);
        let gate2 = Arc::clone(&gate);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            drop(Ticket(gate2));
        });
        let done = tokio::time::timeout(Duration::from_secs(2), gate.wait_idle()).await;
        assert!(done.is_ok());
        assert_eq!(gate.inflight(), 0);
    }
}
