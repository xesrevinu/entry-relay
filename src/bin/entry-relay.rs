use std::path::PathBuf;
use std::time::SystemTime;

use clap::{Parser, Subcommand};
use entry_net::relay::{serve_on, RelayConfig};
use entry_net::reload;
use entry_net::tlsutil::{encode_hex, write_self_signed};
use tokio::sync::oneshot;

#[derive(Parser)]
#[command(name = "entry-relay")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Listen for authenticated TLS sessions and forward them upstream.
    Run { #[arg(long)] config: PathBuf },
    /// Write a self-signed certificate and its SHA-256 pin.
    GenCert { #[arg(long)] out: PathBuf, #[arg(long, default_value = "relay.example")] name: String },
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    match Cli::parse().command {
        Command::GenCert { out, name } => {
            let pin = write_self_signed(&out, &name)?;
            println!("{}", encode_hex(&pin));
            Ok(())
        }
        Command::Run { config } => {
            let raw = std::fs::read_to_string(&config)?;
            let config: RelayConfig = toml::from_str(&raw)?;
            let _ = SystemTime::now();
            if reload::is_worker() {
                let listener = reload::adopt_listener()?;
                let gate = reload::Gate::forever();
                reload::arm_drain(std::sync::Arc::clone(&gate));
                let (tx, _rx) = oneshot::channel();
                return serve_on(config, listener, tx, gate).await;
            }
            let listener = std::net::TcpListener::bind(config.listen)?;
            listener.set_nonblocking(true)?;
            reload::master(listener).await
        }
    }
}
