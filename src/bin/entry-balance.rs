use std::path::PathBuf;

use clap::Parser;
use entry_net::balance::{serve_on, BalanceConfig};
use entry_net::reload;
use tokio::sync::oneshot;

#[derive(Parser)]
#[command(name = "entry-balance")]
struct Cli {
    #[arg(long)]
    config: PathBuf,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let cli = Cli::parse();
    let raw = std::fs::read_to_string(&cli.config)?;
    let config: BalanceConfig = toml::from_str(&raw)?;
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
