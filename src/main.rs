mod client;
mod config;
mod crypto;
mod protocol;

use anyhow::{Context, Result, bail};
use config::Config;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config_path = match args.as_slice() {
        [mode, path] if mode == "sc" => path,
        [path] => path,
        _ => bail!("usage: hppt-rs sc <config.yml>"),
    };

    let config = Config::load(config_path).context("load client configuration")?;
    info!(
        transport = %config.kind,
        user = %config.client_user,
        encrypted = config.enable_encrypt,
        forwards = config.forwards.len(),
        "client configuration loaded"
    );
    client::run(config).await
}

fn init_tracing() -> Result<()> {
    let filter = match std::env::var_os("RUST_LOG") {
        Some(value) => EnvFilter::try_new(value.to_str().context("RUST_LOG must be valid UTF-8")?)
            .context("parse RUST_LOG tracing filter")?,
        None => EnvFilter::new("info"),
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_ansi(false)
        .try_init()
        .map_err(|error| anyhow::anyhow!("initialize tracing subscriber: {error}"))
}
