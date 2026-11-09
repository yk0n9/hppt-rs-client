mod client;
mod config;
mod crypto;
mod protocol;

use anyhow::{Context, Result, bail};
use config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config_path = match args.as_slice() {
        [mode, path] if mode == "sc" => path,
        [path] => path,
        _ => bail!("usage: hppt-rs sc <config.yml>"),
    };

    let config = Config::load(config_path).context("load client configuration")?;
    client::run(config).await
}
