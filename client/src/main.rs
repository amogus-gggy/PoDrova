mod config;
mod tunnel;

use std::io;
use std::path::Path;

use tunnel::run_client;

const CONFIG_PATH: &str = "client.toml";

fn main() -> io::Result<()> {
    let config = config::ClientConfig::load(Path::new(CONFIG_PATH))?;
    run_client(config)
}