mod socks5;
mod tunnel;

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use tunnel::{handle_connection, VpnServerConfig};

const LISTEN_ADDR: &str = "127.0.0.1:1080";
const DEFAULT_VPN_ADDR: &str = "127.0.0.1";
const DEFAULT_VPN_PORT: u16 = 7878;

fn main() -> io::Result<()> {
    let config = VpnServerConfig {
        address: std::env::var("VPN_SERVER_ADDR").unwrap_or_else(|_| DEFAULT_VPN_ADDR.to_string()),
        port: std::env::var("VPN_SERVER_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_VPN_PORT),
    };

    let listener = TcpListener::bind(LISTEN_ADDR)?;
    println!(
        "SOCKS5 proxy listening on {LISTEN_ADDR} (vpn server {}:{} — connection pending)",
        config.address, config.port
    );

    let config = Arc::new(config);

    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                eprintln!("failed to accept connection: {e}");
                continue;
            }
        };

        let config = Arc::clone(&config);
        thread::spawn(move || {
            if let Err(e) = serve(stream, config) {
                eprintln!("session error: {e}");
            }
        });
    }

    Ok(())
}

fn serve(stream: TcpStream, config: Arc<VpnServerConfig>) -> io::Result<()> {
    handle_connection(stream, (*config).clone())
}
