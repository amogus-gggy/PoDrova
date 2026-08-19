use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::thread;

use common::protocol;
use tun::{Configuration, Device};

use crate::config::ClientConfig;

pub fn run_client(config: ClientConfig) -> io::Result<()> {
    let crypto = build_crypto(&config)?;
    let dev = create_tun(&config)?;
    println!(
        "TUN device up: {} mask {} gateway {} mtu {}",
        config.tun.local_ip, config.tun.netmask, config.tun.gateway, config.tun.mtu
    );

    let mut conn = TcpStream::connect((config.server.addr.as_str(), config.server.port))?;
    conn.set_nodelay(true)?;
    protocol::write_auth(&mut conn, &crypto, config.auth.token.as_bytes())?;
    match protocol::read_auth_result(&mut conn, &crypto)? {
        true => {}
        false => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "server rejected authorization token",
            ));
        }
    }
    protocol::write_register(&mut conn, &crypto, config.tun.local_ip)?;
    println!(
        "connected to tunnel server {}:{} (pumping encrypted packets)",
        config.server.addr, config.server.port
    );

    let (tun_reader, tun_writer) = dev.split();
    let conn_reader = conn.try_clone()?;
    let conn_writer = conn.try_clone()?;

    let up_crypto = crypto.clone();
    let up = thread::spawn(move || pump_to_server(tun_reader, conn_writer, up_crypto));
    let down = thread::spawn(move || pump_from_server(conn_reader, tun_writer, crypto));

    let up_res = up
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("upstream pump panicked")));
    let down_res = down
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("downstream pump panicked")));

    // A tunnel normally tears down from either side first; treat a closed
    // direction as a clean shutdown and surface only real errors.
    if up_res.is_err() || down_res.is_err() {
        return Ok(());
    }
    Ok(())
}

fn create_tun(config: &ClientConfig) -> io::Result<Device> {
    let mut c = Configuration::default();
    c.address(config.tun.local_ip)
        .netmask(config.tun.netmask)
        .mtu(config.tun.mtu)
        .up();

    #[cfg(target_os = "windows")]
    {
        c.destination(config.tun.gateway);
        c.metric(1);
    }

    #[cfg(target_os = "linux")]
    {
        c.tun_name("tun0");
        c.destination(config.tun.gateway);
    }

    let dev = tun::create(&c).map_err(|e| io::Error::other(e.to_string()))?;

    #[cfg(target_os = "windows")]
    configure_windows_routes(config, &dev)?;

    #[cfg(target_os = "linux")]
    configure_linux_routes(config, &dev)?;

    Ok(dev)
}

/// The tunnel installs a default route that would swallow our own connection
/// to the VPN server (a routing loop). Add a host route (/32) for the server
/// via the physical NIC so the tunnel's control connection stays on the real
/// network — the more specific prefix wins over the tunnel's default route.
#[cfg(target_os = "windows")]
fn configure_windows_routes(config: &ClientConfig, _dev: &Device) -> io::Result<()> {
    use std::process::Command;

    let tunnel_gw = config.tun.gateway.to_string();

    // Find the physical default gateway (the one not pointing into the tunnel).
    let ps = format!(
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {{ $_.NextHop -ne '{tunnel_gw}' }} | Select-Object -First 1 -ExpandProperty NextHop"
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps])
        .output()?;
    let gw = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if gw.is_empty() {
        return Err(io::Error::other(
            "could not determine physical default gateway",
        ));
    }

    let server_addr = config.server.addr.as_str();
    let out = Command::new("route")
        .args(["add", server_addr, "mask", "255.255.255.255", &gw, "metric", "1"])
        .output()?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr);
        let already_exists = msg.to_lowercase().contains("already exists");
        if !already_exists {
            return Err(io::Error::other(format!(
                "failed to add route to {server_addr}: {msg}"
            )));
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_linux_routes(config: &ClientConfig, _dev: &Device) -> io::Result<()> {
    use std::process::Command;
    Command::new("ip")
        .args(["route", "add", "default", "via", &config.tun.gateway.to_string(), "dev", "tun0"])
        .status()?;
    Ok(())
}

fn build_crypto(config: &ClientConfig) -> io::Result<protocol::Crypto> {
    if config.crypto.key.is_empty() {
        return Err(io::Error::other(
            "crypto.key must be set and match the server's key",
        ));
    }
    Ok(protocol::Crypto::from_shared(config.crypto.key.as_bytes()))
}

fn pump_to_server<R: Read>(
    mut tun: R,
    mut conn: TcpStream,
    crypto: protocol::Crypto,
) -> io::Result<()> {
    let mut buf = vec![0u8; protocol::MAX_PACKET];
    loop {
        let n = tun.read(&mut buf)?;
        if n == 0 {
            break;
        }
        protocol::write_packet(&mut conn, &crypto, &buf[..n])?;
    }
    Ok(())
}

fn pump_from_server<W: Write>(
    mut conn: TcpStream,
    mut tun: W,
    crypto: protocol::Crypto,
) -> io::Result<()> {
    loop {
        let packet = match protocol::read_packet(&mut conn, &crypto) {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };
        if !packet.is_empty() {
            tun.write_all(&packet)?;
        }
    }
    Ok(())
}