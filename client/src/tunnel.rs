use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::thread;

use common::protocol;
use tun::{Configuration, Device};

use crate::config::ClientConfig;

pub fn run_client(config: ClientConfig) -> io::Result<()> {
    let dev = create_tun(&config)?;
    println!(
        "TUN device up: {} mask {} gateway {} mtu {}",
        config.tun.local_ip, config.tun.netmask, config.tun.gateway, config.tun.mtu
    );

    let mut conn = TcpStream::connect((config.server.addr.as_str(), config.server.port))?;
    conn.set_nodelay(true)?;
    protocol::write_auth(&mut conn, config.auth.token.as_bytes())?;
    match protocol::read_auth_result(&mut conn)? {
        true => {}
        false => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "server rejected authorization token",
            ));
        }
    }
    protocol::write_register(&mut conn, config.tun.local_ip)?;
    println!(
        "connected to tunnel server {}:{} (pumping packets)",
        config.server.addr, config.server.port
    );

    let (tun_reader, tun_writer) = dev.split();
    let conn_reader = conn.try_clone()?;
    let conn_writer = conn.try_clone()?;

    let up = thread::spawn(move || pump_to_server(tun_reader, conn_writer));
    let down = thread::spawn(move || pump_from_server(conn_reader, tun_writer));

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

    #[cfg(target_os = "linux")]
    configure_linux_routes(config, &dev)?;

    Ok(dev)
}

#[cfg(target_os = "linux")]
fn configure_linux_routes(config: &ClientConfig, _dev: &Device) -> io::Result<()> {
    use std::process::Command;
    Command::new("ip")
        .args(["route", "add", "default", "via", &config.tun.gateway.to_string(), "dev", "tun0"])
        .status()?;
    Ok(())
}

fn pump_to_server<R: Read>(mut tun: R, mut conn: TcpStream) -> io::Result<()> {
    let mut buf = vec![0u8; protocol::MAX_PACKET];
    loop {
        let n = tun.read(&mut buf)?;
        if n == 0 {
            break;
        }
        protocol::write_packet(&mut conn, &buf[..n])?;
    }
    Ok(())
}

fn pump_from_server<W: Write>(mut conn: TcpStream, mut tun: W) -> io::Result<()> {
    loop {
        let packet = match protocol::read_packet(&mut conn) {
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