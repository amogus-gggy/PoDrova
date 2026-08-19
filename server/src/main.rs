use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

mod config;

use common::protocol;
use tun::{Configuration, Device, Reader, Writer};

const CONFIG_PATH: &str = "server.toml";

/// Routes packets arriving on the server TUN interface back to the client
/// that owns the destination virtual IP.
struct Router {
    clients: Mutex<HashMap<Ipv4Addr, Sender<Vec<u8>>>>,
    tun_writer: Arc<Mutex<Writer>>,
}

fn main() -> io::Result<()> {
    let cfg = config::ServerConfig::load(Path::new(CONFIG_PATH))?;
    let gateway = cfg.gateway;
    let netmask = cfg.netmask;
    let mtu = cfg.mtu;

    let allowed_tokens = cfg.allowed_tokens()?;
    println!("authorization enabled ({} allowed token(s))", allowed_tokens.len());

    let dev = create_tun(gateway, netmask, mtu)?;
    println!("TUN router up: {} mask {} mtu {}", gateway, netmask, mtu);

    #[cfg(target_os = "linux")]
    enable_linux_forwarding(&cfg)?;

    let (tun_reader, tun_writer) = dev.split();
    let router = Arc::new(Router {
        clients: Mutex::new(HashMap::new()),
        tun_writer: Arc::new(Mutex::new(tun_writer)),
    });

    let tun_router = Arc::clone(&router);
    thread::spawn(move || run_tun_reader(tun_reader, tun_router));

    let listener = TcpListener::bind(&cfg.listen_addr)?;
    println!("tunnel server listening on {}", cfg.listen_addr);

    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                eprintln!("failed to accept connection: {e}");
                continue;
            }
        };

        let router = Arc::clone(&router);
        let allowed_tokens = allowed_tokens.clone();
        thread::spawn(move || {
            if let Err(e) = handle_session(stream, router, &allowed_tokens) {
                eprintln!("session error: {e}");
            }
        });
    }

    Ok(())
}

fn create_tun(gateway: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> io::Result<Device> {
    let mut c = Configuration::default();
    c.address(gateway).netmask(netmask).mtu(mtu).up();

    #[cfg(target_os = "linux")]
    {
        c.tun_name("tun0");
        c.destination(Ipv4Addr::new(0, 0, 0, 0));
    }

    tun::create(&c).map_err(|e| io::Error::other(e.to_string()))
}

#[cfg(target_os = "linux")]
fn enable_linux_forwarding(cfg: &config::ServerConfig) -> io::Result<()> {
    use std::process::Command;

    // Allow the kernel to route traffic between the tunnel and the internet.
    Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .status()?;

    // Masquerade client virtual addresses behind the server's own address so
    // return traffic is routed back into the tunnel. Requires root/iptables and
    // the name of the server's outbound interface.
    if let Some(iface) = &cfg.nat_iface {
        let present = Command::new("iptables")
            .args(["-t", "nat", "-C", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !present {
            Command::new("iptables")
                .args(["-t", "nat", "-A", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])
                .status()?;
        }
    } else {
        eprintln!(
            "nat_iface not set; run iptables -t nat -A POSTROUTING -o <iface> -j MASQUERADE manually"
        );
    }

    Ok(())
}

/// Reads packets from the TUN router and delivers each to the client that owns
/// the packet's destination IP.
fn run_tun_reader(mut tun_reader: Reader, router: Arc<Router>) {
    let mut buf = vec![0u8; protocol::MAX_PACKET];
    while let Ok(n) = tun_reader.read(&mut buf) {
        let Some(dst) = destination_ipv4(&buf[..n]) else {
            continue;
        };
        let payload = buf[..n].to_vec();
        let clients = router.clients.lock().unwrap();
        if let Some(tx) = clients.get(&dst) {
            let _ = tx.send(payload);
        }
    }
}

/// Reads the list of authorized client tokens.
/// When the allowlist is empty every connection is rejected.
fn handle_session(
    stream: TcpStream,
    router: Arc<Router>,
    allowed_tokens: &std::collections::HashSet<Vec<u8>>,
) -> io::Result<()> {
    let mut conn = stream;
    conn.set_nodelay(true)?;

    // Authorization: the client must present a token that is on the allowlist
    // (mirrors WireGuard's allowed-peers check, minus encryption).
    let token = protocol::read_auth(&mut conn)?;
    let authorized = allowed_tokens.contains(&token);
    protocol::write_auth_result(&mut conn, authorized)?;
    if !authorized {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "client token is not authorized",
        ));
    }

    let client_ip = protocol::read_register(&mut conn)?;
    let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();
    {
        let mut clients = router.clients.lock().unwrap();
        if clients.insert(client_ip, tx).is_some() {
            eprintln!("duplicate tunnel for {client_ip}; evicting previous");
        }
    }
    println!("tunnel registered for {client_ip}");

    let conn_reader = conn.try_clone()?;
    let conn_writer = conn;

    let tun_writer = Arc::clone(&router.tun_writer);
    let to_tun = thread::spawn(move || pump_client_to_tun(conn_reader, tun_writer));
    let from_tun = thread::spawn(move || pump_tun_to_client(rx, conn_writer));

    let to_tun_res = to_tun
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("client->tun pump panicked")));
    let from_tun_res = from_tun
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("tun->client pump panicked")));

    // Deregister so the TUN reader stops routing to this (now closed) client.
    {
        let mut clients = router.clients.lock().unwrap();
        clients.remove(&client_ip);
    }
    println!("tunnel closed for {client_ip}");

    if to_tun_res.is_err() || from_tun_res.is_err() {
        return Err(io::Error::other("tunnel relay error"));
    }
    Ok(())
}

fn pump_client_to_tun(mut conn: TcpStream, tun_writer: Arc<Mutex<Writer>>) -> io::Result<()> {
    loop {
        let packet = match protocol::read_packet(&mut conn) {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };
        if packet.is_empty() {
            continue;
        }
        tun_writer.lock().unwrap().write_all(&packet)?;
    }
    Ok(())
}

fn pump_tun_to_client(rx: Receiver<Vec<u8>>, mut conn: TcpStream) -> io::Result<()> {
    while let Ok(packet) = rx.recv() {
        protocol::write_packet(&mut conn, &packet)?;
    }
    Ok(())
}

/// Extract the destination IPv4 address from an IPv4 packet.
fn destination_ipv4(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 {
        return None;
    }
    if packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]))
}