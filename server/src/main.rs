use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use common::protocol;
use tun::{Configuration, Device, Reader, Writer};

const LISTEN_ADDR: &str = "0.0.0.0:7878";
const DEFAULT_GATEWAY: &str = "10.8.0.1";
const DEFAULT_NETMASK: &str = "255.255.255.0";

/// Routes packets arriving on the server TUN interface back to the client
/// that owns the destination virtual IP.
struct Router {
    clients: Mutex<HashMap<Ipv4Addr, Sender<Vec<u8>>>>,
    tun_writer: Arc<Mutex<Writer>>,
}

fn main() -> io::Result<()> {
    let gateway: Ipv4Addr = std::env::var("TUN_GATEWAY")
        .unwrap_or_else(|_| DEFAULT_GATEWAY.to_string())
        .parse()
        .map_err(|_| io::Error::other("TUN_GATEWAY must be a valid IPv4 address"))?;
    let netmask: Ipv4Addr = std::env::var("TUN_NETMASK")
        .unwrap_or_else(|_| DEFAULT_NETMASK.to_string())
        .parse()
        .map_err(|_| io::Error::other("TUN_NETMASK must be a valid IPv4 address"))?;
    let mtu: u16 = std::env::var("TUN_MTU").ok().and_then(|v| v.parse().ok()).unwrap_or(1500);

    let dev = create_tun(gateway, netmask, mtu)?;
    println!("TUN router up: {} mask {} mtu {}", gateway, netmask, mtu);

    #[cfg(target_os = "linux")]
    enable_linux_forwarding()?;

    let (tun_reader, tun_writer) = dev.split();
    let router = Arc::new(Router {
        clients: Mutex::new(HashMap::new()),
        tun_writer: Arc::new(Mutex::new(tun_writer)),
    });

    let tun_router = Arc::clone(&router);
    thread::spawn(move || run_tun_reader(tun_reader, tun_router));

    let listener = TcpListener::bind(LISTEN_ADDR)?;
    println!("tunnel server listening on {LISTEN_ADDR}");

    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                eprintln!("failed to accept connection: {e}");
                continue;
            }
        };

        let router = Arc::clone(&router);
        thread::spawn(move || {
            if let Err(e) = handle_session(stream, router) {
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
fn enable_linux_forwarding() -> io::Result<()> {
    use std::process::Command;

    // Allow the kernel to route traffic between the tunnel and the internet.
    Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .status()?;

    // Masquerade client virtual addresses behind the server's own address so
    // return traffic is routed back into the tunnel. Requires root/iptables and
    // the name of the server's outbound interface.
    if let Ok(iface) = std::env::var("TUN_NAT_IFACE") {
        let present = Command::new("iptables")
            .args(["-t", "nat", "-C", "POSTROUTING", "-o", &iface, "-j", "MASQUERADE"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !present {
            Command::new("iptables")
                .args(["-t", "nat", "-A", "POSTROUTING", "-o", &iface, "-j", "MASQUERADE"])
                .status()?;
        }
    } else {
        eprintln!(
            "TUN_NAT_IFACE not set; run iptables -t nat -A POSTROUTING -o <iface> -j MASQUERADE manually"
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

fn handle_session(stream: TcpStream, router: Arc<Router>) -> io::Result<()> {
    let mut conn = stream;
    conn.set_nodelay(true)?;

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