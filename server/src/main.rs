use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use common::protocol::Message;

const LISTEN_ADDR: &str = "0.0.0.0:7878";

fn main() -> io::Result<()> {
    let listener = TcpListener::bind(LISTEN_ADDR)?;
    println!("VPN server listening on {LISTEN_ADDR}");

    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                eprintln!("failed to accept connection: {e}");
                continue;
            }
        };

        thread::spawn(move || {
            if let Err(e) = handle_session(stream) {
                eprintln!("session error: {e}");
            }
        });
    }

    Ok(())
}

fn handle_session(stream: TcpStream) -> io::Result<()> {
    let mut vpn = stream;
    vpn.set_nodelay(true)?;

    let (id, addr) = match Message::read(&mut vpn)? {
        Message::Connect { id, addr } => (id, addr),
        _ => return Err(io::Error::other("expected a Connect frame")),
    };

    let dest = match addr.connect() {
        Ok(s) => {
            s.set_nodelay(true)?;
            Message::connected(id).write(&mut vpn)?;
            s
        }
        Err(_) => {
            Message::error(id, 1).write(&mut vpn)?;
            return Ok(());
        }
    };

    relay(vpn, dest, id)
}

fn relay(vpn: TcpStream, dest: TcpStream, id: u16) -> io::Result<()> {
    let vpn_reader = vpn.try_clone()?;
    let vpn_writer = vpn.try_clone()?;
    let dest_reader = dest.try_clone()?;
    let dest_writer = dest.try_clone()?;

    let to_dest = thread::spawn(move || relay_to_dest(vpn_reader, dest_writer));
    let to_vpn = thread::spawn(move || relay_to_vpn(dest_reader, vpn_writer, id));

    to_dest
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("vpn->dest relay panicked")))?;
    to_vpn
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("dest->vpn relay panicked")))?;

    Ok(())
}

fn relay_to_dest(mut vpn: TcpStream, mut dest: TcpStream) -> io::Result<()> {
    loop {
        match Message::read(&mut vpn) {
            Ok(Message::Data { payload, .. }) => dest.write_all(&payload)?,
            Ok(_) => continue,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn relay_to_vpn(mut dest: TcpStream, mut vpn: TcpStream, id: u16) -> io::Result<()> {
    let mut buf = [0u8; common::protocol::MAX_PAYLOAD];
    loop {
        let n = dest.read(&mut buf)?;
        if n == 0 {
            break;
        }
        Message::data(id, buf[..n].to_vec()).write(&mut vpn)?;
    }
    Ok(())
}