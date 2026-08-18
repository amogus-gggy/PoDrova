use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::thread;

use common::protocol::{Address, Message};

use crate::socks5::{self, CMD_CONNECT, REP_COMMAND_NOT_SUPPORTED, REP_GENERAL_FAILURE, REP_SUCCEEDED};

#[derive(Debug, Clone)]
pub struct VpnServerConfig {
    pub address: String,
    pub port: u16,
}

pub fn handle_connection(stream: TcpStream, config: VpnServerConfig) -> io::Result<()> {
    let mut local = stream;
    local.set_nodelay(true)?;

    socks5::read_greeting(&mut local)?;
    socks5::write_method_selection(&mut local)?;

    let request = socks5::read_connect_request(&mut local)?;

    if request.cmd != CMD_CONNECT {
        let _ = socks5::write_reply(
            &mut local,
            REP_COMMAND_NOT_SUPPORTED,
            socks5::hint_bind(&request.addr),
        );
        return Ok(());
    }

    let dest = request.addr;
    let id = session_id();
    let bind = socks5::hint_bind(&dest);

    match establish(&mut local, dest, id, &config) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = socks5::write_reply(&mut local, REP_GENERAL_FAILURE, bind);
            Err(e)
        }
    }
}

fn establish(
    local: &mut TcpStream,
    dest: Address,
    id: u16,
    config: &VpnServerConfig,
) -> io::Result<()> {
    let mut vpn = TcpStream::connect((config.address.as_str(), config.port))?;
    vpn.set_nodelay(true)?;

    Message::connect(id, dest.clone()).write(&mut vpn)?;

    match Message::read(&mut vpn)? {
        Message::Connected { .. } => {
            socks5::write_reply(local, REP_SUCCEEDED, socks5::hint_bind(&dest))?;
            tunnel(local, vpn, id)
        }
        Message::Error { .. } => {
            socks5::write_reply(local, REP_GENERAL_FAILURE, socks5::hint_bind(&dest))?;
            Ok(())
        }
        _ => Err(io::Error::other("unexpected reply from vpn server")),
    }
}

fn tunnel(local: &mut TcpStream, vpn: TcpStream, id: u16) -> io::Result<()> {
    let local_reader = local.try_clone()?;
    let local_writer = local.try_clone()?;
    let vpn_writer = vpn.try_clone()?;

    let up = thread::spawn(move || pump_up(local_reader, vpn_writer, id));
    let down = thread::spawn(move || pump_down(vpn, local_writer));

    let up_res = up
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("upstream pump panicked")));
    let down_res = down
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("downstream pump panicked")));

    // A normal tunnel shutdown may have either side closed first; ignore EOF
    // and propagate real errors only.
    if up_res.is_err() || down_res.is_err() {
        return Ok(());
    }
    Ok(())
}

fn pump_up(mut src: TcpStream, mut dst: TcpStream, id: u16) -> io::Result<()> {
    let mut buf = [0u8; common::protocol::MAX_PAYLOAD];
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        Message::data(id, buf[..n].to_vec()).write(&mut dst)?;
    }
    Ok(())
}

fn pump_down(mut src: TcpStream, mut dst: TcpStream) -> io::Result<()> {
    loop {
        match Message::read(&mut src) {
            Ok(Message::Data { payload, .. }) => dst.write_all(&payload)?,
            Ok(_) => continue,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn session_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}