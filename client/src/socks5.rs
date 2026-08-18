use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use common::protocol::Address;

pub const VERSION: u8 = 0x05;

pub const CMD_CONNECT: u8 = 0x01;

pub const REP_SUCCEEDED: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;

#[derive(Debug, Clone)]
pub struct ConnectRequest {
    pub cmd: u8,
    pub addr: Address,
}

pub fn read_greeting(reader: &mut impl Read) -> io::Result<()> {
    let version = read_u8(reader)?;
    if version != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported socks version: {version:#04x}"),
        ));
    }

    let nmethods = read_u8(reader)? as usize;
    let mut methods = vec![0u8; nmethods];
    reader.read_exact(&mut methods)?;

    if !methods.contains(&0x00) {
        return Err(io::Error::other(
            "client offered no acceptable authentication method",
        ));
    }

    Ok(())
}

pub fn write_method_selection(writer: &mut impl Write) -> io::Result<()> {
    writer.write_all(&[VERSION, 0x00])?;
    Ok(())
}

pub fn read_connect_request(reader: &mut impl Read) -> io::Result<ConnectRequest> {
    let version = read_u8(reader)?;
    if version != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported socks version: {version:#04x}"),
        ));
    }

    let cmd = read_u8(reader)?;
    let _rsv = read_u8(reader)?;
    let atyp = read_u8(reader)?;
    let addr = Address::parse(reader, atyp)?;

    Ok(ConnectRequest { cmd, addr })
}

pub fn write_reply(writer: &mut impl Write, rep: u8, bind: Address) -> io::Result<()> {
    writer.write_all(&[VERSION, rep, 0x00, bind.atyp()])?;
    match bind {
        Address::Ipv4(a, p) => {
            writer.write_all(&a.octets())?;
            writer.write_all(&p.to_be_bytes())?;
        }
        Address::Ipv6(a, p) => {
            writer.write_all(&a.octets())?;
            writer.write_all(&p.to_be_bytes())?;
        }
        Address::Domain(host, p) => {
            writer.write_all(&[host.len() as u8])?;
            writer.write_all(host.as_bytes())?;
            writer.write_all(&p.to_be_bytes())?;
        }
    }
    Ok(())
}

pub fn hint_bind(addr: &Address) -> Address {
    match addr {
        Address::Ipv4(..) => Address::Ipv4(Ipv4Addr::UNSPECIFIED, 0),
        Address::Ipv6(..) => Address::Ipv6(Ipv6Addr::UNSPECIFIED, 0),
        Address::Domain(..) => Address::Ipv4(Ipv4Addr::UNSPECIFIED, 0),
    }
}

fn read_u8(reader: &mut impl Read) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf)?;
    Ok(buf[0])
}