use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpStream, ToSocketAddrs};

// Frame layout: [u32 length BE][body]
// body: [u8 type][...]
//  - Connect:  type=0x01, id(u16), atyp(u8), address
//  - Data:     type=0x02, id(u16), payload
//  - Error:    type=0x03, id(u16), code(u8)
//  - Connected:type=0x00, id(u16)   (server confirms the destination is open)

pub const TYPE_CONNECTED: u8 = 0x00;
pub const TYPE_CONNECT: u8 = 0x01;
pub const TYPE_DATA: u8 = 0x02;
pub const TYPE_ERROR: u8 = 0x03;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

pub const MAX_PAYLOAD: usize = 64 * 1024;
const FRAME_HEADER: usize = 5;

// Network-layer tunnel framing over the transport connection.
// A registration frame fixes the client's virtual IP, then both sides
// exchange raw IP packets as [u32 length BE][payload].
pub const TYPE_REGISTER: u8 = 0x01;

pub const MAX_PACKET: usize = u16::MAX as usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Ipv4(Ipv4Addr, u16),
    Ipv6(Ipv6Addr, u16),
    Domain(String, u16),
}

impl Address {
    pub fn port(&self) -> u16 {
        match self {
            Address::Ipv4(_, p) | Address::Ipv6(_, p) | Address::Domain(_, p) => *p,
        }
    }

    pub fn atyp(&self) -> u8 {
        match self {
            Address::Ipv4(..) => ATYP_IPV4,
            Address::Ipv6(..) => ATYP_IPV6,
            Address::Domain(..) => ATYP_DOMAIN,
        }
    }

    pub fn parse(reader: &mut impl Read, atyp: u8) -> io::Result<Address> {
        match atyp {
            ATYP_IPV4 => {
                let mut bytes = [0u8; 4];
                reader.read_exact(&mut bytes)?;
                let addr = Ipv4Addr::from(bytes);
                let port = read_u16_be(reader)?;
                Ok(Address::Ipv4(addr, port))
            }
            ATYP_IPV6 => {
                let mut bytes = [0u8; 16];
                reader.read_exact(&mut bytes)?;
                let addr = Ipv6Addr::from(bytes);
                let port = read_u16_be(reader)?;
                Ok(Address::Ipv6(addr, port))
            }
            ATYP_DOMAIN => {
                let len = read_u8(reader)? as usize;
                let mut bytes = vec![0u8; len];
                reader.read_exact(&mut bytes)?;
                let host = String::from_utf8(bytes)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8 domain"))?;
                let port = read_u16_be(reader)?;
                Ok(Address::Domain(host, port))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported address type: {other:#04x}"),
            )),
        }
    }

    fn write_into(&self, w: &mut impl Write) -> io::Result<()> {
        match self {
            Address::Ipv4(a, p) => {
                w.write_all(&a.octets())?;
                w.write_all(&p.to_be_bytes())?;
            }
            Address::Ipv6(a, p) => {
                w.write_all(&a.octets())?;
                w.write_all(&p.to_be_bytes())?;
            }
            Address::Domain(host, p) => {
                w.write_all(&[host.len() as u8])?;
                w.write_all(host.as_bytes())?;
                w.write_all(&p.to_be_bytes())?;
            }
        }
        Ok(())
    }

    pub fn connect(&self) -> io::Result<TcpStream> {
        match self {
            Address::Ipv4(a, p) => TcpStream::connect((*a, *p)),
            Address::Ipv6(a, p) => TcpStream::connect((*a, *p)),
            Address::Domain(host, port) => {
                let mut addrs = (host.as_str(), *port).to_socket_addrs()?;
                let addr = addrs
                    .next()
                    .ok_or_else(|| io::Error::other("destination has no addresses"))?;
                TcpStream::connect(addr)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    Connected { id: u16 },
    Connect { id: u16, addr: Address },
    Data { id: u16, payload: Vec<u8> },
    Error { id: u16, code: u8 },
}

impl Message {
    pub fn connected(id: u16) -> Message {
        Message::Connected { id }
    }

    pub fn connect(id: u16, addr: Address) -> Message {
        Message::Connect { id, addr }
    }

    pub fn data(id: u16, payload: Vec<u8>) -> Message {
        Message::Data { id, payload }
    }

    pub fn error(id: u16, code: u8) -> Message {
        Message::Error { id, code }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        match self {
            Message::Connected { id } => {
                body.push(TYPE_CONNECTED);
                body.extend_from_slice(&id.to_be_bytes());
            }
            Message::Connect { id, addr } => {
                body.push(TYPE_CONNECT);
                body.extend_from_slice(&id.to_be_bytes());
                body.push(addr.atyp());
                let mut a = Vec::new();
                let _ = addr.write_into(&mut a);
                body.extend_from_slice(&a);
            }
            Message::Data { id, payload } => {
                body.push(TYPE_DATA);
                body.extend_from_slice(&id.to_be_bytes());
                body.extend_from_slice(payload);
            }
            Message::Error { id, code } => {
                body.push(TYPE_ERROR);
                body.extend_from_slice(&id.to_be_bytes());
                body.push(*code);
            }
        }

        let mut framed = Vec::with_capacity(FRAME_HEADER + body.len());
        framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
        framed.extend_from_slice(&body);
        framed
    }

    pub fn write(&self, w: &mut impl Write) -> io::Result<()> {
        w.write_all(&self.encode())?;
        w.flush()
    }

    pub fn read(reader: &mut impl Read) -> io::Result<Message> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > MAX_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame too large: {len}"),
            ));
        }

        let mut body = vec![0u8; len];
        reader.read_exact(&mut body)?;

        let mut cur = body.as_slice();
        let msg_type = read_u8(&mut cur)?;
        let id = read_u16_be(&mut cur)?;

        match msg_type {
            TYPE_CONNECTED => Ok(Message::Connected { id }),
            TYPE_CONNECT => {
                let atyp = read_u8(&mut cur)?;
                let addr = Address::parse(&mut cur, atyp)?;
                Ok(Message::Connect { id, addr })
            }
            TYPE_DATA => Ok(Message::Data {
                id,
                payload: cur.to_vec(),
            }),
            TYPE_ERROR => {
                let code = read_u8(&mut cur)?;
                Ok(Message::Error { id, code })
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown message type: {other:#04x}"),
            )),
        }
    }
}

/// Serialize a raw IP packet as [u32 length BE][payload].
pub fn write_packet(writer: &mut impl Write, packet: &[u8]) -> io::Result<()> {
    if packet.len() > MAX_PACKET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("packet too large: {}", packet.len()),
        ));
    }
    writer.write_all(&(packet.len() as u32).to_be_bytes())?;
    writer.write_all(packet)?;
    writer.flush()
}

/// Read one length-prefixed raw IP packet.
pub fn read_packet(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_PACKET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("packet too large: {len}"),
        ));
    }
    let mut packet = vec![0u8; len];
    reader.read_exact(&mut packet)?;
    Ok(packet)
}

/// Client-side handshake: tell the server which virtual IP this tunnel owns.
pub fn write_register(writer: &mut impl Write, ip: Ipv4Addr) -> io::Result<()> {
    writer.write_all(&[TYPE_REGISTER])?;
    writer.write_all(&ip.octets())?;
    writer.flush()
}

/// Server-side handshake: learn the virtual IP of an incoming tunnel.
pub fn read_register(reader: &mut impl Read) -> io::Result<Ipv4Addr> {
    let mut tag = [0u8; 1];
    reader.read_exact(&mut tag)?;
    if tag[0] != TYPE_REGISTER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected register frame, got {:#04x}", tag[0]),
        ));
    }
    let mut bytes = [0u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(Ipv4Addr::from(bytes))
}

fn read_u8(reader: &mut impl Read) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_u16_be(reader: &mut impl Read) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}