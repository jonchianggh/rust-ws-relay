//! VLESS (version 0): TCP (command 1) and UDP (command 2). Mux (command 3) is refused.
//! Spec: https://xtls.github.io/development/protocols/vless.html
//!
//! Request:  ver(1) | uuid(16) | addon_len(1) | addons | cmd(1) | port(2 BE) | atyp(1) | addr
//! Response: ver(1) | addon_len(1)=0
//!
//! atyp here is 1=IPv4, 2=domain, 3=IPv6 (different from SOCKS numbering).
//!
//! For UDP, every datagram after the header travels as `len(2 BE) | payload`
//! in both directions, all to and from the one destination in the header.

use super::Request;
use crate::addr::Target;
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const CMD_TCP: u8 = 0x01;
pub const CMD_UDP: u8 = 0x02;
pub const CMD_MUX: u8 = 0x03;

/// What the client asked the relay to do with the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
}

/// Parse a canonical UUID string into 16 bytes.
pub fn parse_uuid(s: &str) -> Result<[u8; 16], ()> {
    let u = uuid::Uuid::parse_str(s).map_err(|_| ())?;
    Ok(*u.as_bytes())
}

/// Read and authenticate a VLESS request header, then send the response
/// header. On success the stream is positioned at the first payload byte.
pub async fn handshake<S>(s: &mut S, expected: &[u8; 16]) -> std::io::Result<(Request, Command)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = s.read_u8().await?;
    if version != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("unsupported VLESS version {version}"),
        ));
    }

    let mut id = [0u8; 16];
    s.read_exact(&mut id).await?;
    if !constant_time_eq(&id, expected) {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "VLESS uuid mismatch",
        ));
    }

    let addon_len = s.read_u8().await? as usize;
    if addon_len > 0 {
        // Addons (e.g. flow) are not supported by this server; skip them.
        let mut skip = vec![0u8; addon_len];
        s.read_exact(&mut skip).await?;
    }

    let cmd = s.read_u8().await?;
    let command = match cmd {
        CMD_TCP => Command::Tcp,
        CMD_UDP => Command::Udp,
        CMD_MUX => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "VLESS mux is not supported",
            ))
        }
        other => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unknown VLESS command {other}"),
            ))
        }
    };

    let port = s.read_u16().await?;
    let atyp = s.read_u8().await?;
    let target = match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await?;
            Target::Ip(Ipv4Addr::from(b).into())
        }
        0x02 => {
            let len = s.read_u8().await? as usize;
            if len == 0 {
                return Err(Error::new(ErrorKind::InvalidData, "empty domain"));
            }
            let mut b = vec![0u8; len];
            s.read_exact(&mut b).await?;
            Target::Domain(
                String::from_utf8(b)
                    .map_err(|_| Error::new(ErrorKind::InvalidData, "non-utf8 domain"))?,
            )
        }
        0x03 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await?;
            Target::Ip(Ipv6Addr::from(b).into())
        }
        other => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("bad VLESS address type {other}"),
            ))
        }
    };

    // Response header: same version, no addons.
    s.write_all(&[version, 0]).await?;
    s.flush().await?;

    Ok((Request { target, port }, command))
}

fn constant_time_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(uuid: &[u8; 16], cmd: u8, host: &str, port: u16) -> Vec<u8> {
        let mut v = vec![0u8];
        v.extend_from_slice(uuid);
        v.push(0);
        v.push(cmd);
        v.extend_from_slice(&port.to_be_bytes());
        v.push(2);
        v.push(host.len() as u8);
        v.extend_from_slice(host.as_bytes());
        v
    }

    #[tokio::test]
    async fn parses_domain_request() {
        let id = parse_uuid("10889da6-14ea-4cc8-97fa-6c0bc410f121").unwrap();
        let mut req = build(&id, CMD_TCP, "example.com", 443);
        req.extend_from_slice(b"GET /");
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(&req).await.unwrap();
        let (r, cmd) = handshake(&mut server, &id).await.unwrap();
        assert_eq!(cmd, Command::Tcp);
        assert_eq!(r.port, 443);
        assert!(matches!(r.target, Target::Domain(ref d) if d == "example.com"));
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0, 0]);
        let mut rest = [0u8; 5];
        server.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"GET /");
    }

    #[tokio::test]
    async fn rejects_wrong_uuid() {
        let id = parse_uuid("10889da6-14ea-4cc8-97fa-6c0bc410f121").unwrap();
        let other = parse_uuid("00000000-0000-0000-0000-000000000001").unwrap();
        let req = build(&other, CMD_TCP, "example.com", 443);
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(&req).await.unwrap();
        assert!(handshake(&mut server, &id).await.is_err());
    }

    #[tokio::test]
    async fn accepts_udp() {
        let id = parse_uuid("10889da6-14ea-4cc8-97fa-6c0bc410f121").unwrap();
        let req = build(&id, CMD_UDP, "dns.google", 53);
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(&req).await.unwrap();
        let (r, cmd) = handshake(&mut server, &id).await.unwrap();
        assert_eq!(cmd, Command::Udp);
        assert_eq!(r.port, 53);
    }

    #[tokio::test]
    async fn rejects_mux() {
        let id = parse_uuid("10889da6-14ea-4cc8-97fa-6c0bc410f121").unwrap();
        let req = build(&id, CMD_MUX, "v1.mux.cool", 0);
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(&req).await.unwrap();
        assert!(handshake(&mut server, &id).await.is_err());
    }
}
