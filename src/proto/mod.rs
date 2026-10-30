//! Protocol parsers. Each one reads its handshake off a byte stream and yields
//! the requested [`Target`] and port, after which the caller pipes bytes to the
//! upstream TCP socket.

pub mod shadowsocks;
pub mod socks5;
pub mod vless;

use crate::addr::Target;
use tokio::io::{AsyncRead, AsyncReadExt};

/// A parsed destination.
#[derive(Debug, Clone)]
pub struct Request {
    pub target: Target,
    pub port: u16,
}

/// Read a SOCKS-style address (used by Shadowsocks and SOCKS5):
/// `atyp(1) | addr | port(2 BE)` where atyp is 1=IPv4, 3=domain, 4=IPv6.
pub async fn read_socks_address<R>(r: &mut R) -> std::io::Result<Request>
where
    R: AsyncRead + Unpin,
{
    use std::io::{Error, ErrorKind};
    use std::net::{Ipv4Addr, Ipv6Addr};

    let atyp = r.read_u8().await?;
    let target = match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b).await?;
            Target::Ip(Ipv4Addr::from(b).into())
        }
        0x04 => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b).await?;
            Target::Ip(Ipv6Addr::from(b).into())
        }
        0x03 => {
            let len = r.read_u8().await? as usize;
            if len == 0 {
                return Err(Error::new(ErrorKind::InvalidData, "empty domain"));
            }
            let mut b = vec![0u8; len];
            r.read_exact(&mut b).await?;
            let host = String::from_utf8(b)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "non-utf8 domain"))?;
            Target::Domain(host)
        }
        other => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unsupported address type {other}"),
            ))
        }
    };
    let port = r.read_u16().await?;
    Ok(Request { target, port })
}
