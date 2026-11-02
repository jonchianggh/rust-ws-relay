//! sing-box style UDP-over-TCP (UoT), used to carry UDP through Shadowsocks
//! and SOCKS5, whose own UDP modes cannot cross a WebSocket.
//!
//! The client opens an ordinary stream "connection" to a magic hostname:
//!
//! * `sp.v2.udp-over-tcp.arpa` (version 2): the stream opens with
//!   `is_connect(1) | destination (SOCKS form: atyp 1/3/4, addr, port)`.
//!   With `is_connect = 1` every packet, both ways, is `len(2 BE) | payload`
//!   for that one destination. With `is_connect = 0` packets look like v1.
//! * `sp.udp-over-tcp.arpa` (version 1): no header; every packet, both ways,
//!   is `addr | port(2 BE) | len(2 BE) | payload`, where addr is
//!   `0x00 + 4 bytes` (IPv4), `0x01 + 16 bytes` (IPv6) or `0x02 + len + name`.
//!
//! Reference: github.com/SagerNet/sing, common/uot.
//!
//! The same engine serves v2ray "packetaddr" on VLESS (used by mihomo and
//! sing-box with `packet-encoding: packetaddr`): a VLESS UDP request to
//! `sp.packet-addr.v2fly.arpa`, after which every VLESS frame, both ways, is
//! `len(2 BE) | family(1 = IPv4, 2 = IPv6) | addr | port(2 BE) | payload`.

use crate::addr::{self, Target};
use crate::config::Config;
use crate::relay::Activity;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

pub const MAGIC_V2: &str = "sp.v2.udp-over-tcp.arpa";
pub const MAGIC_V1: &str = "sp.udp-over-tcp.arpa";
pub const MAGIC_PACKETADDR: &str = "sp.packet-addr.v2fly.arpa";

/// Wire format of a multi-destination UDP session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// sing-box UoT, version 1 or 2.
    Uot(u8),
    /// v2ray packetaddr inside VLESS UDP framing.
    PacketAddr,
}

/// Whether a VLESS UDP target is the packetaddr magic name.
pub fn is_packetaddr(target: &Target) -> bool {
    matches!(target, Target::Domain(d) if d.eq_ignore_ascii_case(MAGIC_PACKETADDR))
}

/// Split a packetaddr frame into its destination and payload.
fn parse_packetaddr(frame: &[u8]) -> std::io::Result<(Target, u16, &[u8])> {
    let bad = || Error::new(ErrorKind::InvalidData, "bad packetaddr frame");
    let (ip, rest): (IpAddr, &[u8]) = match frame.first() {
        Some(0x01) if frame.len() >= 7 => {
            let b: [u8; 4] = frame[1..5].try_into().unwrap();
            (Ipv4Addr::from(b).into(), &frame[5..])
        }
        Some(0x02) if frame.len() >= 19 => {
            let b: [u8; 16] = frame[1..17].try_into().unwrap();
            (Ipv6Addr::from(b).into(), &frame[17..])
        }
        _ => return Err(bad()),
    };
    let port = u16::from_be_bytes([rest[0], rest[1]]);
    Ok((Target::Ip(ip), port, &rest[2..]))
}

fn write_packetaddr(out: &mut Vec<u8>, from: SocketAddr) {
    match from.ip() {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x02);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&from.port().to_be_bytes());
}

/// Which UoT version a requested target selects, if it is a UoT magic name.
pub fn version_for(target: &Target) -> Option<u8> {
    match target {
        Target::Domain(d) if d.eq_ignore_ascii_case(MAGIC_V2) => Some(2),
        Target::Domain(d) if d.eq_ignore_ascii_case(MAGIC_V1) => Some(1),
        _ => None,
    }
}

/// Where a datagram the client addressed to `target:port` is actually sent.
/// DNS always goes to the configured resolver; anything else is resolved and
/// checked against the private-address block.
pub async fn udp_destination(
    target: &Target,
    port: u16,
    cfg: &Config,
) -> std::io::Result<SocketAddr> {
    let u = &cfg.udp;
    if !u.enabled {
        return Err(Error::new(ErrorKind::PermissionDenied, "udp is disabled"));
    }
    if port == 53 {
        return Ok(u.dns_upstream);
    }
    if u.dns_only {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("udp to port {port} refused (dns_only)"),
        ));
    }
    addr::resolve(target, port, cfg.block_private_addresses).await
}

async fn read_uot_addr<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<(Target, u16)> {
    let target = match r.read_u8().await? {
        0x00 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b).await?;
            Target::Ip(Ipv4Addr::from(b).into())
        }
        0x01 => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b).await?;
            Target::Ip(Ipv6Addr::from(b).into())
        }
        0x02 => {
            let len = r.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            r.read_exact(&mut b).await?;
            Target::Domain(
                String::from_utf8(b).map_err(|_| Error::new(ErrorKind::InvalidData, "bad fqdn"))?,
            )
        }
        other => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("bad UoT address family {other}"),
            ))
        }
    };
    let port = r.read_u16().await?;
    Ok((target, port))
}

fn write_uot_addr(out: &mut Vec<u8>, target: &Target, port: u16) {
    match target {
        Target::Ip(IpAddr::V4(v4)) => {
            out.push(0x00);
            out.extend_from_slice(&v4.octets());
        }
        Target::Ip(IpAddr::V6(v6)) => {
            out.push(0x01);
            out.extend_from_slice(&v6.octets());
        }
        Target::Domain(d) => {
            out.push(0x02);
            out.push(d.len().min(255) as u8);
            out.extend_from_slice(&d.as_bytes()[..d.len().min(255)]);
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
}

/// Serve one UoT session on an already-authenticated stream.
pub async fn serve<S>(stream: S, mode: Mode, cfg: &Config, peer: SocketAddr) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut sr, mut sw) = tokio::io::split(stream);
    let packetaddr = mode == Mode::PacketAddr;

    // UoT version 2 opens with a request header.
    let connect_to = if mode == Mode::Uot(2) {
        let is_connect = sr.read_u8().await? != 0;
        let dest = crate::proto::read_socks_address(&mut sr).await?;
        is_connect.then_some((dest.target, dest.port))
    } else {
        None
    };

    tracing::info!(peer = %peer, proto = if packetaddr { "vless-packetaddr" } else { "uot" }, ?mode, connect = ?connect_to.as_ref().map(|(t, p)| format!("{t}:{p}")), "udp session");

    let sock4 = UdpSocket::bind("0.0.0.0:0").await?;
    let sock6 = UdpSocket::bind("[::]:0").await.ok();
    // Real sender address -> the address the client used for it, so a DNS
    // reply from the redirect resolver is reported as coming from the server
    // the client asked.
    let names: Mutex<HashMap<SocketAddr, (Target, u16)>> = Mutex::new(HashMap::new());
    let act = Activity::new();

    let fixed_dest = match &connect_to {
        Some((t, p)) => Some(udp_destination(t, *p, cfg).await?),
        None => None,
    };

    let up = async {
        let mut buf = vec![0u8; 65535];
        let mut cache: HashMap<(String, u16), SocketAddr> = HashMap::new();
        loop {
            if packetaddr {
                let len = match sr.read_u16().await {
                    Ok(n) => n as usize,
                    Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e),
                };
                sr.read_exact(&mut buf[..len]).await?;
                act.touch();
                let Ok((t, p, payload)) = parse_packetaddr(&buf[..len]) else {
                    continue;
                };
                let dest = match udp_destination(&t, p, cfg).await {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::debug!(error = %e, "packetaddr packet dropped");
                        continue;
                    }
                };
                if dest.port() != p || Target::Ip(dest.ip()).to_string() != t.to_string() {
                    let mut n = names.lock().await;
                    if n.len() > 1024 {
                        n.clear();
                    }
                    n.insert(dest, (t, p));
                }
                let sock = match (&dest, &sock6) {
                    (SocketAddr::V6(_), Some(s6)) => s6,
                    (SocketAddr::V6(_), None) => continue,
                    _ => &sock4,
                };
                let _ = sock.send_to(payload, dest).await;
                continue;
            }
            let (dest, orig) = if let Some(d) = fixed_dest {
                (Some(d), None)
            } else {
                let (t, p) = match read_uot_addr(&mut sr).await {
                    Ok(v) => v,
                    Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e),
                };
                let key = (t.to_string(), p);
                let d = match cache.get(&key) {
                    Some(d) => Some(*d),
                    None => match udp_destination(&t, p, cfg).await {
                        Ok(d) => {
                            if cache.len() > 256 {
                                cache.clear();
                            }
                            cache.insert(key, d);
                            Some(d)
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "uot packet dropped");
                            None
                        }
                    },
                };
                (d, Some((t, p)))
            };
            let len = match sr.read_u16().await {
                Ok(n) => n as usize,
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            };
            sr.read_exact(&mut buf[..len]).await?;
            act.touch();
            let Some(dest) = dest else { continue };
            if let Some(o) = orig {
                let mut n = names.lock().await;
                if n.len() > 1024 {
                    n.clear();
                }
                n.insert(dest, o);
            }
            let sock = match (&dest, &sock6) {
                (SocketAddr::V6(_), Some(s6)) => s6,
                (SocketAddr::V6(_), None) => continue,
                _ => &sock4,
            };
            let _ = sock.send_to(&buf[..len], dest).await;
        }
        Ok::<(), std::io::Error>(())
    };

    let down = async {
        let mut b4 = vec![0u8; 65535];
        let mut b6 = vec![0u8; 65535];
        loop {
            let recv6 = async {
                match &sock6 {
                    Some(s) => s.recv_from(&mut b6).await,
                    None => std::future::pending().await,
                }
            };
            let (n, from, data) = tokio::select! {
                r = sock4.recv_from(&mut b4) => match r {
                    Ok((n, from)) => (n, from, &b4),
                    Err(_) => continue,
                },
                r = recv6 => match r {
                    Ok((n, from)) => (n, from, &b6),
                    Err(_) => continue,
                },
            };
            act.touch();
            let mut out = Vec::with_capacity(n + 24);
            if packetaddr {
                // The reply's source as the client addressed it (a DNS
                // answer from the redirect resolver reports the server the
                // client asked). packetaddr carries IPs only.
                let shown = match names.lock().await.get(&from).cloned() {
                    Some((Target::Ip(ip), p)) => SocketAddr::new(ip, p),
                    _ => from,
                };
                let mut frame = Vec::with_capacity(n + 19);
                write_packetaddr(&mut frame, shown);
                frame.extend_from_slice(&data[..n]);
                out.extend_from_slice(&(frame.len() as u16).to_be_bytes());
                out.extend_from_slice(&frame);
                sw.write_all(&out).await?;
                sw.flush().await?;
                continue;
            }
            if fixed_dest.is_none() {
                let (t, p) = names
                    .lock()
                    .await
                    .get(&from)
                    .cloned()
                    .unwrap_or((Target::Ip(from.ip()), from.port()));
                write_uot_addr(&mut out, &t, p);
            }
            out.extend_from_slice(&(n as u16).to_be_bytes());
            out.extend_from_slice(&data[..n]);
            sw.write_all(&out).await?;
            sw.flush().await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    };

    let r = tokio::select! {
        r = up => r.map_err(Into::into),
        r = down => r.map_err(Into::into),
        _ = act.watchdog(cfg.udp.idle_timeout_secs) => Ok(()),
    };
    sw.shutdown().await.ok();
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_names() {
        assert_eq!(version_for(&Target::Domain(MAGIC_V2.into())), Some(2));
        assert_eq!(version_for(&Target::Domain(MAGIC_V1.into())), Some(1));
        assert_eq!(version_for(&Target::Domain("example.com".into())), None);
    }

    #[test]
    fn packetaddr_roundtrip() {
        for from in ["1.2.3.4:53", "[2606:4700::1111]:443"] {
            let from: SocketAddr = from.parse().unwrap();
            let mut v = Vec::new();
            write_packetaddr(&mut v, from);
            v.extend_from_slice(b"hi");
            let (t, p, payload) = parse_packetaddr(&v).unwrap();
            assert_eq!(
                SocketAddr::new(t.to_string().trim_matches(['[', ']']).parse().unwrap(), p),
                from
            );
            assert_eq!(payload, b"hi");
        }
        assert!(is_packetaddr(&Target::Domain(MAGIC_PACKETADDR.into())));
        assert!(parse_packetaddr(&[0x03, 0, 0]).is_err());
    }

    #[tokio::test]
    async fn addr_roundtrip() {
        for (t, p) in [
            (Target::Ip("1.2.3.4".parse().unwrap()), 53u16),
            (Target::Ip("2606:4700::1111".parse().unwrap()), 443),
            (Target::Domain("dns.google".into()), 853),
        ] {
            let mut v = Vec::new();
            write_uot_addr(&mut v, &t, p);
            let (t2, p2) = read_uot_addr(&mut v.as_slice()).await.unwrap();
            assert_eq!(t.to_string(), t2.to_string());
            assert_eq!(p, p2);
        }
    }
}
