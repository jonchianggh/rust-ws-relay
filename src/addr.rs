//! Target address handling, shared by every protocol, plus the safety check
//! that stops a client from reaching the host's own private network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::net::TcpStream;

/// A destination requested by a client: either a resolved IP or a hostname the
/// server resolves at connect time.
#[derive(Debug, Clone)]
pub enum Target {
    Ip(IpAddr),
    Domain(String),
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Ip(ip) => write!(f, "{ip}"),
            Target::Domain(d) => write!(f, "{d}"),
        }
    }
}

/// Returns true if an IP is one we must never proxy to: loopback, private,
/// link-local, multicast, broadcast, unspecified, or similar.
pub fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => is_blocked_v6(v6),
    }
}

fn is_blocked_v4(ip: &Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        // 100.64.0.0/10 CGNAT
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64)
        // 169.254/16 is link-local (covered above); 192.0.0.0/24 IETF
        || (ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0)
}

fn is_blocked_v6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    let seg = ip.segments();
    // Unique local fc00::/7
    if (seg[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // Link-local fe80::/10
    if (seg[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // IPv4-mapped ::ffff:0:0/96 — check the embedded v4
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_blocked_v4(&v4);
    }
    false
}

/// Resolve the target to the first socket address the block policy allows.
/// Used for UDP, where there is no connect attempt to fall back across.
pub async fn resolve(
    target: &Target,
    port: u16,
    block_private: bool,
) -> std::io::Result<std::net::SocketAddr> {
    use std::io::{Error, ErrorKind};
    let candidates: Vec<std::net::SocketAddr> = match target {
        Target::Ip(ip) => vec![(*ip, port).into()],
        Target::Domain(host) => tokio::net::lookup_host((host.as_str(), port))
            .await?
            .collect(),
    };
    let mut last_err = Error::new(ErrorKind::AddrNotAvailable, "no address resolved");
    for sa in candidates {
        if block_private && is_blocked_ip(&sa.ip()) {
            last_err = Error::new(
                ErrorKind::PermissionDenied,
                format!("destination {target} resolved to blocked {}", sa.ip()),
            );
            continue;
        }
        return Ok(sa);
    }
    Err(last_err)
}

/// Open a TCP connection to the target, enforcing the private-address block
/// after any DNS resolution.
pub async fn connect(
    target: &Target,
    port: u16,
    block_private: bool,
) -> std::io::Result<TcpStream> {
    use std::io::{Error, ErrorKind};
    match target {
        Target::Ip(ip) => {
            if block_private && is_blocked_ip(ip) {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    format!("destination {ip} is blocked"),
                ));
            }
            TcpStream::connect((*ip, port)).await
        }
        Target::Domain(host) => {
            // Resolve, filter, then dial the first allowed address.
            let addrs = tokio::net::lookup_host((host.as_str(), port)).await?;
            let mut last_err = Error::new(ErrorKind::AddrNotAvailable, "no address resolved");
            for sa in addrs {
                if block_private && is_blocked_ip(&sa.ip()) {
                    last_err = Error::new(
                        ErrorKind::PermissionDenied,
                        format!("destination {host} resolved to blocked {}", sa.ip()),
                    );
                    continue;
                }
                match TcpStream::connect(sa).await {
                    Ok(s) => return Ok(s),
                    Err(e) => last_err = e,
                }
            }
            Err(last_err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_private_and_loopback() {
        for s in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "::1",
            "fd00::1",
            "100.64.0.1",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(is_blocked_ip(&ip), "{s} should be blocked");
        }
    }

    #[test]
    fn allows_public() {
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_blocked_ip(&ip), "{s} should be allowed");
        }
    }

    #[tokio::test]
    async fn udp_resolve_honours_block() {
        let lo = Target::Ip("127.0.0.1".parse().unwrap());
        assert!(resolve(&lo, 123, true).await.is_err());
        assert!(resolve(&lo, 123, false).await.is_ok());
        let public = Target::Ip("1.1.1.1".parse().unwrap());
        assert_eq!(resolve(&public, 53, true).await.unwrap().port(), 53);
    }
}
