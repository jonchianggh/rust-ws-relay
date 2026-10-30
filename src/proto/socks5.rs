//! SOCKS5 (RFC 1928) CONNECT only, with optional username/password auth
//! (RFC 1929), carried inside the WebSocket.

use super::{read_socks_address, Request};
use std::io::{Error, ErrorKind};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const VER: u8 = 0x05;
const METHOD_NONE: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_REJECT: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;

pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONN_REFUSED: u8 = 0x05;
pub const REP_CMD_UNSUPPORTED: u8 = 0x07;

/// Credentials required from the client, if any.
pub struct Auth<'a> {
    pub username: &'a str,
    pub password: &'a str,
}

/// Run method negotiation, auth and read the CONNECT request. The caller must
/// then dial the target and call [`reply`] with the outcome.
pub async fn handshake<S>(s: &mut S, auth: Option<Auth<'_>>) -> std::io::Result<Request>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Greeting
    let ver = s.read_u8().await?;
    if ver != VER {
        return Err(Error::new(ErrorKind::InvalidData, "not SOCKS5"));
    }
    let n = s.read_u8().await? as usize;
    let mut methods = vec![0u8; n];
    s.read_exact(&mut methods).await?;

    let want = if auth.is_some() {
        METHOD_USERPASS
    } else {
        METHOD_NONE
    };
    if !methods.contains(&want) {
        s.write_all(&[VER, METHOD_REJECT]).await?;
        s.flush().await?;
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "no acceptable SOCKS5 auth method",
        ));
    }
    s.write_all(&[VER, want]).await?;
    s.flush().await?;

    if let Some(a) = auth {
        // RFC 1929 sub-negotiation
        let sub = s.read_u8().await?;
        if sub != 0x01 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "bad auth sub-negotiation version",
            ));
        }
        let ulen = s.read_u8().await? as usize;
        let mut user = vec![0u8; ulen];
        s.read_exact(&mut user).await?;
        let plen = s.read_u8().await? as usize;
        let mut pass = vec![0u8; plen];
        s.read_exact(&mut pass).await?;
        let ok = ct_eq(&user, a.username.as_bytes()) & ct_eq(&pass, a.password.as_bytes());
        s.write_all(&[0x01, if ok { 0x00 } else { 0x01 }]).await?;
        s.flush().await?;
        if !ok {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "SOCKS5 auth failed",
            ));
        }
    }

    // Request
    let ver = s.read_u8().await?;
    let cmd = s.read_u8().await?;
    let _rsv = s.read_u8().await?;
    if ver != VER {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "bad SOCKS5 request version",
        ));
    }
    if cmd != CMD_CONNECT {
        // Still need to consume the address before replying cleanly.
        let _ = read_socks_address(s).await;
        reply(s, REP_CMD_UNSUPPORTED).await?;
        return Err(Error::new(
            ErrorKind::Unsupported,
            "only SOCKS5 CONNECT is supported",
        ));
    }
    read_socks_address(s).await
}

/// Send the CONNECT reply. Bound address is reported as 0.0.0.0:0.
pub async fn reply<S>(s: &mut S, rep: u8) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    s.write_all(&[VER, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    s.flush().await
}

/// Map a connect error to a SOCKS5 reply code.
pub fn rep_for_error(e: &std::io::Error) -> u8 {
    match e.kind() {
        ErrorKind::PermissionDenied => REP_NOT_ALLOWED,
        ErrorKind::ConnectionRefused => REP_CONN_REFUSED,
        ErrorKind::TimedOut | ErrorKind::AddrNotAvailable | ErrorKind::NotFound => {
            REP_HOST_UNREACHABLE
        }
        _ => REP_GENERAL_FAILURE,
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Target;

    #[tokio::test]
    async fn userpass_connect() {
        let (mut c, mut s) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            let r = handshake(
                &mut s,
                Some(Auth {
                    username: "u",
                    password: "p",
                }),
            )
            .await
            .unwrap();
            reply(&mut s, REP_SUCCESS).await.unwrap();
            r
        });
        c.write_all(&[5, 1, 2]).await.unwrap();
        let mut b = [0u8; 2];
        c.read_exact(&mut b).await.unwrap();
        assert_eq!(b, [5, 2]);
        c.write_all(&[1, 1, b'u', 1, b'p']).await.unwrap();
        c.read_exact(&mut b).await.unwrap();
        assert_eq!(b, [1, 0]);
        let mut req = vec![5, 1, 0, 3, 11];
        req.extend_from_slice(b"example.com");
        req.extend_from_slice(&80u16.to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], REP_SUCCESS);
        let r = server.await.unwrap();
        assert_eq!(r.port, 80);
        assert!(matches!(r.target, Target::Domain(ref d) if d == "example.com"));
    }

    #[tokio::test]
    async fn bad_password_rejected() {
        let (mut c, mut s) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            handshake(
                &mut s,
                Some(Auth {
                    username: "u",
                    password: "p",
                }),
            )
            .await
        });
        c.write_all(&[5, 1, 2]).await.unwrap();
        let mut b = [0u8; 2];
        c.read_exact(&mut b).await.unwrap();
        c.write_all(&[1, 1, b'u', 1, b'x']).await.unwrap();
        c.read_exact(&mut b).await.unwrap();
        assert_eq!(b, [1, 1]);
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn noauth_refused_when_auth_required() {
        let (mut c, mut s) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            handshake(
                &mut s,
                Some(Auth {
                    username: "u",
                    password: "p",
                }),
            )
            .await
        });
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut b = [0u8; 2];
        c.read_exact(&mut b).await.unwrap();
        assert_eq!(b, [5, 0xff]);
        assert!(server.await.unwrap().is_err());
    }
}
