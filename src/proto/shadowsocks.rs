//! Shadowsocks TCP.
//!
//! Supported methods:
//!   * Legacy AEAD: aes-256-gcm, aes-128-gcm, chacha20-ietf-poly1305
//!   * SS-2022:     2022-blake3-aes-256-gcm, 2022-blake3-aes-128-gcm
//!
//! The server decrypts the client->server direction (an [`SsReader`]) and
//! encrypts the server->client direction (an [`SsWriter`]). The caller then
//! runs a simple two-way copy between these and the upstream TCP socket, so
//! there is no need to implement AsyncRead/AsyncWrite for the cipher itself.

pub mod crypto;

use super::Request;
use crate::addr::Target;
use crypto::{Method, SsReader, SsWriter};
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Result of a successful Shadowsocks handshake.
pub struct Accepted {
    pub reader: SsReader,
    pub writer: SsWriter,
    pub request: Request,
    /// Any plaintext that arrived in the same chunk(s) as the address header.
    pub leftover: Vec<u8>,
}

/// Read the client salt, derive the session, validate the SS-2022 request
/// header where applicable, and parse the target address.
pub async fn accept<S>(inner: &mut S, method: Method, key: &[u8]) -> std::io::Result<Accepted>
where
    S: AsyncRead + Unpin,
{
    let mut salt = vec![0u8; method.salt_len()];
    inner.read_exact(&mut salt).await?;

    let mut reader = SsReader::new(method, key, &salt)?;

    if method.is_2022() {
        // SS-2022 request: fixed header block (type u8, timestamp u64,
        // var_len u16), then one variable header block of var_len bytes:
        // atyp|addr|port|padding_len u16|padding|initial payload.
        let fixed = reader.open_block(inner, 1 + 8 + 2).await?;
        if fixed[0] != 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "bad SS-2022 request type",
            ));
        }
        let ts = u64::from_be_bytes(fixed[1..9].try_into().unwrap());
        check_timestamp(ts)?;
        replay::check_and_insert(&salt)?;
        let var_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
        if var_len == 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "empty SS-2022 variable header",
            ));
        }
        let var = reader.open_block(inner, var_len).await?;
        let mut cur = std::io::Cursor::new(&var[..]);
        let request = read_address(&mut cur).await?;
        let mut pl = [0u8; 2];
        cur.read_exact(&mut pl).await?;
        let padlen = u16::from_be_bytes(pl) as usize;
        let pos = cur.position() as usize + padlen;
        if pos > var.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "SS-2022 padding overruns header",
            ));
        }
        let leftover = var[pos..].to_vec();
        let writer = SsWriter::new(method, key, &salt)?;
        return Ok(Accepted {
            reader,
            writer,
            request,
            leftover,
        });
    }

    // Legacy AEAD: the address is the start of the first payload chunk(s).
    let mut plain: Vec<u8> = Vec::new();
    let request = parse_address(&mut plain, &mut reader, inner).await?;
    // Only record the salt once the first chunk has authenticated, so an
    // unauthenticated sender cannot fill the filter with junk.
    replay::check_and_insert_legacy(&salt)?;

    let writer = SsWriter::new(method, key, &salt)?;

    Ok(Accepted {
        reader,
        writer,
        request,
        leftover: plain,
    })
}

/// Ensure `plain` holds at least `need` bytes, pulling more chunks as required.
async fn fill<S>(
    plain: &mut Vec<u8>,
    reader: &mut SsReader,
    inner: &mut S,
    need: usize,
) -> std::io::Result<()>
where
    S: AsyncRead + Unpin,
{
    while plain.len() < need {
        match reader.read_chunk(inner).await? {
            Some(mut c) => plain.append(&mut c),
            None => {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "SS stream ended mid-header",
                ))
            }
        }
    }
    Ok(())
}

async fn parse_address<S>(
    plain: &mut Vec<u8>,
    reader: &mut SsReader,
    inner: &mut S,
) -> std::io::Result<Request>
where
    S: AsyncRead + Unpin,
{
    fill(plain, reader, inner, 1).await?;
    let atyp = plain[0];
    plain.drain(..1);
    let target = match atyp {
        0x01 => {
            fill(plain, reader, inner, 4).await?;
            let b: [u8; 4] = plain[..4].try_into().unwrap();
            plain.drain(..4);
            Target::Ip(Ipv4Addr::from(b).into())
        }
        0x04 => {
            fill(plain, reader, inner, 16).await?;
            let b: [u8; 16] = plain[..16].try_into().unwrap();
            plain.drain(..16);
            Target::Ip(Ipv6Addr::from(b).into())
        }
        0x03 => {
            fill(plain, reader, inner, 1).await?;
            let len = plain[0] as usize;
            plain.drain(..1);
            if len == 0 {
                return Err(Error::new(ErrorKind::InvalidData, "empty domain"));
            }
            fill(plain, reader, inner, len).await?;
            let host = String::from_utf8(plain[..len].to_vec())
                .map_err(|_| Error::new(ErrorKind::InvalidData, "non-utf8 domain"))?;
            plain.drain(..len);
            Target::Domain(host)
        }
        other => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("bad SS address type {other}"),
            ))
        }
    };
    fill(plain, reader, inner, 2).await?;
    let port = u16::from_be_bytes([plain[0], plain[1]]);
    plain.drain(..2);
    Ok(Request { target, port })
}

/// Parse a SOCKS-style address from any plaintext reader.
async fn read_address<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Request> {
    super::read_socks_address(r).await
}

/// In-memory replay filters for client salts.
///
/// * SS-2022: reject a salt seen in the last 60 seconds (the spec's window;
///   the timestamp check rejects anything older).
/// * Legacy AEAD: there is no timestamp, so remember the most recent
///   `LEGACY_CAPACITY` salts regardless of age, as shadowsocks-rust and
///   shadowsocks-libev do with their salt filters.
mod replay {
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::io::{Error, ErrorKind};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    static SEEN: Mutex<Option<HashMap<Vec<u8>, Instant>>> = Mutex::new(None);
    const WINDOW: Duration = Duration::from_secs(60);

    pub fn check_and_insert(salt: &[u8]) -> std::io::Result<()> {
        let mut g = SEEN.lock().unwrap();
        let map = g.get_or_insert_with(HashMap::new);
        let now = Instant::now();
        if map.len() > 4096 {
            map.retain(|_, t| now.duration_since(*t) < WINDOW);
        }
        if let Some(t) = map.get(salt) {
            if now.duration_since(*t) < WINDOW {
                return Err(Error::new(ErrorKind::InvalidData, "SS-2022 salt replay"));
            }
        }
        map.insert(salt.to_vec(), now);
        Ok(())
    }

    /// About 100k salts of up to 32 bytes: a few MB at most.
    pub const LEGACY_CAPACITY: usize = 100_000;

    struct Legacy {
        set: HashSet<Vec<u8>>,
        order: VecDeque<Vec<u8>>,
    }

    static LEGACY: Mutex<Option<Legacy>> = Mutex::new(None);

    pub fn check_and_insert_legacy(salt: &[u8]) -> std::io::Result<()> {
        let mut g = LEGACY.lock().unwrap();
        let f = g.get_or_insert_with(|| Legacy {
            set: HashSet::new(),
            order: VecDeque::new(),
        });
        if f.set.contains(salt) {
            return Err(Error::new(ErrorKind::InvalidData, "SS salt replay"));
        }
        if f.order.len() >= LEGACY_CAPACITY {
            if let Some(old) = f.order.pop_front() {
                f.set.remove(&old);
            }
        }
        f.set.insert(salt.to_vec());
        f.order.push_back(salt.to_vec());
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn legacy_rejects_repeat_salt() {
            let salt = [0x5au8; 32];
            check_and_insert_legacy(&salt).unwrap();
            assert!(check_and_insert_legacy(&salt).is_err());
            check_and_insert_legacy(&[0xa5u8; 32]).unwrap();
        }

        #[test]
        fn ss2022_rejects_repeat_salt() {
            let salt = [0x33u8; 32];
            check_and_insert(&salt).unwrap();
            assert!(check_and_insert(&salt).is_err());
        }
    }
}

/// SS-2022 requires the request timestamp to be within 30 seconds.
fn check_timestamp(ts: u64) -> std::io::Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let diff = now.abs_diff(ts);
    if diff > 30 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("SS-2022 timestamp out of window ({diff}s)"),
        ));
    }
    Ok(())
}

/// Resolve a configured method name + password into (Method, key bytes).
pub fn resolve(method_name: &str, password: &str) -> std::io::Result<(Method, Vec<u8>)> {
    let method = Method::from_name(method_name).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("unknown SS method {method_name}"),
        )
    })?;
    let key = method.derive_key(password)?;
    Ok((method, key))
}
