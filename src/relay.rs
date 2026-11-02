//! Per-protocol handlers: parse the handshake, dial the target, and pipe bytes.

use crate::addr;
use crate::config::{Config, ShadowsocksConfig, Socks5Config, VlessConfig};
use crate::proto::{shadowsocks as ss, socks5, vless};
use crate::wsbytes::WsByteStream;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::info;

type Ws = hyper_tungstenite::WebSocketStream<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>;

pub async fn vless(
    ws: Ws,
    cfg_v: &VlessConfig,
    cfg: &Config,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let uuid = vless::parse_uuid(&cfg_v.uuid).map_err(|_| anyhow::anyhow!("bad uuid in config"))?;
    let mut stream = WsByteStream::new(ws);

    let (req, cmd) = tokio::time::timeout(
        Duration::from_secs(cfg.handshake_timeout_secs),
        vless::handshake(&mut stream, &uuid),
    )
    .await
    .map_err(|_| anyhow::anyhow!("vless handshake timed out"))??;

    if cmd == vless::Command::Udp && crate::uot::is_packetaddr(&req.target) {
        if !cfg.udp.enabled {
            anyhow::bail!("udp is disabled");
        }
        return crate::uot::serve(stream, crate::uot::Mode::PacketAddr, cfg, peer).await;
    }
    if cmd == vless::Command::Udp {
        return vless_udp(stream, req, cfg, peer).await;
    }

    info!(peer = %peer, proto = "vless", target = %req.target, port = req.port, "connect");
    let upstream = addr::connect(&req.target, req.port, cfg.block_private_addresses).await?;
    pipe(stream, upstream, cfg.idle_timeout_secs).await
}

/// Relay one VLESS UDP session: `len(2 BE) | datagram` frames from the client
/// go to a single destination, and each reply comes back framed the same way.
/// DNS (port 53) is redirected to the configured upstream resolver.
async fn vless_udp<S>(
    stream: S,
    req: crate::proto::Request,
    cfg: &Config,
    peer: SocketAddr,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let dest = crate::uot::udp_destination(&req.target, req.port, cfg).await?;
    info!(peer = %peer, proto = "vless-udp", target = %req.target, port = req.port, via = %dest, "connect");

    let bind: SocketAddr = if dest.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    sock.connect(dest).await?;

    let (mut sr, mut sw) = tokio::io::split(stream);
    let act = Activity::new();

    let up = async {
        let mut buf = vec![0u8; 65535];
        loop {
            let len = match sr.read_u16().await {
                Ok(n) => n as usize,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            };
            sr.read_exact(&mut buf[..len]).await?;
            act.touch();
            // A send error (e.g. ICMP unreachable) drops this datagram only.
            let _ = sock.send(&buf[..len]).await;
        }
        Ok::<(), std::io::Error>(())
    };
    let down = async {
        let mut buf = vec![0u8; 65535 + 2];
        loop {
            let n = match sock.recv(&mut buf[2..]).await {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => continue,
                Err(e) => return Err(e),
            };
            act.touch();
            buf[..2].copy_from_slice(&(n as u16).to_be_bytes());
            sw.write_all(&buf[..n + 2]).await?;
            sw.flush().await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    };
    // The session ends when the client closes, either side errors, or it idles.
    let r = tokio::select! {
        r = up => r.map_err(Into::into),
        r = down => r.map_err(Into::into),
        _ = act.watchdog(cfg.udp.idle_timeout_secs) => Ok(()),
    };
    sw.shutdown().await.ok();
    r
}

pub async fn socks5(
    ws: Ws,
    cfg_s: &Socks5Config,
    cfg: &Config,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let mut stream = WsByteStream::new(ws);
    let auth = match (&cfg_s.username, &cfg_s.password) {
        (Some(u), Some(p)) => Some(socks5::Auth {
            username: u,
            password: p,
        }),
        _ => None,
    };

    let req = tokio::time::timeout(
        Duration::from_secs(cfg.handshake_timeout_secs),
        socks5::handshake(&mut stream, auth),
    )
    .await
    .map_err(|_| anyhow::anyhow!("socks5 handshake timed out"))??;

    if let Some(version) = crate::uot::version_for(&req.target) {
        socks5::reply(&mut stream, socks5::REP_SUCCESS).await?;
        return crate::uot::serve(stream, crate::uot::Mode::Uot(version), cfg, peer).await;
    }

    info!(peer = %peer, proto = "socks5", target = %req.target, port = req.port, "connect");
    match addr::connect(&req.target, req.port, cfg.block_private_addresses).await {
        Ok(upstream) => {
            socks5::reply(&mut stream, socks5::REP_SUCCESS).await?;
            pipe(stream, upstream, cfg.idle_timeout_secs).await
        }
        Err(e) => {
            let _ = socks5::reply(&mut stream, socks5::rep_for_error(&e)).await;
            Err(e.into())
        }
    }
}

pub async fn shadowsocks(
    ws: Ws,
    cfg_s: &ShadowsocksConfig,
    cfg: &Config,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let (method, key) = ss::resolve(&cfg_s.method, &cfg_s.password)?;
    let mut stream = WsByteStream::new(ws);

    let accepted = tokio::time::timeout(
        Duration::from_secs(cfg.handshake_timeout_secs),
        ss::accept(&mut stream, method, &key),
    )
    .await
    .map_err(|_| anyhow::anyhow!("shadowsocks handshake timed out"))??;

    let ss::Accepted {
        reader,
        writer,
        request,
        leftover,
    } = accepted;
    // UDP-over-TCP: the "upstream" is an in-memory pipe to the UoT server.
    if let Some(version) = crate::uot::version_for(&request.target) {
        let (near, far) = tokio::io::duplex(128 * 1024);
        let session = crate::uot::serve(far, crate::uot::Mode::Uot(version), cfg, peer);
        let pipe = ss_pipe(
            stream,
            reader,
            writer,
            leftover,
            near,
            cfg.idle_timeout_secs,
        );
        // Whichever side finishes first ends the session.
        return tokio::select! { r = session => r, r = pipe => r };
    }

    info!(peer = %peer, proto = "shadowsocks", target = %request.target, port = request.port, "connect");

    let upstream =
        addr::connect(&request.target, request.port, cfg.block_private_addresses).await?;
    ss_pipe(
        stream,
        reader,
        writer,
        leftover,
        upstream,
        cfg.idle_timeout_secs,
    )
    .await
}

/// Pipe a Shadowsocks session (decrypting client chunks, encrypting replies)
/// to any byte-stream upstream: a TCP socket or the UoT pipe.
async fn ss_pipe<U>(
    stream: WsByteStream<Ws>,
    mut reader: ss::crypto::SsReader,
    mut writer: ss::crypto::SsWriter,
    leftover: Vec<u8>,
    upstream: U,
    idle_secs: u64,
) -> anyhow::Result<()>
where
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut up_r, mut up_w) = tokio::io::split(upstream);
    if !leftover.is_empty() {
        up_w.write_all(&leftover).await?;
    }

    let (ws_r, ws_w) = tokio::io::split(stream);
    let act = Activity::new();
    let (a1, a2) = (act.clone(), act.clone());

    // client -> upstream: decrypt chunks and forward.
    let c2u = async move {
        let mut ws_r = ws_r;
        while let Some(chunk) = reader.read_chunk(&mut ws_r).await? {
            a1.touch();
            up_w.write_all(&chunk).await?;
        }
        up_w.shutdown().await.ok();
        Ok::<(), anyhow::Error>(())
    };

    // upstream -> client: encrypt and forward.
    let u2c = async move {
        let mut ws_w = ws_w;
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = up_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            a2.touch();
            writer.write(&mut ws_w, &buf[..n]).await?;
        }
        ws_w.shutdown().await.ok();
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        r = async { tokio::try_join!(c2u, u2c) } => { r?; Ok(()) }
        _ = act.watchdog(idle_secs) => Err(anyhow::anyhow!("idle timeout")),
    }
}

/// Tracks the last time any byte moved in either direction, so a long
/// one-way download is not killed just because the client is silent.
#[derive(Clone)]
pub struct Activity(
    std::sync::Arc<std::sync::atomic::AtomicU64>,
    std::time::Instant,
);

impl Activity {
    pub fn new() -> Self {
        Self(Default::default(), std::time::Instant::now())
    }
    pub fn touch(&self) {
        self.0.store(
            self.1.elapsed().as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
    fn idle_for(&self) -> u64 {
        self.1
            .elapsed()
            .as_secs()
            .saturating_sub(self.0.load(std::sync::atomic::Ordering::Relaxed))
    }
    /// Resolves when the connection has been idle longer than `idle_secs`.
    pub async fn watchdog(&self, idle_secs: u64) {
        if idle_secs == 0 {
            std::future::pending::<()>().await;
        }
        loop {
            tokio::time::sleep(Duration::from_secs(5.min(idle_secs).max(1))).await;
            if self.idle_for() >= idle_secs {
                return;
            }
        }
    }
}

/// Pipe a websocket byte stream and an upstream TCP socket both ways, closing
/// when both sides end or the shared idle timeout trips.
async fn pipe<S>(stream: S, upstream: tokio::net::TcpStream, idle_secs: u64) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut sr, mut sw) = tokio::io::split(stream);
    let (mut ur, mut uw) = upstream.into_split();
    let act = Activity::new();

    let up = async {
        let r = copy_counting(&mut sr, &mut uw, &act).await;
        uw.shutdown().await.ok();
        r
    };
    let down = async {
        let r = copy_counting(&mut ur, &mut sw, &act).await;
        sw.shutdown().await.ok();
        r
    };
    tokio::select! {
        r = async { tokio::try_join!(up, down) } => { r?; Ok(()) }
        _ = act.watchdog(idle_secs) => Err(anyhow::anyhow!("idle timeout")),
    }
}

async fn copy_counting<R, W>(mut r: R, mut w: W, act: &Activity) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        act.touch();
        w.write_all(&buf[..n]).await?;
        // The WebSocket sink buffers frames until flushed.
        w.flush().await?;
        total += n as u64;
    }
    Ok(total)
}
