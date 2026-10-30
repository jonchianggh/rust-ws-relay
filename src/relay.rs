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

    let req = tokio::time::timeout(
        Duration::from_secs(cfg.handshake_timeout_secs),
        vless::handshake(&mut stream, &uuid),
    )
    .await
    .map_err(|_| anyhow::anyhow!("vless handshake timed out"))??;

    info!(peer = %peer, proto = "vless", target = %req.target, port = req.port, "connect");
    let upstream = addr::connect(&req.target, req.port, cfg.block_private_addresses).await?;
    pipe(stream, upstream, cfg.idle_timeout_secs).await
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
        mut reader,
        mut writer,
        request,
        leftover,
    } = accepted;
    info!(peer = %peer, proto = "shadowsocks", target = %request.target, port = request.port, "connect");

    let upstream =
        addr::connect(&request.target, request.port, cfg.block_private_addresses).await?;
    let (mut up_r, mut up_w) = upstream.into_split();
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
        _ = act.watchdog(cfg.idle_timeout_secs) => Err(anyhow::anyhow!("idle timeout")),
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
