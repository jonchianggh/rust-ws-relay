//! HTTP front door: route WebSocket upgrades on secret paths into the proxy,
//! and answer everything else with the decoy site.

use crate::config::{Config, Inbound, Protocol};
use crate::relay;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, error, info};

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    info!(addr = %cfg.listen, inbounds = cfg.inbounds.len(), "listening");
    let cfg = Arc::new(cfg);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                error!(error = %e, "accept failed");
                continue;
            }
        };
        let cfg = cfg.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| handle(req, cfg.clone(), peer));
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                debug!(error = %e, "connection closed with error");
            }
        });
    }
}

async fn handle(
    mut req: Request<hyper::body::Incoming>,
    cfg: Arc<Config>,
    peer: std::net::SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path().to_string();

    // A configured path + a valid WebSocket upgrade is the only way into the
    // proxy. Everything else (including a plain GET to a secret path) is decoy.
    if hyper_tungstenite::is_upgrade_request(&req) {
        if let Some(inbound) = cfg.inbounds.iter().find(|i| i.path == path) {
            match hyper_tungstenite::upgrade(&mut req, None) {
                Ok((response, websocket)) => {
                    let inbound = inbound.clone();
                    let cfg = cfg.clone();
                    tokio::spawn(async move {
                        match websocket.await {
                            Ok(ws) => {
                                if let Err(e) = dispatch(ws, &inbound, &cfg, peer).await {
                                    debug!(peer = %peer, path = %inbound.path, error = %e, "relay ended");
                                }
                            }
                            Err(e) => debug!(error = %e, "websocket handshake failed"),
                        }
                    });
                    // hyper-tungstenite's response body is an empty string body;
                    // map it to our Full<Bytes> body type.
                    let (parts, _) = response.into_parts();
                    return Ok(Response::from_parts(parts, Full::new(Bytes::new())));
                }
                Err(e) => {
                    debug!(error = %e, "upgrade failed");
                }
            }
        }
    }

    Ok(crate::decoy::respond(&cfg.decoy, &req).await)
}

type Ws = hyper_tungstenite::WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>;

async fn dispatch(
    ws: Ws,
    inbound: &Inbound,
    cfg: &Config,
    peer: std::net::SocketAddr,
) -> anyhow::Result<()> {
    match &inbound.protocol {
        Protocol::Vless(v) => relay::vless(ws, v, cfg, peer).await,
        Protocol::Socks5(s) => relay::socks5(ws, s, cfg, peer).await,
        Protocol::Shadowsocks(s) => relay::shadowsocks(ws, s, cfg, peer).await,
    }
}
