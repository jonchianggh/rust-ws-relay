//! HTTP front door: route WebSocket upgrades on secret paths into the proxy,
//! and answer everything else with the decoy site.

use crate::config::{Config, Inbound, Protocol, SubscriptionConfig};
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

    if let Some(sub) = &cfg.subscription {
        if path == sub.path && req.method() == hyper::Method::GET {
            return Ok(subscription(&req, &cfg, sub, peer));
        }
    }

    Ok(crate::decoy::respond(&cfg.decoy, &req).await)
}

fn subscription(
    req: &Request<hyper::body::Incoming>,
    cfg: &Config,
    sub: &SubscriptionConfig,
    peer: std::net::SocketAddr,
) -> Response<Full<Bytes>> {
    use crate::sub::{self, Endpoint, Format};
    let header = |name: hyper::header::HeaderName| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let ua = header(hyper::header::USER_AGENT);
    // The configured public domain wins; otherwise trust the Host the
    // client reached us by (TLS is terminated in front, so port 443).
    let ep = match &cfg.domain {
        Some(d) => Endpoint::parse(d),
        None => Endpoint {
            host: header(hyper::header::HOST)
                .rsplit_once(':')
                .map(|(h, _)| h.to_string())
                .unwrap_or_else(|| header(hyper::header::HOST)),
            port: 443,
        },
    };
    let format = Format::detect(req.uri().query(), &ua);
    info!(peer = %peer, ?format, ua = %ua, "subscription served");
    let (body, ctype, ext) = match format {
        Format::Clash => (
            sub::clash(cfg, &ep, &sub.name),
            "text/yaml; charset=utf-8",
            "yaml",
        ),
        Format::SingBox => (
            sub::singbox(cfg, &ep, &sub.name),
            "application/json; charset=utf-8",
            "json",
        ),
        Format::Base64 => (
            sub::base64_list(cfg, &ep, &sub.name),
            "text/plain; charset=utf-8",
            "txt",
        ),
    };
    Response::builder()
        .header(hyper::header::CONTENT_TYPE, ctype)
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .header(
            "profile-update-interval",
            sub.update_interval_hours.to_string(),
        )
        .header(
            "profile-title",
            format!("base64:{}", {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(&sub.name)
            }),
        )
        .header(
            hyper::header::CONTENT_DISPOSITION,
            format!(
                "attachment; filename*=UTF-8''{}.{ext}",
                sub::urlencode(&sub.name)
            ),
        )
        .body(Full::new(Bytes::from(body)))
        .unwrap()
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
