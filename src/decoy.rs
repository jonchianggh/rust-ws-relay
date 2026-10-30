//! The cover website. Every request that is not a valid proxy handshake on a
//! configured path is answered here, so an observer sees an ordinary site and
//! never a hint of the proxy, a UUID, or a share link.

use crate::config::Decoy;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use std::path::{Component, Path, PathBuf};

const BUILTIN_INDEX: &str = include_str!("decoy_index.html");

pub async fn respond(cfg: &Decoy, req: &Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    match cfg {
        Decoy::Builtin => builtin(req.uri().path()),
        Decoy::Static { dir } => serve_static(dir, req.uri().path()),
        Decoy::Reverse { upstream } => reverse(upstream, req).await,
    }
}

fn html(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("server", "nginx")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn builtin(path: &str) -> Response<Full<Bytes>> {
    match path {
        "/" => html(StatusCode::OK, BUILTIN_INDEX.to_string()),
        "/robots.txt" => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .header("server", "nginx")
            .body(Full::new(Bytes::from_static(b"User-agent: *\nDisallow:\n")))
            .unwrap(),
        "/favicon.ico" => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("server", "nginx")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        _ => html(
            StatusCode::NOT_FOUND,
            "<!doctype html><title>404 Not Found</title><h1>404 Not Found</h1>".to_string(),
        ),
    }
}

fn serve_static(dir: &Path, req_path: &str) -> Response<Full<Bytes>> {
    let rel = req_path.trim_start_matches('/');
    let mut file = PathBuf::from(dir);
    // Reject traversal.
    let candidate = Path::new(rel);
    for c in candidate.components() {
        match c {
            Component::Normal(p) => file.push(p),
            Component::CurDir => {}
            _ => {
                return html(StatusCode::NOT_FOUND, not_found());
            }
        }
    }
    if rel.is_empty() || file.is_dir() {
        file.push("index.html");
    }
    match std::fs::read(&file) {
        Ok(bytes) => {
            let ctype = content_type(&file);
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", ctype)
                .header("server", "nginx")
                .body(Full::new(Bytes::from(bytes)))
                .unwrap()
        }
        Err(_) => html(StatusCode::NOT_FOUND, not_found()),
    }
}

fn not_found() -> String {
    "<!doctype html><title>404 Not Found</title><h1>404 Not Found</h1>".to_string()
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain; charset=utf-8",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

/// Best-effort reverse proxy to an http:// upstream. (For an https upstream,
/// front the relay with your own TLS-terminating proxy and point this at it.)
async fn reverse(upstream: &str, req: &Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let url = format!("{}{}", upstream.trim_end_matches('/'), req.uri().path());
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let proxied = match Request::builder()
        .method(req.method())
        .uri(&url)
        .body(Full::new(Bytes::new()))
    {
        Ok(r) => r,
        Err(_) => return html(StatusCode::BAD_GATEWAY, "502".into()),
    };
    match client.request(proxied).await {
        Ok(resp) => {
            let status = resp.status();
            let ctype = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("text/html; charset=utf-8")
                .to_string();
            use http_body_util::BodyExt;
            let bytes = resp
                .into_body()
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            Response::builder()
                .status(status)
                .header("content-type", ctype)
                .header("server", "nginx")
                .body(Full::new(bytes))
                .unwrap()
        }
        Err(_) => html(StatusCode::BAD_GATEWAY, "<h1>502 Bad Gateway</h1>".into()),
    }
}
