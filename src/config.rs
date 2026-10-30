//! Configuration model, loaded from a TOML file.

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

fn default_listen() -> SocketAddr {
    "0.0.0.0:3000".parse().unwrap()
}

fn default_true() -> bool {
    true
}

fn default_handshake_timeout() -> u64 {
    10
}

fn default_idle_timeout() -> u64 {
    300
}

/// Top-level configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address the HTTP/WebSocket server binds to. TLS is expected to be
    /// terminated upstream (a CDN, a reverse proxy, or the InstaBox gateway).
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,

    /// Public hostname clients connect to (used only to generate share links).
    #[serde(default)]
    pub domain: Option<String>,

    /// Seconds allowed for a client to send its protocol header before the
    /// connection is dropped. Guards against half-open probes.
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,

    /// Seconds a proxied connection may sit with no traffic before it is closed.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,

    /// Refuse to proxy to private, loopback, link-local and multicast
    /// destinations. Keep this on unless you really trust every client.
    #[serde(default = "default_true")]
    pub block_private_addresses: bool,

    /// The cover website shown for every request that is not a valid proxy
    /// handshake on a configured path.
    #[serde(default)]
    pub decoy: Decoy,

    /// Inbound protocol endpoints. Each binds to one secret WebSocket path.
    #[serde(default)]
    pub inbounds: Vec<Inbound>,
}

/// How to answer ordinary web requests, so the server looks like a real site.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Decoy {
    /// Serve a small, believable built-in page.
    #[default]
    Builtin,
    /// Serve static files from a local directory (its index.html at `/`).
    Static { dir: PathBuf },
    /// Reverse-proxy unknown requests to a real upstream site.
    Reverse { upstream: String },
}

/// One inbound proxy endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct Inbound {
    /// The secret WebSocket path this endpoint listens on, e.g. "/a7f3c9e1".
    /// Anything that is not a WebSocket upgrade here falls through to the decoy.
    pub path: String,
    /// Protocol-specific settings.
    #[serde(flatten)]
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum Protocol {
    Vless(VlessConfig),
    Shadowsocks(ShadowsocksConfig),
    Socks5(Socks5Config),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlessConfig {
    /// Client UUID that must match the VLESS handshake.
    pub uuid: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowsocksConfig {
    /// Cipher name, e.g. "2022-blake3-aes-256-gcm", "aes-256-gcm",
    /// "chacha20-ietf-poly1305".
    pub method: String,
    /// Pre-shared key. For 2022 ciphers this is base64 of the raw key bytes;
    /// for legacy ciphers it is a password of any length.
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Socks5Config {
    /// Optional username/password auth (RFC 1929). Strongly recommended:
    /// without it, anyone who learns the path has an open proxy.
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.inbounds.is_empty() {
            anyhow::bail!("no [[inbounds]] configured; the server would only serve the decoy");
        }
        let mut seen = std::collections::HashSet::new();
        for ib in &self.inbounds {
            if !ib.path.starts_with('/') {
                anyhow::bail!("inbound path {:?} must start with '/'", ib.path);
            }
            if ib.path == "/" {
                anyhow::bail!("inbound path must not be '/', which is the decoy home page");
            }
            if !seen.insert(ib.path.clone()) {
                anyhow::bail!("duplicate inbound path {:?}", ib.path);
            }
            match &ib.protocol {
                Protocol::Vless(v) => {
                    crate::proto::vless::parse_uuid(&v.uuid)
                        .map_err(|_| anyhow::anyhow!("invalid VLESS uuid {:?}", v.uuid))?;
                }
                Protocol::Shadowsocks(s) => {
                    crate::proto::shadowsocks::resolve(&s.method, &s.password)
                        .map_err(|e| anyhow::anyhow!("inbound {}: {e}", ib.path))?;
                }
                Protocol::Socks5(s) => {
                    if s.username.is_some() != s.password.is_some() {
                        anyhow::bail!(
                            "inbound {}: set both socks5 username and password, or neither",
                            ib.path
                        );
                    }
                    if s.username.is_none() {
                        tracing::warn!(path = %ib.path, "socks5 inbound has no auth; anyone who finds the path can use it");
                    }
                }
            }
        }
        Ok(())
    }
}
