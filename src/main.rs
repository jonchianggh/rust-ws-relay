//! rust-ws-relay: a lightweight proxy that carries VLESS, Shadowsocks and
//! SOCKS5 over a single WebSocket, hidden behind a natural decoy website.
//!
//! A Rust reimplementation of the idea behind vevc/nodejs-vless, with the
//! remote-shell feature removed and a few safety features added.

mod addr;
mod config;
mod decoy;
mod proto;
mod relay;
mod server;
mod uot;
mod wsbytes;

use clap::{Parser, Subcommand};
use config::{Config, Protocol};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rust-ws-relay", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server.
    Run {
        /// Path to the TOML config file.
        #[arg(short, long, default_value = "config.toml")]
        config: PathBuf,
    },
    /// Print client share links for a config's inbounds (never served over HTTP).
    Links {
        #[arg(short, long, default_value = "config.toml")]
        config: PathBuf,
        /// Override the public host/port used in links, e.g. "example.com:443".
        #[arg(long)]
        host: Option<String>,
    },
    /// Generate a fresh random secret path and a matching UUID.
    Gen,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run { config } => {
            init_tracing();
            let cfg = Config::load(&config)?;
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(async move {
                tokio::select! {
                    r = server::run(cfg) => r,
                    _ = shutdown_signal() => {
                        tracing::info!("shutting down");
                        Ok(())
                    }
                }
            })
        }
        Command::Links { config, host } => {
            let cfg = Config::load(&config)?;
            print_links(&cfg, host);
            Ok(())
        }
        Command::Gen => {
            use rand::Rng;
            let path: String = (0..10)
                .map(|_| rand::thread_rng().gen_range(b'a'..=b'z') as char)
                .collect();
            let uuid = uuid::Uuid::new_v4();
            println!("path = \"/{path}\"");
            println!("uuid = \"{uuid}\"");
            Ok(())
        }
    }
}

fn print_links(cfg: &Config, host_override: Option<String>) {
    let host = host_override
        .or_else(|| cfg.domain.clone())
        .unwrap_or_else(|| cfg.listen.to_string());
    let (hostname, port) = match host.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.to_string()),
        None => (host.clone(), "443".to_string()),
    };

    for ib in &cfg.inbounds {
        let path_enc = urlencode(&ib.path);
        match &ib.protocol {
            Protocol::Vless(v) => {
                println!(
                    "vless://{uuid}@{hostname}:{port}?encryption=none&security=tls&sni={hostname}&fp=chrome&type=ws&host={hostname}&path={path}#rust-ws-relay-vless",
                    uuid = v.uuid,
                    path = path_enc,
                );
            }
            Protocol::Shadowsocks(s) => {
                // SIP002 with the v2ray-plugin websocket convention (mux off),
                // understood by v2rayN, Shadowrocket, NekoBox, sing-box, etc.
                use base64::Engine;
                let userinfo = if s.method.starts_with("2022-") {
                    // SIP022: 2022 keys go in plain (percent-encoded) form.
                    format!("{}:{}", urlencode(&s.method), urlencode(&s.password))
                } else {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(format!("{}:{}", s.method, s.password))
                };
                let plugin = format!(
                    "v2ray-plugin;tls;mux=0;mode=websocket;host={hostname};path={}",
                    ib.path
                );
                println!(
                    "ss://{userinfo}@{hostname}:{port}/?plugin={plugin}#rust-ws-relay-ss",
                    plugin = urlencode(&plugin),
                );
            }
            Protocol::Socks5(_) => {
                println!(
                    "# socks5 inbound at wss://{hostname}:{port}{path} (configure a ws-capable SOCKS client)",
                    path = ib.path,
                );
            }
        }
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
