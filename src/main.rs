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
mod sub;
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
    /// Print client share links and the subscription URL for a config.
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
    let ep = sub::Endpoint::parse(&host);
    let name = cfg
        .subscription
        .as_ref()
        .map(|s| s.name.clone())
        .unwrap_or_else(|| "rust-ws-relay".to_string());
    for link in sub::share_links(cfg, &ep, &name) {
        println!("{link}");
    }
    for ib in &cfg.inbounds {
        if let Protocol::Socks5(_) = ib.protocol {
            println!(
                "# socks5 inbound at wss://{}:{}{} (configure a ws-capable SOCKS client)",
                ep.host, ep.port, ib.path
            );
        }
    }
    if let Some(s) = &cfg.subscription {
        println!("# subscription: https://{}:{}{}", ep.host, ep.port, s.path);
        println!("#   ?format=clash | singbox | base64 (auto-detected from the client otherwise)");
    }
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
