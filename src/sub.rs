//! Client configuration output: share links (printed by the `links` CLI) and
//! the optional subscription endpoint, which serves the same nodes as a
//! Clash/mihomo profile, a sing-box profile, or a base64 link list.
//!
//! Only VLESS and Shadowsocks are exported: no mainstream client can dial
//! SOCKS5 over a WebSocket from a subscription, so SOCKS5 inbounds are left
//! out (configure those by hand in Xray).

use crate::config::{Config, Inbound, Protocol};
use base64::Engine;
use serde_json::{json, Value};

/// Public address clients connect to (TLS is terminated in front of us).
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    /// Parse "host" or "host:port" (port defaults to 443).
    pub fn parse(s: &str) -> Self {
        let s = s.trim();
        if let Some((h, p)) = s.rsplit_once(':') {
            if let (false, Ok(port)) = (h.contains(':'), p.parse::<u16>()) {
                return Self {
                    host: h.to_string(),
                    port,
                };
            }
        }
        Self {
            host: s.trim_matches(['[', ']']).to_string(),
            port: 443,
        }
    }
}

/// Output format of a subscription response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Clash,
    SingBox,
    Base64,
}

impl Format {
    /// `?format=` wins; otherwise guess from the client's User-Agent.
    pub fn detect(query: Option<&str>, user_agent: &str) -> Self {
        if let Some(q) = query {
            for pair in q.split('&') {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                if k == "format" || k == "target" || k == "flag" {
                    match v.to_ascii_lowercase().as_str() {
                        "clash" | "mihomo" | "meta" | "clash-meta" | "clashmeta" | "stash" => {
                            return Self::Clash
                        }
                        "singbox" | "sing-box" | "sfa" | "sfi" | "sfm" => return Self::SingBox,
                        "base64" | "v2ray" | "v2rayn" | "v2rayng" | "links" => return Self::Base64,
                        _ => {}
                    }
                }
            }
        }
        let ua = user_agent.to_ascii_lowercase();
        if ua.contains("sing-box") || ua.contains("singbox") {
            Self::SingBox
        } else if ua.contains("clash") || ua.contains("mihomo") || ua.contains("stash") {
            Self::Clash
        } else {
            Self::Base64
        }
    }
}

/// One exportable node.
struct Node<'a> {
    name: String,
    inbound: &'a Inbound,
}

fn nodes<'a>(cfg: &'a Config, prefix: &str) -> Vec<Node<'a>> {
    let mut out: Vec<Node> = Vec::new();
    for ib in &cfg.inbounds {
        let base = match &ib.protocol {
            Protocol::Vless(_) => format!("{prefix} VLESS"),
            Protocol::Shadowsocks(s) if s.method.starts_with("2022-") => {
                format!("{prefix} SS-2022")
            }
            Protocol::Shadowsocks(s) => format!("{prefix} SS {}", s.method),
            Protocol::Socks5(_) => continue,
        };
        let mut name = base.clone();
        let mut n = 2;
        while out.iter().any(|x| x.name == name) {
            name = format!("{base} {n}");
            n += 1;
        }
        out.push(Node { name, inbound: ib });
    }
    out
}

pub fn urlencode(s: &str) -> String {
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

/// Share links, one per exportable inbound.
pub fn share_links(cfg: &Config, ep: &Endpoint, prefix: &str) -> Vec<String> {
    let (h, port) = (&ep.host, ep.port);
    let he = urlencode(h);
    nodes(cfg, prefix)
        .into_iter()
        .map(|node| {
            let path_enc = urlencode(&node.inbound.path);
            let frag = urlencode(&node.name);
            match &node.inbound.protocol {
                Protocol::Vless(v) => format!(
                    "vless://{uuid}@{h}:{port}?encryption=none&security=tls&sni={he}&fp=chrome&type=ws&host={he}&path={path_enc}#{frag}",
                    uuid = v.uuid,
                ),
                Protocol::Shadowsocks(s) => {
                    let userinfo = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(format!("{}:{}", s.method, s.password));
                    let plugin = format!(
                        "v2ray-plugin;tls;mux=0;mode=websocket;host={h};path={}",
                        node.inbound.path
                    );
                    // Both the SIP002 plugin form (sing-box, NekoBox, Shadowrocket,
                    // v2rayN) and the plain transport fields (newer v2rayNG).
                    format!(
                        "ss://{userinfo}@{h}:{port}/?plugin={plugin}&type=ws&host={he}&path={path_enc}&security=tls&sni={he}#{frag}",
                        plugin = urlencode(&plugin),
                    )
                }
                Protocol::Socks5(_) => unreachable!("filtered out by nodes()"),
            }
        })
        .collect()
}

/// v2rayN / v2rayNG / Shadowrocket subscription body.
pub fn base64_list(cfg: &Config, ep: &Endpoint, prefix: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(share_links(cfg, ep, prefix).join("\n"))
}

/// YAML scalar: JSON strings are valid double-quoted YAML.
fn y(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

/// A complete Clash Meta (mihomo) profile.
pub fn clash(cfg: &Config, ep: &Endpoint, prefix: &str) -> String {
    let nodes = nodes(cfg, prefix);
    let h = y(&ep.host);
    let mut s = String::new();
    s.push_str(
        "# Generated by rust-ws-relay. Requires a mihomo (Clash Meta) core.\n\
mixed-port: 7890\n\
allow-lan: false\n\
mode: rule\n\
log-level: info\n\
ipv6: false\n\
unified-delay: true\n\
dns:\n  enable: true\n  ipv6: false\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n\
  default-nameserver:\n    - 1.1.1.1\n    - 8.8.8.8\n\
  nameserver:\n    - https://1.1.1.1/dns-query\n    - https://dns.google/dns-query\n\
proxies:\n",
    );
    for n in &nodes {
        let path = y(&n.inbound.path);
        match &n.inbound.protocol {
            Protocol::Vless(v) => s.push_str(&format!(
                "  - name: {name}\n    type: vless\n    server: {h}\n    port: {port}\n    uuid: {uuid}\n    udp: true\n    packet-encoding: packetaddr\n    tls: true\n    servername: {h}\n    client-fingerprint: chrome\n    network: ws\n    ws-opts:\n      path: {path}\n      headers:\n        Host: {h}\n",
                name = y(&n.name),
                port = ep.port,
                uuid = y(&v.uuid),
            )),
            Protocol::Shadowsocks(ss) => s.push_str(&format!(
                "  - name: {name}\n    type: ss\n    server: {h}\n    port: {port}\n    cipher: {method}\n    password: {pw}\n    udp: true\n    udp-over-tcp: true\n    udp-over-tcp-version: 2\n    plugin: v2ray-plugin\n    plugin-opts:\n      mode: websocket\n      tls: true\n      host: {h}\n      path: {path}\n      mux: false\n",
                name = y(&n.name),
                port = ep.port,
                method = y(&ss.method),
                pw = y(&ss.password),
            )),
            Protocol::Socks5(_) => {}
        }
    }
    let list: Vec<String> = nodes
        .iter()
        .map(|n| format!("      - {}\n", y(&n.name)))
        .collect();
    let list = list.concat();
    s.push_str("proxy-groups:\n  - name: Proxy\n    type: select\n    proxies:\n      - Auto\n");
    s.push_str(&list);
    s.push_str("  - name: Auto\n    type: url-test\n    url: https://www.gstatic.com/generate_204\n    interval: 300\n    proxies:\n");
    s.push_str(&list);
    s.push_str(
        "rules:\n\
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve\n\
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n\
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve\n\
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve\n\
  - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve\n\
  - MATCH,Proxy\n",
    );
    s
}

/// A complete sing-box (1.12+) profile, with a TUN inbound for the
/// graphical clients and a local mixed port.
pub fn singbox(cfg: &Config, ep: &Endpoint, prefix: &str) -> String {
    let nodes = nodes(cfg, prefix);
    let names: Vec<Value> = nodes.iter().map(|n| json!(n.name)).collect();
    let mut sel: Vec<Value> = vec![json!("auto")];
    sel.extend(names.iter().cloned());
    let mut outbounds = vec![
        json!({ "type": "selector", "tag": "proxy", "outbounds": sel, "default": "auto" }),
        json!({ "type": "urltest", "tag": "auto", "outbounds": names, "url": "https://www.gstatic.com/generate_204", "interval": "5m" }),
    ];
    for n in &nodes {
        let path = &n.inbound.path;
        outbounds.push(match &n.inbound.protocol {
            Protocol::Vless(v) => json!({
                "type": "vless",
                "tag": n.name,
                "server": ep.host,
                "server_port": ep.port,
                "uuid": v.uuid,
                // packetaddr: all UDP over one VLESS stream (no XUDP/mux).
                "packet_encoding": "packetaddr",
                // uTLS: present a Chrome ClientHello instead of Go's own,
                // matching fp=chrome in the links and the Clash profile.
                "tls": {
                    "enabled": true,
                    "server_name": ep.host,
                    "utls": { "enabled": true, "fingerprint": "chrome" }
                },
                "transport": { "type": "ws", "path": path, "headers": { "Host": ep.host } }
            }),
            Protocol::Shadowsocks(ss) => json!({
                "type": "shadowsocks",
                "tag": n.name,
                "server": ep.host,
                "server_port": ep.port,
                "method": ss.method,
                "password": ss.password,
                "plugin": "v2ray-plugin",
                "plugin_opts": format!("mode=websocket;tls;host={};path={};mux=0", ep.host, path),
                "udp_over_tcp": { "enabled": true, "version": 2 }
            }),
            Protocol::Socks5(_) => unreachable!("filtered out by nodes()"),
        });
    }
    outbounds.push(json!({ "type": "direct", "tag": "direct" }));

    let profile = json!({
        "log": { "level": "info" },
        "dns": {
            "servers": [
                { "type": "tcp", "tag": "remote", "server": "1.1.1.1", "detour": "proxy" },
                { "type": "local", "tag": "local" }
            ],
            "final": "remote",
            "strategy": "ipv4_only"
        },
        "inbounds": [
            { "type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": true, "strict_route": true, "stack": "mixed" },
            { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080 }
        ],
        "outbounds": outbounds,
        "route": {
            "rules": [
                { "action": "sniff" },
                { "protocol": "dns", "action": "hijack-dns" },
                { "ip_is_private": true, "outbound": "direct" }
            ],
            "final": "proxy",
            "auto_detect_interface": true,
            "default_domain_resolver": "local"
        }
    });
    serde_json::to_string_pretty(&profile).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        toml::from_str(
            r#"
domain = "relay.example.com"
[subscription]
path = "/sub-abcdefghij"
[[inbounds]]
path = "/v"
protocol = "vless"
uuid = "00000000-0000-4000-8000-000000000000"
[[inbounds]]
path = "/s"
protocol = "shadowsocks"
method = "2022-blake3-aes-256-gcm"
password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
[[inbounds]]
path = "/x"
protocol = "socks5"
"#,
        )
        .unwrap()
    }

    #[test]
    fn detect_format() {
        assert_eq!(
            Format::detect(None, "ClashMetaForAndroid/2.11"),
            Format::Clash
        );
        assert_eq!(Format::detect(None, "mihomo/1.19"), Format::Clash);
        assert_eq!(
            Format::detect(None, "SFA/1.12.0 (sing-box 1.12.0)"),
            Format::SingBox
        );
        assert_eq!(Format::detect(None, "v2rayNG/1.10"), Format::Base64);
        assert_eq!(
            Format::detect(Some("format=singbox"), "clash"),
            Format::SingBox
        );
    }

    #[test]
    fn endpoint_parse() {
        let e = Endpoint::parse("a.example:8443");
        assert_eq!((e.host.as_str(), e.port), ("a.example", 8443));
        let e = Endpoint::parse("a.example");
        assert_eq!((e.host.as_str(), e.port), ("a.example", 443));
    }

    #[test]
    fn outputs_skip_socks_and_parse() {
        let c = cfg();
        let ep = Endpoint::parse("relay.example.com");
        assert_eq!(share_links(&c, &ep, "r").len(), 2);
        let sb: Value = serde_json::from_str(&singbox(&c, &ep, "r")).unwrap();
        assert_eq!(sb["outbounds"].as_array().unwrap().len(), 5);
        let vless = sb["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["type"] == "vless")
            .unwrap();
        assert_eq!(vless["tls"]["utls"]["fingerprint"], "chrome");
        let yml = clash(&c, &ep, "r");
        assert!(yml.contains("type: vless") && yml.contains("udp-over-tcp: true"));
        assert!(yml.contains("packet-encoding: packetaddr"));
        assert!(!yml.contains("socks"));
        let raw = base64::engine::general_purpose::STANDARD
            .decode(base64_list(&c, &ep, "r"))
            .unwrap();
        assert!(String::from_utf8(raw).unwrap().starts_with("vless://"));
    }
}
