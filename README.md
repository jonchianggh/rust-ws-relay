# rust-ws-relay

A lightweight proxy relay written in Rust. It carries **VLESS**, **Shadowsocks** (SS-2022 and legacy AEAD) and **SOCKS5** over a single WebSocket port, and hides behind a natural-looking decoy website.

It's a Rust reimplementation of the idea behind [vevc/nodejs-vless](https://github.com/vevc/nodejs-vless). The approach is the same, but the language and a few defaults are different:

| | nodejs-vless | rust-ws-relay |
|---|---|---|
| Runtime | Node.js (~100 MB) + `ws` | single static binary (~2 MB), no runtime |
| Idle memory | ~40–50 MB | ~2 MB |
| Protocols | VLESS | VLESS, Shadowsocks (2022 + legacy), SOCKS5 |
| Remote shell endpoint | optional `POST /<uuid>/run` | **removed entirely** |
| Home page | advertises `/your-uuid` and the repo | generic decoy; never reveals a UUID, path or link |
| Share links | served over HTTP at `/<uuid>` | printed offline by `links`; optional subscription URL (Clash/mihomo, sing-box, base64) on its own secret path |
| Private-network access | unrestricted | blocked by default (127/8, 10/8, 192.168/16, ::1, …) |
| Timeouts | none | handshake + idle timeouts |

TCP for every protocol, plus UDP:

- **VLESS UDP** (command 2): datagrams are length-framed over the WebSocket. The v2ray **packetaddr** encoding (mihomo and sing-box `packet-encoding: packetaddr`) carries UDP to many destinations over one VLESS stream.
- **Shadowsocks and SOCKS5 UDP** via sing-box style **UDP-over-TCP** (UoT v1 and v2, the `sp.v2.udp-over-tcp.arpa` magic address). Turn on `udp_over_tcp` in a sing-box based client (sing-box, NekoBox, Hiddify, Karing...). Plain SS UDP and SOCKS5 UDP ASSOCIATE can't cross a WebSocket, and Xray's SS outbound doesn't send UoT over ws.

Every DNS datagram (port 53) goes to `[udp] dns_upstream` (default `1.1.1.1:53`), so remote DNS works even when the client names a private resolver; replies are reported as coming from the server the client asked. Other UDP goes to the requested public destination unless `dns_only = true`. Not supported yet: VLESS mux/XUDP (command 3, which Xray uses by default for non-DNS UDP) and XTLS flows.

## How it works

```
client ──TLS──▶ CDN / reverse proxy / InstaBox gateway ──HTTP──▶ rust-ws-relay :3000
                                                              │
     WebSocket upgrade on a configured secret path ───────────┤──▶ VLESS / SS / SOCKS5 ──▶ target
     anything else ───────────────────────────────────────────┘──▶ decoy website
```

- Each inbound owns one **secret WebSocket path**. Only a WebSocket upgrade on that exact path reaches the proxy.
- A plain `GET` to a secret path, a WebSocket upgrade to any other path, and every other request all get the decoy, with an identical `404` for unknown pages.
- TLS is expected to be terminated in front of the relay, so the relay itself speaks plain HTTP.

## Quick start

### On InstaBox or any Linux box with systemd

```sh
curl -fsSL https://raw.githubusercontent.com/jonchianggh/rust-ws-relay/main/deploy/install.sh | sudo sh
```

The installer:

1. Downloads the latest release binary for your CPU (x86_64 or aarch64, statically linked).
2. Writes `/etc/rust-ws-relay/config.toml` with **freshly generated** paths, UUID and keys. An existing file is never overwritten.
3. Installs and starts the `rust-ws-relay` systemd service (falls back to `nohup` without systemd).
4. On InstaBox, publishes port 3000 with `instabox-port publish`. InstaBox gives it an HTTPS URL and terminates TLS, and WebSockets pass straight through.

Then print your client links, using the public host InstaBox (or your CDN) gave you:

```sh
sudo rust-ws-relay links --config /etc/rust-ws-relay/config.toml --host 3000-xxxx.instabox.sh:443
```

> **InstaBox free plan:** machines pause after 30 idle minutes and run at most 8 hours at a stretch, followed by a 5–20 minute cooldown. A request to the public URL wakes an idle-paused machine, and systemd restarts the relay after a reboot.

### From source

```sh
cargo build --release
cp config.example.toml config.toml   # then replace every secret
./target/release/rust-ws-relay gen   # random path + UUID
openssl rand -base64 32              # SS-2022 key (use 16 for aes-128)
./target/release/rust-ws-relay run --config config.toml
```

## Configuration

See [`config.example.toml`](config.example.toml). Key settings:

| Key | Default | Meaning |
|---|---|---|
| `listen` | `0.0.0.0:3000` | Bind address (plain HTTP) |
| `domain` | – | Public host (`host` or `host:port`) used in links and the subscription |
| `handshake_timeout_secs` | `10` | Time allowed to send a protocol header |
| `idle_timeout_secs` | `300` | Close a connection idle in **both** directions this long (`0` = never) |
| `block_private_addresses` | `true` | Refuse private, loopback and link-local targets (also checked after DNS) |

### Inbounds

```toml
[[inbounds]]
path = "/k3j9x2m1qz"
protocol = "vless"
uuid = "e84e913f-0d63-43c9-955c-25f310738a4b"

[[inbounds]]
path = "/p8w2n5c7aa"
protocol = "shadowsocks"
method = "2022-blake3-aes-256-gcm"   # base64 key of exactly 32 bytes
password = "…"

[[inbounds]]
path = "/r4t6y8u0bb"
protocol = "shadowsocks"
method = "chacha20-ietf-poly1305"    # or aes-256-gcm / aes-128-gcm, any password
password = "…"

[[inbounds]]
path = "/z1x3c5v7cc"
protocol = "socks5"
username = "user"                     # strongly recommended; without auth the path is an open proxy
password = "…"
```

Supported Shadowsocks methods: `2022-blake3-aes-256-gcm`, `2022-blake3-aes-128-gcm`, `aes-256-gcm`, `aes-128-gcm`, `chacha20-ietf-poly1305`. SS-2022 includes the timestamp window check and salt replay protection.

### Decoy website

```toml
[decoy]
mode = "builtin"                 # a small generic status page (default)

# mode = "static"                # serve your own site: index.html, css, images…
# dir = "/opt/rust-ws-relay/site"

# mode = "reverse"               # mirror a real site
# upstream = "http://example.org"
```

All responses carry `server: nginx`. Static mode rejects path traversal.

## Subscription

Add a `[subscription]` table and every VLESS and Shadowsocks inbound is served as one profile on a secret path:

```toml
[subscription]
path = "/sub-3k9x7q2m1v8p4z"     # 12+ characters; anyone with it gets every credential
name = "rust-ws-relay"           # profile name and node-name prefix
update_interval_hours = 24
```

Subscribe to `https://<domain><path>`. The format follows the client's User-Agent, or `?format=`:

| `?format=` | Auto-detected for | Contents |
|---|---|---|
| `clash` | Clash Meta / mihomo, Clash Verge, Stash | Full mihomo profile: VLESS (UDP via packetaddr), SS with `v2ray-plugin` + UoT v2, select and url-test groups |
| `singbox` | sing-box, SFA / SFI / SFM | Full sing-box 1.12+ profile: TUN + mixed inbound, the same nodes, DNS over TCP through the proxy |
| `base64` | everything else (v2rayN, v2rayNG, Shadowrocket, NekoBox) | Base64 list of share links |

Hostnames come from `domain` (or the request's `Host` when unset), port 443. SOCKS5 inbounds are left out because none of these clients can dial SOCKS5 over a WebSocket. Only `GET` on the exact path answers; everything else is the decoy. `rust-ws-relay links` prints the URL.

## Clients

Tested end-to-end with **Xray-core** using a `ws` transport for every protocol:

- **VLESS:** standard `vless://` link (`type=ws`, `security=tls`, `path=<your path>`).
- **Shadowsocks:** any client whose Shadowsocks outbound supports a WebSocket transport (Xray, sing-box). `links` prints SIP002 links using the `v2ray-plugin` convention with `mux=0`, which v2rayN, NekoBox and Shadowrocket import.
- **SOCKS5:** Xray's `socks` outbound with `streamSettings.network = "ws"`, or any SOCKS-over-WebSocket client.

Example Xray outbound (Shadowsocks 2022 over WebSocket):

```json
{
  "protocol": "shadowsocks",
  "settings": { "servers": [{ "address": "your.host", "port": 443,
    "method": "2022-blake3-aes-256-gcm", "password": "<base64 key>" }] },
  "streamSettings": { "network": "ws", "security": "tls",
    "tlsSettings": { "serverName": "your.host" },
    "wsSettings": { "path": "/p8w2n5c7aa", "host": "your.host" } }
}
```

## Releases

Pushing a tag such as `v0.1.0` runs [`.github/workflows/release.yml`](.github/workflows/release.yml), which builds static musl binaries for x86_64 and aarch64 with `cargo-zigbuild` and attaches them, with SHA-256 sums, to a GitHub Release. The installer downloads from there.

## Security notes

- Treat every path, UUID and key as a password. Anyone with a share link can use that inbound.
- There is deliberately **no** remote command execution of any kind.
- VLESS here is bare (`encryption=none`), so confidentiality comes entirely from the TLS in front of it. Never expose port 3000 directly to the internet without TLS. Whoever terminates that TLS (a CDN or hosting gateway) can see VLESS traffic in plaintext; Shadowsocks stays encrypted end to end, so prefer SS-2022 behind an edge you don't control.
- Shadowsocks client salts are replay-filtered: SS-2022 within its 60-second window, legacy AEAD across the most recent 100,000 sessions (the filter is in memory and resets on restart).
- The generated sing-box profile turns on uTLS with a Chrome fingerprint for VLESS, matching `fp=chrome` in the share links and the Clash profile.
- Use responsibly and in line with your hosting provider's terms and local law.

## License

MIT
