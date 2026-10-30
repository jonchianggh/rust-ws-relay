#!/usr/bin/env sh
# rust-ws-relay installer for a Linux box with systemd (InstaBox, any VPS).
#
#   curl -fsSL https://raw.githubusercontent.com/jonchianggh/rust-ws-relay/main/deploy/install.sh | sudo sh
#
# Downloads the latest release binary, writes /etc/rust-ws-relay/config.toml
# with freshly generated secrets (only if it doesn't exist yet), installs and
# starts the systemd service, and on InstaBox publishes the port.
#
# Env overrides: VERSION (default: latest), PORT (default: 3000), DOMAIN.
set -eu

REPO="jonchianggh/rust-ws-relay"
PORT="${PORT:-3000}"
VERSION="${VERSION:-latest}"
BIN=/usr/local/bin/rust-ws-relay
CONF_DIR=/etc/rust-ws-relay
CONF="$CONF_DIR/config.toml"

if [ "$(id -u)" -ne 0 ]; then
  echo "please run as root (sudo sh install.sh)" >&2; exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) TARGET=x86_64-unknown-linux-musl ;;
  aarch64|arm64) TARGET=aarch64-unknown-linux-musl ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/$REPO/releases/latest/download/rust-ws-relay-$TARGET.tar.gz"
else
  URL="https://github.com/$REPO/releases/download/$VERSION/rust-ws-relay-$TARGET.tar.gz"
fi

echo "==> downloading $URL"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL "$URL" -o "$TMP/r.tar.gz"
tar -xzf "$TMP/r.tar.gz" -C "$TMP"
install -m 0755 "$TMP/rust-ws-relay" "$BIN"
echo "==> installed $($BIN --version)"

rand_path() { echo "/$(head -c 1024 /dev/urandom | tr -dc 'a-z0-9' | head -c 12)"; }
rand_pass() { head -c 1024 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 24; }

if [ ! -f "$CONF" ]; then
  echo "==> generating $CONF"
  mkdir -p "$CONF_DIR"
  UUID="$(cat /proc/sys/kernel/random/uuid)"
  SSKEY="$(head -c 32 /dev/urandom | base64)"
  DOMAIN_LINE=""
  if [ -n "${DOMAIN:-}" ]; then DOMAIN_LINE="domain = \"$DOMAIN\""; fi
  cat > "$CONF" <<CFG
listen = "0.0.0.0:$PORT"
$DOMAIN_LINE

[decoy]
mode = "builtin"

[[inbounds]]
path = "$(rand_path)"
protocol = "vless"
uuid = "$UUID"

[[inbounds]]
path = "$(rand_path)"
protocol = "shadowsocks"
method = "2022-blake3-aes-256-gcm"
password = "$SSKEY"

[[inbounds]]
path = "$(rand_path)"
protocol = "shadowsocks"
method = "chacha20-ietf-poly1305"
password = "$(rand_pass)"

[[inbounds]]
path = "$(rand_path)"
protocol = "socks5"
username = "user"
password = "$(rand_pass)"
CFG
  # The service runs as a DynamicUser, so the file must be world-readable.
  # Fine on a single-user box; tighten (e.g. a dedicated user) if you share it.
  chmod 0644 "$CONF"
else
  echo "==> keeping existing $CONF"
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  curl -fsSL "https://raw.githubusercontent.com/$REPO/main/deploy/rust-ws-relay.service" \
    -o /etc/systemd/system/rust-ws-relay.service
  systemctl daemon-reload
  systemctl enable --now rust-ws-relay
  systemctl restart rust-ws-relay
  echo "==> service running: systemctl status rust-ws-relay"
else
  echo "==> no systemd; starting in background (logs: /var/log/rust-ws-relay.log)"
  nohup "$BIN" run --config "$CONF" >>/var/log/rust-ws-relay.log 2>&1 &
fi

if command -v instabox-port >/dev/null 2>&1; then
  echo "==> publishing port $PORT on InstaBox"
  instabox-port publish "$PORT" --name "web" || true
  echo "    use the printed https URL's host as DOMAIN for your client links"
fi

echo
echo "==> client links (keep these private):"
if [ -n "${DOMAIN:-}" ]; then
  "$BIN" links --config "$CONF" --host "$DOMAIN:443"
else
  echo "    run: sudo $BIN links --config $CONF --host <your-public-host>:443"
fi
