#!/usr/bin/env bash
#
# Dropjak — preparing the host for the Docker deployment
#
# This script runs ON THE HOST, as root. Its only job is to block forwarded
# traffic even in the early boot phase, before the Docker daemon and the
# container start:
#
#   - /etc/nftables/hatarvedelem-boot.nft  (policy drop on the forward chain)
#   - /etc/systemd/system/hatarvedelem-boot.service
#   - /etc/sysctl.d/90-hatarvedelem.conf   (net.ipv4.ip_forward = 1,
#     net.ipv4.conf.all.route_localnet = 1 for the input port proxy's
#     127.0.0.1 destination; the loopback_guard chain drops 127/8 packets
#     on every non-loopback interface)
#
# After loading its own rules, the container deletes the boot table, so the
# final rules take over.
#
# Usage:  sudo ./docker/setup-host.sh
#
# The script is idempotent: repeated runs leave the same state.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)

BOOT_NFT=/etc/nftables/hatarvedelem-boot.nft
BOOT_UNIT=/etc/systemd/system/hatarvedelem-boot.service
SYSCTL_FILE=/etc/sysctl.d/90-hatarvedelem.conf

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '[hatarvedelem] %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0"

[ -r "$REPO_DIR/deploy/hatarvedelem-boot.nft" ] \
    || die "missing file: $REPO_DIR/deploy/hatarvedelem-boot.nft"
[ -r "$REPO_DIR/deploy/hatarvedelem-boot.service" ] \
    || die "missing file: $REPO_DIR/deploy/hatarvedelem-boot.service"

# ------------------------------------------------------------- installing nft

NFT_BIN=$(command -v nft 2>/dev/null || true)
if [ -z "$NFT_BIN" ]; then
    info "nftables is not installed, installing it"
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y nftables
    elif command -v yum >/dev/null 2>&1; then
        yum install -y nftables
    elif command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nftables
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install nftables
    else
        die "no package manager found; install the nftables package manually"
    fi
    NFT_BIN=$(command -v nft 2>/dev/null || true)
fi
[ -n "$NFT_BIN" ] || die "nft cannot be found even after installation"

if ! command -v systemctl >/dev/null 2>&1; then
    die "this script assumes systemd"
fi

info "nft: $NFT_BIN"

# --------------------------------------------------------------- files

install -d -m 0755 /etc/nftables
install -m 0600 "$REPO_DIR/deploy/hatarvedelem-boot.nft" "$BOOT_NFT"

TMP_UNIT=$(mktemp)
trap 'rm -f "$TMP_UNIT"' EXIT
sed "s|__NFT_BIN__|$NFT_BIN|g" \
    "$REPO_DIR/deploy/hatarvedelem-boot.service" >"$TMP_UNIT"
grep -q '__[A-Z0-9_]*__' "$TMP_UNIT" && die "a placeholder remained in the unit"
install -m 0644 "$TMP_UNIT" "$BOOT_UNIT"

if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$BOOT_NFT" "$BOOT_UNIT" >/dev/null 2>&1 || true
fi

# --------------------------------------------------------------- sysctl

cat >"$SYSCTL_FILE" <<'EOF'
# Dropjak: the VM forwards the clients' traffic as a gateway.
# The actual permission is granted by the nftables allowed_v4 set.
net.ipv4.ip_forward = 1
# The input port proxy DNATs to 127.0.0.1 for targets listening only there
# (for example a Docker port published on 127.0.0.1). Packets arriving from
# outside with a 127/8 destination/source are dropped by the nft loopback_guard
# chain.
net.ipv4.conf.all.route_localnet = 1
EOF
chmod 0644 "$SYSCTL_FILE"

if command -v sysctl >/dev/null 2>&1; then
    sysctl -q -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    sysctl -q -w net.ipv4.conf.all.route_localnet=1 >/dev/null 2>&1 || true
else
    echo 1 >/proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    echo 1 >/proc/sys/net/ipv4/conf/all/route_localnet 2>/dev/null || true
fi
if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != "1" ]; then
    info "WARNING: net.ipv4.ip_forward cannot be enabled right now; it will be after a reboot."
fi

# --------------------------------------------------------------- unit

systemctl daemon-reload

# If Docker is already running, the container's rules protect the forward
# chain; loading the boot table immediately would interrupt clients that are
# already connected. In that case we only enable it; it takes effect at the
# next boot.
if systemctl is-active --quiet docker.service 2>/dev/null; then
    systemctl enable hatarvedelem-boot.service >/dev/null
    info "Docker is already running: the boot table is not loaded now, so that traffic is not interrupted."
    info "it will take effect before Docker on the next reboot."
else
    "$NFT_BIN" -c -f "$BOOT_NFT" || die "invalid boot rule file"
    systemctl enable --now hatarvedelem-boot.service
    systemctl is-active --quiet hatarvedelem-boot.service \
        || die "hatarvedelem-boot.service did not start"
    info "early forward blocking is active."
fi

# --------------------------------------------------------------- warning

for svc in firewalld ufw; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        info "WARNING: $svc is active on the host. Our nftables tables work"
        info "         independently of it, but other Docker containers' forwarded"
        info "         traffic may also be affected by the hatarvedelem rules. A dedicated gateway is recommended."
    fi
done

info "done."
info "Next step: cp .env.example .env, edit it, then docker compose up -d --build"
