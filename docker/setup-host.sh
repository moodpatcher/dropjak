#!/usr/bin/env bash
#
# Dropjak — preparing the host for the Docker deployment
#
# This script runs ON THE HOST, as root. Its only job is to block forwarded
# traffic even in the early boot phase, before the Docker daemon and the
# container start:
#
#   - /etc/nftables/dropjak-boot.nft  (policy drop on the forward chain)
#   - /etc/systemd/system/dropjak-boot.service
#   - /etc/sysctl.d/90-dropjak.conf   (net.ipv4.ip_forward = 1,
#     net.ipv4.conf.all.route_localnet = 1 for the input port proxy's
#     127.0.0.1 destination; the loopback_guard chain drops 127/8 packets
#     on every non-loopback interface; disable_ipv6 = 1 on HV_LAN_IF, read
#     from .env, two-NIC mode only)
#
# With HV_SINGLE_NIC=1 there is no separate client LAN interface: HV_LAN_IF is
# not required and the IPv6 setting for it is omitted.
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

BOOT_NFT=/etc/nftables/dropjak-boot.nft
BOOT_UNIT=/etc/systemd/system/dropjak-boot.service
SYSCTL_FILE=/etc/sysctl.d/90-dropjak.conf

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '[dropjak] %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0"

[ -r "$REPO_DIR/deploy/dropjak-boot.nft" ] \
    || die "missing file: $REPO_DIR/deploy/dropjak-boot.nft"
[ -r "$REPO_DIR/deploy/dropjak-boot.service" ] \
    || die "missing file: $REPO_DIR/deploy/dropjak-boot.service"

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
install -m 0600 "$REPO_DIR/deploy/dropjak-boot.nft" "$BOOT_NFT"

TMP_UNIT=$(mktemp)
trap 'rm -f "$TMP_UNIT"' EXIT
sed "s|__NFT_BIN__|$NFT_BIN|g" \
    "$REPO_DIR/deploy/dropjak-boot.service" >"$TMP_UNIT"
grep -q '__[A-Z0-9_]*__' "$TMP_UNIT" && die "a placeholder remained in the unit"
install -m 0644 "$TMP_UNIT" "$BOOT_UNIT"

if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$BOOT_NFT" "$BOOT_UNIT" >/dev/null 2>&1 || true
fi

# Upgrading from the previous file names: the old unit would load a second
# copy of the same table at boot. Stopping it does not open the forward chain
# (the unit has no ExecStop), and the new unit takes over.
LEGACY_BOOT_UNIT=/etc/systemd/system/hatarvedelem-boot.service
LEGACY_BOOT_NFT=/etc/nftables/hatarvedelem-boot.nft
if [ -e "$LEGACY_BOOT_UNIT" ]; then
    systemctl disable --now hatarvedelem-boot.service >/dev/null 2>&1 || true
    rm -f "$LEGACY_BOOT_UNIT" "$LEGACY_BOOT_NFT"
    info "removed the legacy hatarvedelem-boot unit"
fi

# --------------------------------------------------------------- sysctl

# IPv6 is always dropped by the firewall. In two-NIC mode the client LAN must
# have no other IPv6 router: a rogue router advertisement would give the
# clients an IPv6 path that bypasses the gateway. IPv6 is therefore switched
# off on the LAN interface (there is no opt-out). In single-NIC mode there is
# no separate LAN interface, so only ip_forward and route_localnet are set.
# The interface and the mode come from the environment or from the matching
# lines of .env (only those lines are read; the file also holds secrets).
LAN_IF=${HV_LAN_IF:-}
SINGLE_NIC=${HV_SINGLE_NIC:-}
if [ -z "$SINGLE_NIC" ] && [ -r "$REPO_DIR/.env" ]; then
    SINGLE_NIC=$(sed -n 's/^[[:space:]]*HV_SINGLE_NIC[[:space:]]*=[[:space:]]*//p' "$REPO_DIR/.env" \
        | tail -n 1 | sed 's/[[:space:]]*$//; s/^["'\'']//; s/["'\'']$//')
fi
case "$SINGLE_NIC" in
    ''|0) SINGLE_NIC=0 ;;
    1) SINGLE_NIC=1 ;;
    *) die "invalid HV_SINGLE_NIC: $SINGLE_NIC (expected 0 or 1)" ;;
esac
if [ -z "$LAN_IF" ] && [ -r "$REPO_DIR/.env" ]; then
    LAN_IF=$(sed -n 's/^[[:space:]]*HV_LAN_IF[[:space:]]*=[[:space:]]*//p' "$REPO_DIR/.env" \
        | tail -n 1 | sed 's/[[:space:]]*$//; s/^["'\'']//; s/["'\'']$//')
fi
if [ "$SINGLE_NIC" = "1" ]; then
    [ -n "$LAN_IF" ] && info "single-NIC mode: HV_LAN_IF ($LAN_IF) is ignored"
    LAN_IF=""
else
    [ -n "$LAN_IF" ] \
        || die "HV_LAN_IF is not set: create .env (cp .env.example .env) and set HV_LAN_IF first (or set HV_SINGLE_NIC=1 for a single-NIC host)"
    case "$LAN_IF" in
        *[!A-Za-z0-9_.:@+-]*) die "invalid HV_LAN_IF: $LAN_IF" ;;
    esac
    [ "${#LAN_IF}" -le 15 ] || die "invalid HV_LAN_IF (longer than 15 characters): $LAN_IF"
    # A dot in the name (VLAN) would split the dotted key; the slash form works
    # for every name.
    if [ "${LAN_IF#*.}" != "$LAN_IF" ]; then
        LAN_IPV6_KEY="net/ipv6/conf/$LAN_IF/disable_ipv6"
    else
        LAN_IPV6_KEY="net.ipv6.conf.${LAN_IF}.disable_ipv6"
    fi
fi

if [ "$SINGLE_NIC" = "0" ]; then
cat >"$SYSCTL_FILE" <<EOF
# Dropjak: the VM forwards the clients' traffic as a gateway.
# The actual permission is granted by the nftables allowed_v4 set.
net.ipv4.ip_forward = 1
# The input port proxy DNATs to 127.0.0.1 for targets listening only there
# (for example a Docker port published on 127.0.0.1). Packets arriving from
# outside with a 127/8 destination/source are dropped by the nft loopback_guard
# chain.
net.ipv4.conf.all.route_localnet = 1
# IPv6 is always dropped; no IPv6 on the client LAN interface (no opt-out).
$LAN_IPV6_KEY = 1
EOF
else
cat >"$SYSCTL_FILE" <<EOF
# Dropjak: the VM forwards the clients' traffic as a gateway.
# The actual permission is granted by the nftables allowed_v4 set.
net.ipv4.ip_forward = 1
# The input port proxy DNATs to 127.0.0.1 for targets listening only there
# (for example a Docker port published on 127.0.0.1). Packets arriving from
# outside with a 127/8 destination/source are dropped by the nft loopback_guard
# chain.
net.ipv4.conf.all.route_localnet = 1
# Single-NIC mode: there is no separate client LAN interface to disable IPv6
# on; the firewall drops IPv6.
EOF
fi
chmod 0644 "$SYSCTL_FILE"

if command -v sysctl >/dev/null 2>&1; then
    sysctl -q -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    sysctl -q -w net.ipv4.conf.all.route_localnet=1 >/dev/null 2>&1 || true
else
    echo 1 >/proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    echo 1 >/proc/sys/net/ipv4/conf/all/route_localnet 2>/dev/null || true
fi
# Directly through /proc: it takes any interface name. A missing interface
# (VLAN or bridge created later) gets it from systemd-sysctl when it appears.
# Single-NIC mode has no separate client LAN interface.
if [ "$SINGLE_NIC" = "0" ]; then
    if [ -w "/proc/sys/net/ipv6/conf/$LAN_IF/disable_ipv6" ]; then
        echo 1 >"/proc/sys/net/ipv6/conf/$LAN_IF/disable_ipv6" 2>/dev/null \
            || info "WARNING: cannot disable IPv6 on $LAN_IF right now; it will be after a reboot."
    else
        info "WARNING: $LAN_IF has no IPv6 settings right now (missing interface or IPv6 off); the sysctl file applies when it appears."
    fi
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
    systemctl enable dropjak-boot.service >/dev/null
    info "Docker is already running: the boot table is not loaded now, so that traffic is not interrupted."
    info "it will take effect before Docker on the next reboot."
else
    info "loading the early boot protection: forwarding is blocked and host SSH (TCP 22) is closed."
    "$NFT_BIN" -c -f "$BOOT_NFT" || die "invalid boot rule file"
    systemctl enable --now dropjak-boot.service
    systemctl is-active --quiet dropjak-boot.service \
        || die "dropjak-boot.service did not start"
    info "early forward blocking is active."
    # The boot table drops every inbound TCP 22, including the SSH session that
    # started this script. Keep that one source address reachable so the
    # installation can continue over SSH; the container deletes the boot table
    # as soon as its own rules are loaded.
    # IPv6 is always dropped, so an IPv6 session gets no exception.
    ssh_source=${SSH_CONNECTION%% *}
    if [ -n "$ssh_source" ]; then
        case "$ssh_source" in
            *:*)
                info "WARNING: this SSH session uses IPv6 ($ssh_source), which the firewall always drops; reconnect over IPv4."
                ;;
            *)
                "$NFT_BIN" insert rule inet hatarvedelem_boot input \
                    ip saddr "$ssh_source" tcp dport 22 accept \
                    && info "the current SSH session from $ssh_source stays reachable until the portal loads its rules."
                ;;
        esac
    fi
fi

# --------------------------------------------------------------- warning

for svc in firewalld ufw; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        info "WARNING: $svc is active on the host. Our nftables tables work"
        info "         independently of it, but other Docker containers' forwarded"
        info "         traffic may also be affected by the Dropjak rules. A dedicated gateway is recommended."
    fi
done

info "done."
info "Next step: cp .env.example .env, set the admin password and the interfaces, build the image on the host network"
info "           (DOCKER_BUILDKIT=0 docker build --network host -t dropjak:2 .), then docker compose up -d"
info "The first container start closes host SSH again; the way back is the portal (port 8100) with the admin account from .env."
