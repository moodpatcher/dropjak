#!/usr/bin/env bash
#
# Dropjak — installer
#
# Supported systems: RHEL / AlmaLinux / Rocky Linux / Oracle Linux 8+,
# Fedora, Debian 11+, Ubuntu 20.04+, SLES/openSUSE Leap (Python 3.8+ and
# nftables required). The installer detects the package manager
# (dnf/yum/apt-get/zypper) and offers to install missing packages.
#
# Must be run as root. It only puts the firewall rules into effect at the end,
# after verification. WARNING: the first rule load drops SSH if there is no
# assigned host (input) rule allowing TCP 22 for the source IP yet. The
# existing SSH connection is NOT kept alive by conntrack alone: the template's
# SSH guard also closes a revoked connection. A NEW SSH connection is only
# created if you log in to the portal from the same IP and allow TCP 22 in an
# assigned host rule. Keep the provider console open, or perform the first
# start with HV_SKIP_FIREWALL=1, then restart normally after setting the rule.
#
# Example:
#   sudo ./install.sh --wan-if eth0 --lan-if eth1
#   sudo ./install.sh --wan-if eth0 --lan-if eth1 \
#        --portal-net 192.168.1.50/32 --portal-url http://192.168.50.1
#   sudo ./install.sh --single-nic --wan-if eth0
#
set -euo pipefail

APP_DIR="/opt/hatarvedelem"
STATE_DIR="/var/lib/hatarvedelem"
SERVICE="dropjak"
FIREWALL_SERVICE="${SERVICE}-firewall"
# The system user stays hatarvedelem; the installed paths are unchanged.
SERVICE_USER="hatarvedelem"
NFT_FILE="/etc/nftables/dropjak.nft"
SYSTEMD_DIR="/etc/systemd/system"
SYSTEMD_UNIT="${SYSTEMD_DIR}/${SERVICE}.service"
FIREWALL_UNIT="${SYSTEMD_DIR}/${FIREWALL_SERVICE}.service"
CHECK_UNIT="${SYSTEMD_DIR}/${FIREWALL_SERVICE}-check.service"
CHECK_TIMER="${SYSTEMD_DIR}/${FIREWALL_SERVICE}-check.timer"
SYSCTL_FILE="/etc/sysctl.d/90-dropjak.conf"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Values used for rendering the template. The same defaults as in
# docker/entrypoint.sh and docker-compose.yml.
FWD_MARK="${HV_FWD_MARK:-0x44524a4b}"
DROP_LOG_GROUP="${HV_DROP_LOG_GROUP:-5}"

PORT="80"
LAN_IF=""
WAN_IF=""
LAN_NET=""
GW_IP=""
PORTAL_NET=""
PORTAL_URL=""
SINGLE_NIC=0
# Extra networks the gateway never forwards to (DJ-02), and the interfaces
# of input port proxies with a 127.0.0.1 target (route_localnet, DJ-04).
NO_FORWARD_NETS="${HV_NO_FORWARD_NETS:-}"
ROUTE_LOCALNET_IFS="${HV_ROUTE_LOCALNET_IFS:-}"
ASSUME_YES=0
SKIP_USER=0
SSH_SRC=""
DISABLED_OTHER_FIREWALL=0

PYTHON=""
NFT_BIN=""
NOLOGIN=""
PKG_MANAGER=""
PKG_NFT=""
PKG_PY=""
PKG_IP=""
PKG_USER=""
PKG_CT=""
DISTRO_NAME=""
DISTRO_VERSION=""

die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
note() { printf '\n\033[1m%s\033[0m\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }

# For rendering we accept the same values as the Docker entrypoint,
# so the nftables mark and the drop-log group do not drift.
[[ "$FWD_MARK" =~ ^0x[0-9A-Fa-f]{1,8}$ ]] \
  || die "invalid HV_FWD_MARK (expected a hex number starting with 0x, at most 8 digits): $FWD_MARK"
[[ "$DROP_LOG_GROUP" =~ ^[0-9]+$ ]] \
  && (( 10#$DROP_LOG_GROUP >= 1 && 10#$DROP_LOG_GROUP <= 65535 )) \
  || die "invalid HV_DROP_LOG_GROUP (1-65535): $DROP_LOG_GROUP"

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh [options]

  --wan-if IF          the upstream (internet) interface (required)
  --lan-if IF          the internal (client) interface
  --lan-net CIDR       internal network, e.g. 192.168.50.0/24
  --gateway-ip IP      the gateway address on the internal network, e.g. 192.168.50.1
  --single-nic         single-NIC host: HV_WAN_IF is also the client-facing
                       interface (HV_SINGLE_NIC=1). DHCP, LAN DNS, the HTTP
                       redirect, masquerade, MAC binding and the LAN input
                       block are disabled; --lan-if/--lan-net/--gateway-ip
                       are not used.
  --portal-net CIDR    where the portal is reachable from (default: the SSH source or
                       the LAN network). For a public portal: 0.0.0.0/0.
                       This does not control host SSH: it only opens with an active portal
                       session and a host (input) rule assigned to the user that
                       allows TCP 22.
  --port PORT          the portal port (default: 80)
  --portal-url URL     the canonical portal address (default: http://<gateway-ip>)
  --no-forward-nets L  IPv4 networks never forwarded to, comma separated network
                       addresses (169.254.0.0/16 is always blocked), e.g. the
                       WAN subnet and the provider's private networks
  --route-localnet-ifs L  interfaces of input port proxies whose target listens
                       only on 127.0.0.1 (route_localnet; never set on "all")
  --yes                do not ask; installs missing packages too, and disables
                       firewalld/ufw as well
  --skip-user          do not create a user
  -h, --help           this help

The installer works under dnf/yum/apt-get/zypper. Python 3.8 or newer is
required; on RHEL 8 it automatically offers the python39 package for this.

Environment variables (matching the defaults in docker/entrypoint.sh):
  HV_FWD_MARK          nftables mark for the forward rules (default: 0x44524a4b)
  HV_DROP_LOG_GROUP    NFLOG group for the drop log (default: 5)
  HV_NO_FORWARD_NETS   the default of --no-forward-nets
  HV_ROUTE_LOCALNET_IFS  the default of --route-localnet-ifs
EOF
}

# ------------------------------------------------------------------ arguments

while [[ $# -gt 0 ]]; do
  case "$1" in
    --wan-if)     WAN_IF="${2:-}"; shift 2 ;;
    --lan-if)     LAN_IF="${2:-}"; shift 2 ;;
    --lan-net)    LAN_NET="${2:-}"; shift 2 ;;
    --gateway-ip) GW_IP="${2:-}"; shift 2 ;;
    --portal-net) PORTAL_NET="${2:-}"; shift 2 ;;
    --port)       PORT="${2:-}"; shift 2 ;;
    --portal-url) PORTAL_URL="${2:-}"; shift 2 ;;
    --single-nic) SINGLE_NIC=1; shift ;;
    --no-forward-nets) NO_FORWARD_NETS="${2:-}"; shift 2 ;;
    --route-localnet-ifs) ROUTE_LOCALNET_IFS="${2:-}"; shift 2 ;;
    --yes)        ASSUME_YES=1; shift ;;
    --skip-user)  SKIP_USER=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *)            die "unknown option: $1 (see: --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root: sudo $0"
command -v systemctl >/dev/null 2>&1 || die "systemd is missing"
for f in server.py gateway.py settings_store.py fail2ban.py droplog.py tunnel.py \
         index.html icon.png blocked.png unauthorized.png sus.png ok.png services.json VERSION \
         deploy/dropjak.nft deploy/dropjak.service \
         deploy/dropjak-firewall.service \
         deploy/dropjak-firewall-check.service \
         deploy/dropjak-firewall-check.timer \
         deploy/tunnel-agent/compose.agent.yml \
         deploy/tunnel-agent/Dockerfile deploy/tunnel-agent/agent.py \
         deploy/tunnel-agent/selfinstall.sh \
         deploy/tunnel-agent/check-containment.sh; do
  [[ -f "$SRC_DIR/$f" ]] || die "missing file: $SRC_DIR/$f"
done

# ------------------------------------------------------------------ helper functions

ask_value() {
  local prompt="$1" default="$2" value
  if [[ $ASSUME_YES -eq 1 ]]; then
    printf '%s\n' "$default"
    return
  fi
  read -r -p "$prompt [$default]: " value
  printf '%s\n' "${value:-$default}"
}

confirm() {
  local prompt="$1" default="${2:-n}" answer hint
  if [[ $ASSUME_YES -eq 1 ]]; then
    return 0
  fi
  case "$default" in
    [yY]*) hint="Y/n" ;;
    *) hint="y/N" ;;
  esac
  read -r -p "$prompt [$hint]: " answer
  answer="${answer:-$default}"
  [[ "$answer" =~ ^[yY]([eE][sS])?$ ]]
}

# Escaping a value that goes into a sed substitution pattern. The patterns use
# the `|` delimiter, so the backslash, `|` and `&` characters must be
# escaped.
sed_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//|/\\|}"
  value="${value//&/\\&}"
  printf '%s' "$value"
}

python_ok() {
  "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' \
    >/dev/null 2>&1
}

find_python() {
  local cand path
  for cand in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8; do
    path="$(command -v "$cand" 2>/dev/null || true)"
    [[ -n "$path" ]] || continue
    if python_ok "$path"; then
      printf '%s\n' "$path"
      return 0
    fi
  done
  return 1
}

# ------------------------------------------------------------------ distribution

detect_system() {
  if [[ -r /etc/os-release ]]; then
    DISTRO_NAME="$(
      . /etc/os-release 2>/dev/null || true
      printf '%s' "${PRETTY_NAME:-${ID:-unknown}}"
    )"
    DISTRO_VERSION="$(
      . /etc/os-release 2>/dev/null || true
      printf '%s' "${VERSION_ID:-}"
    )"
  else
    DISTRO_NAME="$(uname -s)"
    DISTRO_VERSION="$(uname -r)"
  fi

  if command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
  elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
  elif command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt-get"
  elif command -v zypper >/dev/null 2>&1; then
    PKG_MANAGER="zypper"
  else
    die "cannot find the package manager (dnf/yum/apt-get/zypper)"
  fi

  case "$PKG_MANAGER" in
    dnf|yum)
      PKG_NFT="nftables"
      PKG_PY="python3"
      PKG_IP="iproute"
      PKG_USER="shadow-utils"
      PKG_CT="conntrack-tools"
      ;;
    apt-get)
      PKG_NFT="nftables"
      PKG_PY="python3"
      PKG_IP="iproute2"
      PKG_USER="passwd"
      PKG_CT="conntrack"
      ;;
    zypper)
      PKG_NFT="nftables"
      PKG_PY="python3"
      PKG_IP="iproute2"
      PKG_USER="shadow"
      PKG_CT="conntrack-tools"
      ;;
  esac
}

pkg_install() {
  local pkgs=("$@")
  [[ ${#pkgs[@]} -gt 0 ]] || return 0

  note "Missing packages: ${pkgs[*]}"
  if ! confirm "Install them using $PKG_MANAGER?"; then
    die "install them manually: $PKG_MANAGER install ${pkgs[*]}, then run again"
  fi

  case "$PKG_MANAGER" in
    dnf|yum)
      "$PKG_MANAGER" install -y "${pkgs[@]}"
      ;;
    apt-get)
      DEBIAN_FRONTEND=noninteractive apt-get update
      DEBIAN_FRONTEND=noninteractive \
        apt-get install -y --no-install-recommends "${pkgs[@]}"
      ;;
    zypper)
      zypper --non-interactive install "${pkgs[@]}"
      ;;
  esac
}

ensure_dependencies() {
  local missing=()

  command -v nft >/dev/null 2>&1 || missing+=("$PKG_NFT")
  command -v ip >/dev/null 2>&1 || missing+=("$PKG_IP")
  command -v useradd >/dev/null 2>&1 || missing+=("$PKG_USER")

  if ! PYTHON="$(find_python)"; then
    missing+=("$PKG_PY")
    # On RHEL 8 python3 is still 3.6; the python39 package provides 3.9.
    if [[ ( "$PKG_MANAGER" == "dnf" || "$PKG_MANAGER" == "yum" ) \
          && "${DISTRO_VERSION%%.*}" == "8" ]]; then
      missing+=("python39")
    fi
  fi

  if ! command -v conntrack >/dev/null 2>&1; then
    if confirm "Install the conntrack tool? (recommended for immediate enforcement of logout)"; then
      missing+=("$PKG_CT")
    fi
  fi

  pkg_install "${missing[@]}"

  command -v nft >/dev/null 2>&1 || die "nft is not available after installation"
  command -v ip >/dev/null 2>&1 || die "the ip command is not available"
  command -v useradd >/dev/null 2>&1 || die "useradd is not available"

  if ! PYTHON="$(find_python)"; then
    die "Python 3.8 or newer is required. Install it manually (e.g. python39 or python3.11), then run again."
  fi

  NFT_BIN="$(command -v nft)"
  NOLOGIN="$(command -v nologin 2>/dev/null || true)"
  [[ -n "$NOLOGIN" ]] || NOLOGIN="/bin/false"
}

detect_system
ensure_dependencies

# ------------------------------------------------------------------ network helpers

# $1: network; $2: "strict" rejects host bits (no silent widening).
canon_v4_net() {
  "$PYTHON" - "$1" "${2:-}" <<'PY'
import ipaddress, sys
try:
    net = ipaddress.ip_network(sys.argv[1], strict=sys.argv[2] == "strict")
except ValueError:
    sys.exit(1)
if net.version != 4:
    sys.exit(1)
print(net)
PY
}

# The extra elements of the no_forward_v4 set (", net, net"): merged, with
# the always-present 169.254.0.0/16 cut out (an interval set rejects
# overlapping elements). Arguments: networks already checked strictly.
no_forward_elements() {
  "$PYTHON" - "$@" <<'PY'
import ipaddress, sys
link_local = ipaddress.ip_network("169.254.0.0/16")
extra = []
nets = [ipaddress.ip_network(item, strict=True) for item in sys.argv[1:]]
for net in ipaddress.collapse_addresses(nets):
    if net.subnet_of(link_local):
        continue
    if link_local.subnet_of(net):
        extra.extend(net.address_exclude(link_local))
    else:
        extra.append(net)
print("".join(f", {net}" for net in sorted(extra)))
PY
}

is_v4() {
  "$PYTHON" - "$1" <<'PY'
import ipaddress, sys
try:
    addr = ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(1)
sys.exit(0 if addr.version == 4 else 1)
PY
}

is_v6() {
  "$PYTHON" - "$1" <<'PY'
import ipaddress, sys
try:
    addr = ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(1)
sys.exit(0 if addr.version == 6 else 1)
PY
}

iface_ok() {
  [[ "$1" =~ ^[A-Za-z0-9_.:-]{1,32}$ ]] && ip link show dev "$1" >/dev/null 2>&1
}

first_v4_cidr() {
  ip -o -4 addr show dev "$1" scope global 2>/dev/null | awk 'NR==1{print $4}'
}

default_wan_if() {
  ip -4 route show default 2>/dev/null | awk '{print $5; exit}'
}

# First private-IPv4 interface other than the given (WAN) interface. Empty
# output means there is no separate client LAN on this host.
private_lan_if() {
  local want="$1" iface cidr
  while read -r iface cidr; do
    [[ -n "$iface" && "$iface" != "$want" ]] || continue
    "$PYTHON" - "$cidr" <<'PY' 2>/dev/null || continue
import ipaddress, sys
sys.exit(0 if ipaddress.ip_interface(sys.argv[1]).ip.is_private else 1)
PY
    printf '%s\n' "$iface"
    return 0
  done < <(ip -o -4 addr show scope global 2>/dev/null | awk '{print $2, $4}')
}

# The SSH source running the installation (if any).
detect_ssh_src() {
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    printf '%s\n' "${SSH_CONNECTION%% *}"
    return
  fi
  local w
  w="$(who am i 2>/dev/null | sed -n 's/.*(\([^)]*\)).*/\1/p' | head -n1)"
  [[ -n "$w" ]] || return 0
  if is_v4 "$w" || is_v6 "$w"; then
    printf '%s\n' "$w"
  else
    getent ahosts "$w" 2>/dev/null | awk 'NR==1{print $1}'
  fi
}

# ------------------------------------------------------------------ values

PORTAL_URL_RE='^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$'
[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) \
  || die "invalid port: $PORT"

SSH_SRC="$(detect_ssh_src || true)"

if [[ -z "$WAN_IF" ]]; then
  WAN_IF="$(default_wan_if || true)"
  if [[ -z "$WAN_IF" ]]; then
    WAN_IF="$(ask_value "No default route. Specify the WAN interface" "eth0")"
  elif [[ $ASSUME_YES -eq 0 ]]; then
    WAN_IF="$(ask_value "WAN interface (upstream)" "$WAN_IF")"
  fi
fi
iface_ok "$WAN_IF" || die "no such WAN interface: $WAN_IF"

# Mode. Given any LAN setting, two-NIC is implied. Otherwise ask, defaulting to
# single-NIC when the host has no private IPv4 interface besides the WAN.
if [[ $SINGLE_NIC -eq 0 && -z "$LAN_IF" && -z "$LAN_NET" && -z "$GW_IP" ]]; then
  single_default=n
  [[ -n "$(private_lan_if "$WAN_IF")" ]] || single_default=y
  if confirm "Single-NIC host (no separate client LAN)?" "$single_default"; then
    SINGLE_NIC=1
  fi
fi

if [[ $SINGLE_NIC -eq 1 ]]; then
  [[ -z "$LAN_IF" && -z "$LAN_NET" && -z "$GW_IP" ]] \
    || die "--single-nic cannot be combined with --lan-if/--lan-net/--gateway-ip"
  LAN_IF=""
  LAN_NET=""
  GW_IP=""
else
  if [[ -z "$LAN_IF" ]]; then
    note "Available IPv4 interfaces:"
    ip -o -4 addr show scope global | awk '{print "  " $2 "  " $4}'
    LAN_IF="$(ask_value "LAN interface (toward clients)" "eth1")"
  fi
  iface_ok "$LAN_IF" || die "no such LAN interface: $LAN_IF"
  [[ "$LAN_IF" != "$WAN_IF" ]] || die "the LAN and WAN interface cannot be the same"

  LAN_CIDR="$(first_v4_cidr "$LAN_IF" || true)"
  [[ -n "$LAN_CIDR" ]] || die "interface $LAN_IF has no IPv4 address; configure one first"

  if [[ -z "$GW_IP" ]]; then
    GW_IP="${LAN_CIDR%%/*}"
    GW_IP="$(ask_value "The gateway address on the LAN" "$GW_IP")"
  fi
  is_v4 "$GW_IP" || die "invalid gateway IP: $GW_IP"

  if [[ -z "$LAN_NET" ]]; then
    LAN_NET="$("$PYTHON" -c \
      'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)' \
      "$LAN_CIDR")"
    LAN_NET="$(ask_value "Internal network" "$LAN_NET")"
  fi
  LAN_NET="$(canon_v4_net "$LAN_NET")" || die "invalid LAN network: $LAN_NET"
  "$PYTHON" - "$GW_IP" "$LAN_NET" <<'PY' \
    || die "the gateway IP ($GW_IP) is not inside the LAN network ($LAN_NET)"
import ipaddress, sys
sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2]) else 1)
PY
fi

if [[ -z "$PORTAL_NET" ]]; then
  # The portal is public by default; narrow it if it should not be
  # reachable from the internet.
  PORTAL_NET="0.0.0.0/0"
  PORTAL_NET="$(ask_value "Portal source network (0.0.0.0/0 = from anywhere)" "$PORTAL_NET")"
fi
PORTAL_NET="$(canon_v4_net "$PORTAL_NET")" \
  || die "invalid portal network: $PORTAL_NET"

if [[ -z "$PORTAL_URL" ]]; then
  if [[ $SINGLE_NIC -eq 1 ]]; then
    PORTAL_HOST="$(first_v4_cidr "$WAN_IF" || true)"
    PORTAL_HOST="${PORTAL_HOST%%/*}"
    [[ -n "$PORTAL_HOST" ]] || PORTAL_HOST="$WAN_IF"
  else
    PORTAL_HOST="$GW_IP"
  fi
  if [[ "$PORT" == "80" ]]; then
    PORTAL_URL="http://${PORTAL_HOST}"
  else
    PORTAL_URL="http://${PORTAL_HOST}:${PORT}"
  fi
fi
[[ "$PORTAL_URL" =~ $PORTAL_URL_RE ]] || die "invalid portal URL: $PORTAL_URL"

NO_FORWARD_LIST=()
for net in ${NO_FORWARD_NETS//,/ }; do
  canon="$(canon_v4_net "$net" strict)" \
    || die "invalid --no-forward-nets entry (an IPv4 network address is required, e.g. 10.0.0.0/8): $net"
  NO_FORWARD_LIST+=("$canon")
done
NO_FORWARD_ELEMENTS=""
if (( ${#NO_FORWARD_LIST[@]} )); then
  NO_FORWARD_ELEMENTS="$(no_forward_elements "${NO_FORWARD_LIST[@]}")"
fi
LOCALNET_LIST=()
for iface in ${ROUTE_LOCALNET_IFS//,/ }; do
  [[ "$iface" =~ ^[A-Za-z0-9_.:@+-]{1,15}$ ]] \
    || die "invalid --route-localnet-ifs entry: $iface"
  LOCALNET_LIST+=("$iface")
done

if [[ -n "$SSH_SRC" ]] && is_v4 "$SSH_SRC"; then
  if ! "$PYTHON" - "$SSH_SRC" "$PORTAL_NET" <<'PY'
import ipaddress, sys
sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2]) else 1)
PY
  then
    warn "the SSH source ($SSH_SRC) is not inside the portal source network."
    warn "Your current connection may survive, but you cannot open a new SSH"
    warn "session from outside the portal. For a public portal: --portal-net 0.0.0.0/0."
    confirm "Continue anyway?" || die "aborted"
  fi
fi

note "Installation plan"
cat <<EOF
  System:              $DISTRO_NAME ($PKG_MANAGER)
  Python:              $PYTHON
  nft:                 $NFT_BIN
EOF
if [[ $SINGLE_NIC -eq 1 ]]; then
  cat <<EOF
  Mode:                single-NIC (WAN is also the client side)
  WAN interface:       $WAN_IF
  Portal source:       $PORTAL_NET
  Portal:              $PORTAL_URL  (port: $PORT)
EOF
else
  cat <<EOF
  Mode:                LAN+WAN
  WAN interface:       $WAN_IF
  LAN interface:       $LAN_IF
  LAN network:         $LAN_NET
  Gateway address:     $GW_IP
  Portal source:       $PORTAL_NET
  Portal:              $PORTAL_URL  (port: $PORT)
EOF
fi
cat <<EOF
  Never forwarded:     169.254.0.0/16${NO_FORWARD_ELEMENTS}
  Program:             $APP_DIR
  State:               $STATE_DIR
EOF

confirm "Continue the installation?" || die "aborted"

# ------------------------------------------------------------------ other firewalls

disable_conflicting_firewalls() {
  if systemctl is-enabled --quiet firewalld 2>/dev/null \
     || systemctl is-active --quiet firewalld 2>/dev/null; then
    warn "firewalld is active or enabled, and may conflict with our own rules."
    if confirm "Disable and mask firewalld?"; then
      systemctl disable --now firewalld >/dev/null 2>&1 || true
      DISABLED_OTHER_FIREWALL=1
    else
      die "disable firewalld first, otherwise the gateway will not work"
    fi
  fi

  if command -v ufw >/dev/null 2>&1 \
     && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    warn "ufw is active, and may conflict with our own rules."
    if confirm "Disable ufw?"; then
      ufw --force disable >/dev/null 2>&1 || true
      DISABLED_OTHER_FIREWALL=1
    else
      die "disable ufw first, otherwise the gateway will not work"
    fi
  fi

  if systemctl is-enabled --quiet netfilter-persistent 2>/dev/null; then
    warn "netfilter-persistent (iptables-persistent) is enabled."
    warn "iptables rules restored at boot may conflict with the gateway."
    if confirm "Disable the netfilter-persistent service?"; then
      systemctl disable --now netfilter-persistent >/dev/null 2>&1 || true
      DISABLED_OTHER_FIREWALL=1
    else
      die "disable netfilter-persistent first"
    fi
  fi

  local unit
  for unit in iptables ip6tables; do
    if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
      warn "$unit.service is enabled, and may load iptables rules at boot."
      if confirm "Disable $unit.service?"; then
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
        DISABLED_OTHER_FIREWALL=1
      else
        die "disable $unit.service first"
      fi
    fi
  done

  if systemctl is-enabled --quiet nftables 2>/dev/null \
     || systemctl is-active --quiet nftables 2>/dev/null; then
    warn "nftables.service is active or enabled."
    warn "Our own table works alongside it, but the forward rules in it"
    warn "may conflict. Check: nft list ruleset"
    warn "Our own rules are in dropjak-firewall.service."
  fi
}

disable_conflicting_firewalls

# ------------------------------------------------------------------ files, user

note "Installing the program"
install -d -m 0755 "$APP_DIR"
install -m 0644 "$SRC_DIR/server.py" "$SRC_DIR/gateway.py" \
  "$SRC_DIR/settings_store.py" "$SRC_DIR/fail2ban.py" "$SRC_DIR/droplog.py" \
  "$SRC_DIR/tunnel.py" \
  "$SRC_DIR/index.html" "$SRC_DIR/icon.png" "$SRC_DIR/blocked.png" \
  "$SRC_DIR/unauthorized.png" "$SRC_DIR/sus.png" "$SRC_DIR/ok.png" \
  "$SRC_DIR/services.json" "$SRC_DIR/VERSION" "$APP_DIR/"
# The uninstaller and the updater are shell scripts, so they need the
# executable bit.
install -m 0755 "$SRC_DIR/uninstall.sh" "$APP_DIR/"
install -m 0755 "$SRC_DIR/update.sh" "$APP_DIR/"
if [[ -f "$SRC_DIR/README.md" ]]; then
  install -m 0644 "$SRC_DIR/README.md" "$APP_DIR/"
fi
# The template is placed here as a reference target, matching the Docker layout; the native
# firewall uses the rendered copy at /etc/nftables/dropjak.nft.
install -d -m 0755 "$APP_DIR/deploy"
install -m 0644 "$SRC_DIR/deploy/dropjak.nft" "$APP_DIR/deploy/"
# Source of the downloadable agent package (the native installation provides the same).
install -d -m 0755 "$APP_DIR/tunnel-agent"
install -m 0644 "$SRC_DIR/deploy/tunnel-agent/Dockerfile" \
  "$SRC_DIR/deploy/tunnel-agent/compose.agent.yml" \
  "$SRC_DIR/deploy/tunnel-agent/selfinstall.sh" "$APP_DIR/tunnel-agent/"
install -m 0755 "$SRC_DIR/deploy/tunnel-agent/agent.py" \
  "$SRC_DIR/deploy/tunnel-agent/check-containment.sh" "$APP_DIR/tunnel-agent/"

if ! getent group "$SERVICE_USER" >/dev/null; then
  groupadd --system "$SERVICE_USER"
fi
if ! getent passwd "$SERVICE_USER" >/dev/null; then
  useradd --system --home-dir "$STATE_DIR" --shell "$NOLOGIN" \
    --gid "$SERVICE_USER" "$SERVICE_USER"
fi
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR"

# ------------------------------------------------------------------ nftables

note "Preparing the firewall rules"
TMP_NFT="$(mktemp)"
TMP_FW=""
TMP_UNIT=""
cleanup() {
  rm -f "$TMP_NFT" "$TMP_FW" "$TMP_UNIT"
}
trap cleanup EXIT

# CLIENT_IFS: the interfaces grants may arrive on (DJ-17).
if [[ $SINGLE_NIC -eq 1 ]]; then
  LAN_PREFIX="# "
  CLIENT_IFS="\"$WAN_IF\""
else
  LAN_PREFIX=""
  CLIENT_IFS="\"$LAN_IF\", \"$WAN_IF\""
fi
sed \
  -e "s|__LANONLY__|$LAN_PREFIX|g" \
  -e "s|__CLIENT_IFS__|$(sed_escape "$CLIENT_IFS")|g" \
  -e "s|__LAN_IF__|$(sed_escape "$LAN_IF")|g" \
  -e "s|__WAN_IF__|$(sed_escape "$WAN_IF")|g" \
  -e "s|__LAN_NET__|$(sed_escape "$LAN_NET")|g" \
  -e "s|__PORTAL_NET__|$(sed_escape "$PORTAL_NET")|g" \
  -e "s|__PORT__|$(sed_escape "$PORT")|g" \
  -e "s|__FWD_MARK__|$(sed_escape "$FWD_MARK")|g" \
  -e "s|__DROP_LOG_GROUP__|$(sed_escape "$DROP_LOG_GROUP")|g" \
  -e "s|__PROXY__|# |g" \
  -e "s|__NO_FORWARD_NETS__|$(sed_escape "$NO_FORWARD_ELEMENTS")|g" \
  "$SRC_DIR/deploy/dropjak.nft" > "$TMP_NFT"

if grep -qE '__[A-Z0-9_]+__' "$TMP_NFT"; then
  die "an unfilled placeholder remained in the generated nftables rules"
fi
# The 3.14.0 interval flags cannot be added in place to an existing set, and the
# referenced set cannot be deleted. Therefore, with an old table, we rebuild the table
# under the early boot protection; this must be decided BEFORE the check,
# because `nft -c` would fail with the old sets. Deletion happens after
# confirmation, and we check once more afterwards.
recreate_table=0
if "$NFT_BIN" list set inet hatarvedelem allowed_tcp >/dev/null 2>&1 \
        && ! "$NFT_BIN" list set inet hatarvedelem allowed_tcp \
            2>/dev/null | grep -q 'flags interval'; then
  recreate_table=1
else
  "$NFT_BIN" -c -f "$TMP_NFT" || die "the generated rules are not valid"
fi

install -d -m 0755 /etc/nftables
install -m 0600 "$TMP_NFT" "$NFT_FILE"

# A distribution nftables config that starts with "flush ruleset" deletes the
# Dropjak table whenever nftables.service is restarted or reloaded.
# dropjak-firewall.service follows those (PartOf=/ReloadPropagatedFrom=), but
# until it has run, nothing filters.
for distro_conf in /etc/nftables.conf /etc/sysconfig/nftables.conf; do
  if [[ -r "$distro_conf" ]] && grep -Eq '^[[:space:]]*flush[[:space:]]+ruleset' "$distro_conf"; then
    warn "$distro_conf contains 'flush ruleset': restarting nftables.service briefly removes the Dropjak rules."
    warn "Prefer 'destroy table'/'flush table' for the distribution's own tables there."
  fi
done

note "Enabling IP forwarding and reverse-path filtering"
# IPv6 is always dropped by the firewall. In two-NIC mode the client LAN must
# have no other IPv6 router (a rogue router advertisement would give the
# clients a path around the gateway), so IPv6 is always off on the LAN
# interface; there is no opt-out. A dot in the name (VLAN) would split the
# dotted key, so the slash form is used then.
# The sysctl key of an IPv4 interface setting (slash form for a VLAN name).
ipv4_conf_key() {
  if [[ "$1" == *.* ]]; then
    printf 'net/ipv4/conf/%s/%s' "$1" "$2"
  else
    printf 'net.ipv4.conf.%s.%s' "$1" "$2"
  fi
}
# Strict reverse-path filtering on the client-facing interfaces (DJ-17).
if [[ $SINGLE_NIC -eq 1 ]]; then
  RP_FILTER_IFS=("$WAN_IF")
else
  RP_FILTER_IFS=("$LAN_IF" "$WAN_IF")
fi
# Migration: an older docker/setup-host.sh run wrote route_localnet on "all"
# into the same file. It is never set there any more (DJ-04).
OLD_ALL_LOCALNET=0
if [[ -r "$SYSCTL_FILE" ]] && grep -Eq '^[[:space:]]*net[./]ipv4[./]conf[./]all[./]route_localnet[[:space:]]*=[[:space:]]*1' "$SYSCTL_FILE"; then
  OLD_ALL_LOCALNET=1
fi
RP_FILTER_LINES=""
for iface in "${RP_FILTER_IFS[@]}"; do
  RP_FILTER_LINES+="$(ipv4_conf_key "$iface" rp_filter) = 1"$'\n'
done
LOCALNET_LINES=""
for iface in "${LOCALNET_LIST[@]}"; do
  LOCALNET_LINES+="$(ipv4_conf_key "$iface" route_localnet) = 1"$'\n'
done
if [[ $SINGLE_NIC -eq 0 ]]; then
  if [[ "$LAN_IF" == *.* ]]; then
    LAN_IPV6_KEY="net/ipv6/conf/${LAN_IF}/disable_ipv6"
  else
    LAN_IPV6_KEY="net.ipv6.conf.${LAN_IF}.disable_ipv6"
  fi
  IPV6_LINES="# IPv6 is always dropped; no IPv6 on the client LAN interface (no opt-out).
$LAN_IPV6_KEY = 1"
else
  IPV6_LINES="# Single-NIC mode: there is no separate client LAN interface; IPv6 is
# dropped by the firewall (which has no IPv6 forwarding path)."
fi
cat > "$SYSCTL_FILE" <<EOF
# Dropjak: the machine forwards traffic as a router.
net.ipv4.ip_forward = 1
# Strict reverse-path filtering on the client-facing interfaces.
${RP_FILTER_LINES}# Input port proxies with a 127.0.0.1 target: route_localnet only on their
# interfaces (--route-localnet-ifs), never on "all".
${LOCALNET_LINES}${IPV6_LINES}
EOF
if command -v sysctl >/dev/null 2>&1; then
  sysctl -q -w net.ipv4.ip_forward=1 >/dev/null
else
  printf '1\n' > /proc/sys/net/ipv4/ip_forward
fi
for iface in "${RP_FILTER_IFS[@]}"; do
  printf '1\n' > "/proc/sys/net/ipv4/conf/${iface}/rp_filter" 2>/dev/null \
    || warn "cannot set rp_filter on ${iface} right now; it will be after a reboot."
done
for iface in "${LOCALNET_LIST[@]}"; do
  printf '1\n' > "/proc/sys/net/ipv4/conf/${iface}/route_localnet" 2>/dev/null \
    || warn "cannot set route_localnet on ${iface} right now; it will be after a reboot."
done
if (( OLD_ALL_LOCALNET )); then
  printf '0\n' > /proc/sys/net/ipv4/conf/all/route_localnet 2>/dev/null || true
  warn "route_localnet is no longer set on \"all\"; list the interfaces of input port proxies with a 127.0.0.1 target in --route-localnet-ifs."
fi
if [[ $SINGLE_NIC -eq 0 && -w "/proc/sys/net/ipv6/conf/${LAN_IF}/disable_ipv6" ]]; then
  printf '1\n' > "/proc/sys/net/ipv6/conf/${LAN_IF}/disable_ipv6" \
    || warn "cannot disable IPv6 on ${LAN_IF} right now; it will be after a reboot."
fi

note "Loading the firewall"
warn "After this, host SSH only opens if you log in to the portal from the same IP,"
warn "and explicitly allow TCP port 22 in a host rule assigned to the user."
warn "WARNING: the first load drops the current SSH connection,"
warn "if there is no such assigned rule for the source IP yet. conntrack"
warn "alone does not keep it alive. Keep the provider console"
warn "access, or first start with HV_SKIP_FIREWALL=1, set"
warn "the rule, and then load the firewall."
confirm "Load the firewall rules?" || die "aborted"
if (( recreate_table )); then
  warn "Due to the old nft set flags, the Dropjak table is rebuilt."
  # Between deletion and the new load, the host may only be under the early boot
  # protection (fail-closed).
  if ! "$NFT_BIN" list table inet hatarvedelem_boot >/dev/null 2>&1; then
    "$NFT_BIN" -f "$SRC_DIR/deploy/dropjak-boot.nft" \
      || die "loading the early boot protection failed"
  fi
  "$NFT_BIN" delete table inet hatarvedelem \
    || die "deleting the old nft table failed; the early boot protection remained in effect"
  if ! "$NFT_BIN" -c -f "$TMP_NFT"; then
    die "the generated rules are not valid; the old table has already been deleted, the early boot protection remained in effect (fail-closed)"
  fi
fi
# The file is idempotent: running it multiple times does not duplicate the rules, and
# the set elements of logged-in clients are preserved (after the one-time table
# rebuild for switching to the interval flag).
if ! "$NFT_BIN" -f "$NFT_FILE"; then
  if (( recreate_table )); then
    die "loading the rules failed; the early boot protection remained in effect (fail-closed)"
  fi
  die "loading the rules failed"
fi
if "$NFT_BIN" list table inet hatarvedelem_boot >/dev/null 2>&1; then
  "$NFT_BIN" delete table inet hatarvedelem_boot \
    || die "removing the early boot protection failed"
fi
for hv_set in allowed_v4 allowed_tcp allowed_udp allowed_icmp; do
  "$NFT_BIN" list set inet hatarvedelem "$hv_set" >/dev/null \
    || die "the firewall was loaded, but set $hv_set cannot be found"
done

# ------------------------------------------------------------------ systemd

note "Installing services"

# Upgrading from the previous unit names: a leftover hatarvedelem.service or
# hatarvedelem-firewall.service would start alongside the new units.
for legacy in hatarvedelem-firewall hatarvedelem; do
  if [ -e "${SYSTEMD_DIR}/${legacy}.service" ]; then
    systemctl disable --now "$legacy" >/dev/null 2>&1 || true
    rm -f "${SYSTEMD_DIR}/${legacy}.service"
    warn "removed the legacy ${legacy}.service unit"
  fi
done

TMP_FW="$(mktemp)"
sed -e "s|__NFT_BIN__|$NFT_BIN|g" \
  "$SRC_DIR/deploy/dropjak-firewall.service" > "$TMP_FW"
install -m 0644 "$TMP_FW" "$FIREWALL_UNIT"
# Native watchdog (DJ-04): every 10 s, reload the rules if the table is gone.
sed -e "s|__NFT_BIN__|$NFT_BIN|g" \
  "$SRC_DIR/deploy/dropjak-firewall-check.service" > "$TMP_FW"
install -m 0644 "$TMP_FW" "$CHECK_UNIT"
install -m 0644 "$SRC_DIR/deploy/dropjak-firewall-check.timer" "$CHECK_TIMER"

TMP_UNIT="$(mktemp)"
sed \
  -e "s|__PYTHON__|$PYTHON|g" \
  -e "s|__NFT_BIN__|$NFT_BIN|g" \
  -e "s|__PORT__|$PORT|g" \
  -e "s|__PORTAL_URL__|$PORTAL_URL|g" \
  "$SRC_DIR/deploy/dropjak.service" > "$TMP_UNIT"
install -m 0644 "$TMP_UNIT" "$SYSTEMD_UNIT"

if grep -qE '__[A-Z0-9_]+__' "$SYSTEMD_UNIT" "$FIREWALL_UNIT" "$CHECK_UNIT"; then
  die "an unfilled placeholder remained in the systemd units"
fi

# The mark, NFLOG group, interfaces, LAN network and mode of the rendered
# rules must match the values used by the portal and the drop-log listener.
# The unit template does not contain these, so we pass them as a drop-in.
# Without HV_LAN_IF/HV_LAN_NET (two-NIC) the portal records no client MAC,
# while the rules drop every LAN grant without one. In single-NIC mode the
# empty LAN values are expected and the portal uses IP-based grants only.
ENV_DROPIN_DIR="${SYSTEMD_DIR}/${SERVICE}.service.d"
install -d -m 0755 "$ENV_DROPIN_DIR"
cat > "$ENV_DROPIN_DIR/10-dropjak-env.conf" <<EOF
[Service]
Environment=HV_SINGLE_NIC=$SINGLE_NIC
Environment=HV_FWD_MARK=$FWD_MARK
Environment=HV_DROP_LOG_GROUP=$DROP_LOG_GROUP
Environment=HV_LAN_IF=$LAN_IF
Environment=HV_WAN_IF=$WAN_IF
Environment=HV_LAN_NET=$LAN_NET
Environment=HV_PORTAL_NET=$PORTAL_NET
EOF
chmod 0644 "$ENV_DROPIN_DIR/10-dropjak-env.conf"

systemctl daemon-reload
systemctl enable "$FIREWALL_SERVICE" >/dev/null
systemctl enable "$SERVICE" >/dev/null

if ! systemctl restart "$FIREWALL_SERVICE"; then
  warn "the firewall service did not start; log:"
  journalctl -u "$FIREWALL_SERVICE" -n 30 --no-pager || true
  die "installation failed"
fi
for hv_set in allowed_v4 allowed_tcp allowed_udp allowed_icmp; do
  "$NFT_BIN" list set inet hatarvedelem "$hv_set" >/dev/null \
    || die "set $hv_set cannot be found after the service started"
done
systemctl enable --now "${FIREWALL_SERVICE}-check.timer" >/dev/null \
  || warn "the firewall check timer could not be enabled"

if ! systemctl restart "$SERVICE"; then
  warn "the service did not start; log:"
  journalctl -u "$SERVICE" -n 30 --no-pager || true
  die "installation failed"
fi
sleep 1
if ! systemctl is-active --quiet "$SERVICE"; then
  warn "the service is not running; log:"
  journalctl -u "$SERVICE" -n 30 --no-pager || true
  die "installation failed"
fi

# ------------------------------------------------------------------ first user

if [[ $SKIP_USER -eq 0 ]]; then
  if ! "$PYTHON" - "$STATE_DIR/users.json" <<'PY' 2>/dev/null
import json, sys
try:
    with open(sys.argv[1]) as fh:
        sys.exit(0 if json.load(fh) else 1)
except Exception:
    sys.exit(1)
PY
  then
    if [[ $ASSUME_YES -eq 1 ]]; then
      warn "I did not create a user (--yes). Later:"
      echo "  HV_USERS=$STATE_DIR/users.json $PYTHON $APP_DIR/server.py user add <name>"
    else
      echo
      ADMIN_NAME="$(ask_value "First user's name" "admin")"
      HV_USERS="$STATE_DIR/users.json" HV_STATE_DIR="$STATE_DIR" \
        "$PYTHON" "$APP_DIR/server.py" user add "$ADMIN_NAME"
      chown "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR/users.json"
      if [[ -f "$STATE_DIR/users.json.lock" ]]; then
        chown "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR/users.json.lock"
      fi
    fi
  fi
fi

if command -v restorecon >/dev/null 2>&1; then
  restorecon -R "$APP_DIR" "$STATE_DIR" >/dev/null 2>&1 || true
  restorecon "$NFT_FILE" "$SYSTEMD_UNIT" "$FIREWALL_UNIT" \
    "$CHECK_UNIT" "$CHECK_TIMER" \
    >/dev/null 2>&1 || true
fi

# ------------------------------------------------------------------ summary

note "Done"
cat <<EOF
  System:            $DISTRO_NAME ($PKG_MANAGER)
  Python:            $PYTHON
  nft:               $NFT_BIN
  Mode:              $(if [[ $SINGLE_NIC -eq 1 ]]; then printf 'single-NIC'; else printf 'LAN+WAN'; fi)
  Portal:            $PORTAL_URL
  Firewall status:   systemctl status $FIREWALL_SERVICE
  Portal status:     systemctl status $SERVICE
  Log:               journalctl -u $SERVICE -f
  Firewall log:      journalctl -u $FIREWALL_SERVICE -f
  Permissions:       $NFT_BIN list set inet hatarvedelem allowed_v4
  User:              HV_USERS=$STATE_DIR/users.json $PYTHON $APP_DIR/server.py user add <name>

EOF
if [[ $SINGLE_NIC -eq 1 ]]; then
  cat <<EOF
  Grants are IP-based only on the public interface; there is no MAC binding.
  Serve the portal over HTTPS (HV_PROXY=1) or set HV_WAN_HTTPS_ONLY=1 before
  exposing it publicly.

EOF
else
  cat <<EOF
  The clients' default gateway: $GW_IP

EOF
fi
cat <<EOF
  HTTPS does not pass before login (we can only direct HTTP to the portal),
  therefore the portal address is: $PORTAL_URL

  Restarting the portal deletes every login (clean start).
  Reloading the firewall (systemctl reload $FIREWALL_SERVICE) preserves the
  logged-in clients.
EOF

if [[ $DISABLED_OTHER_FIREWALL -eq 1 ]]; then
  warn "We also disabled other firewalls. Because of leftover boot-time rules,"
  warn "it is worth rebooting the machine before putting it into production use."
fi
