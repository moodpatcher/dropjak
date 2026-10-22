#!/usr/bin/env bash
#
# Dropjak — telepítő
#
# Támogatott rendszerek: RHEL / AlmaLinux / Rocky Linux / Oracle Linux 8+,
# Fedora, Debian 11+, Ubuntu 20.04+, SLES/openSUSE Leap (Python 3.8+ és
# nftables szükséges). A telepítő felismeri a csomagkezelőt
# (dnf/yum/apt-get/zypper), és felajánlja a hiányzó csomagok telepítését.
#
# rootként futtatandó. A tűzfal-szabályokat csak a végén, ellenőrzés után
# teszi élesbe. FIGYELEM: az első szabálybetöltés megszakítja az SSH-t, ha
# a forrás IP-hez még nincs hozzárendelt, TCP 22-t engedélyező host (input)
# szabály. A meglévő SSH-kapcsolatot a conntrack önmagában NEM tartja
# életben: a sablon SSH-őre a visszavont kapcsolatot is lezárja. ÚJ SSH
# csak akkor jön létre, ha ugyanarról az IP-ről belépsz a portálon, és egy
# hozzárendelt host szabályban engedélyezed a TCP 22-t. Tartsd nyitva a
# szolgáltatói konzolt, vagy az első indítást HV_SKIP_FIREWALL=1 értékkel
# végezd, majd a szabály beállítása után indíts újra normálisan.
#
# Példa:
#   sudo ./install.sh --wan-if eth0 --lan-if eth1
#   sudo ./install.sh --wan-if eth0 --lan-if eth1 \
#        --portal-net 192.168.1.50/32 --portal-url http://192.168.50.1
#
set -euo pipefail

APP_DIR="/opt/hatarvedelem"
STATE_DIR="/var/lib/hatarvedelem"
SERVICE="hatarvedelem"
FIREWALL_SERVICE="${SERVICE}-firewall"
SERVICE_USER="hatarvedelem"
NFT_FILE="/etc/nftables/hatarvedelem.nft"
SYSTEMD_DIR="/etc/systemd/system"
SYSTEMD_UNIT="${SYSTEMD_DIR}/${SERVICE}.service"
FIREWALL_UNIT="${SYSTEMD_DIR}/${FIREWALL_SERVICE}.service"
SYSCTL_FILE="/etc/sysctl.d/90-hatarvedelem.conf"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# A sablon rendereléséhez használt értékek. Ugyanazok az alapértékek, mint a
# docker/entrypoint.sh-ban és a docker-compose.yml-ben.
FWD_MARK="${HV_FWD_MARK:-0x44524a4b}"
DROP_LOG_GROUP="${HV_DROP_LOG_GROUP:-5}"

PORT="80"
LAN_IF=""
WAN_IF=""
LAN_NET=""
GW_IP=""
PORTAL_NET=""
PORTAL_URL=""
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

die()  { printf 'HIBA: %s\n' "$*" >&2; exit 1; }
note() { printf '\n\033[1m%s\033[0m\n' "$*"; }
warn() { printf 'FIGYELEM: %s\n' "$*" >&2; }

# A rendereléshez ugyanazokat az értékeket fogadjuk el, mint a Dockeres
# belépési pont, hogy a nftables mark és a drop-log csoport ne csússzon el.
[[ "$FWD_MARK" =~ ^0x[0-9A-Fa-f]{1,8}$ ]] \
  || die "érvénytelen HV_FWD_MARK (0x kezdetű, legfeljebb 8 jegyű hex szám kell): $FWD_MARK"
[[ "$DROP_LOG_GROUP" =~ ^[0-9]+$ ]] \
  && (( 10#$DROP_LOG_GROUP >= 1 && 10#$DROP_LOG_GROUP <= 65535 )) \
  || die "érvénytelen HV_DROP_LOG_GROUP (1-65535): $DROP_LOG_GROUP"

usage() {
  cat <<'EOF'
Használat: sudo ./install.sh [opciók]

  --wan-if IF          a felfelé (internet) irányú interfész
  --lan-if IF          a belső (kliens) interfész
  --lan-net CIDR       belső hálózat, pl. 192.168.50.0/24
  --gateway-ip IP      a kapu címe a belső hálózaton, pl. 192.168.50.1
  --portal-net CIDR    ahonnan a portál elérhető (alap: az SSH forrása vagy
                       a LAN hálózat). Nyilvános portálhoz: 0.0.0.0/0.
                       A host SSH-t nem ez szabályozza: az csak aktív portál-
                       munkamenettel és a felhasználóhoz rendelt, TCP 22-t
                       engedélyező host (input) szabállyal nyílik meg.
  --port PORT          a portál portja (alap: 80)
  --portal-url URL     a portál kanonikus címe (alap: http://<gateway-ip>)
  --yes                nem kérdez; a hiányzó csomagokat is telepíti, és a
                       firewalld/ufw-t is kikapcsolja
  --skip-user          nem hoz létre felhasználót
  -h, --help           ez a súgó

A telepítő dnf/yum/apt-get/zypper alatt működik. Python 3.8 vagy újabb
szükséges; RHEL 8-on ehhez automatikusan a python39 csomagot ajánlja fel.

Környezeti változók (a docker/entrypoint.sh alapértékeivel egyezően):
  HV_FWD_MARK          a forward szabályok nftables markja (alap: 0x44524a4b)
  HV_DROP_LOG_GROUP    a drop-napló NFLOG csoportja (alap: 5)
EOF
}

# ------------------------------------------------------------------ argumentumok

while [[ $# -gt 0 ]]; do
  case "$1" in
    --wan-if)     WAN_IF="${2:-}"; shift 2 ;;
    --lan-if)     LAN_IF="${2:-}"; shift 2 ;;
    --lan-net)    LAN_NET="${2:-}"; shift 2 ;;
    --gateway-ip) GW_IP="${2:-}"; shift 2 ;;
    --portal-net) PORTAL_NET="${2:-}"; shift 2 ;;
    --port)       PORT="${2:-}"; shift 2 ;;
    --portal-url) PORTAL_URL="${2:-}"; shift 2 ;;
    --yes)        ASSUME_YES=1; shift ;;
    --skip-user)  SKIP_USER=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *)            die "ismeretlen opció: $1 (lásd: --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "rootként futtasd: sudo $0"
command -v systemctl >/dev/null 2>&1 || die "hiányzik a systemd"
for f in server.py gateway.py settings_store.py fail2ban.py droplog.py \
         index.html icon.png blocked.png unauthorized.png sus.png services.json VERSION \
         deploy/hatarvedelem.nft deploy/hatarvedelem.service \
         deploy/hatarvedelem-firewall.service; do
  [[ -f "$SRC_DIR/$f" ]] || die "hiányzó fájl: $SRC_DIR/$f"
done

# ------------------------------------------------------------------ segédfüggvények

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
  local prompt="$1" answer
  if [[ $ASSUME_YES -eq 1 ]]; then
    return 0
  fi
  read -r -p "$prompt [i/N]: " answer
  [[ "$answer" =~ ^[iI]([gG][eE][nN])?$ ]]
}

# sed helyettesítési mintájába kerülő érték escape-elése. A minták `|`
# határolót használnak, ezért a backslash, a `|` és a `&` karaktereket kell
# escape-elni.
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

# ------------------------------------------------------------------ disztribúció

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
    die "nem találom a csomagkezelőt (dnf/yum/apt-get/zypper)"
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

  note "Hiányzó csomagok: ${pkgs[*]}"
  if ! confirm "Telepítsem őket a(z) $PKG_MANAGER segítségével?"; then
    die "telepítsd kézzel: $PKG_MANAGER install ${pkgs[*]}, majd futtasd újra"
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
    # RHEL 8-on a python3 még 3.6; a python39 csomag ad 3.9-et.
    if [[ ( "$PKG_MANAGER" == "dnf" || "$PKG_MANAGER" == "yum" ) \
          && "${DISTRO_VERSION%%.*}" == "8" ]]; then
      missing+=("python39")
    fi
  fi

  if ! command -v conntrack >/dev/null 2>&1; then
    if confirm "Telepítsem a conntrack eszközt? (a kilépés azonnali érvényesítéséhez ajánlott)"; then
      missing+=("$PKG_CT")
    fi
  fi

  pkg_install "${missing[@]}"

  command -v nft >/dev/null 2>&1 || die "az nft nem érhető el a telepítés után"
  command -v ip >/dev/null 2>&1 || die "az ip parancs nem érhető el"
  command -v useradd >/dev/null 2>&1 || die "a useradd nem érhető el"

  if ! PYTHON="$(find_python)"; then
    die "Python 3.8 vagy újabb szükséges. Telepítsd kézzel (pl. python39 vagy python3.11), majd futtasd újra."
  fi

  NFT_BIN="$(command -v nft)"
  NOLOGIN="$(command -v nologin 2>/dev/null || true)"
  [[ -n "$NOLOGIN" ]] || NOLOGIN="/bin/false"
}

detect_system
ensure_dependencies

# ------------------------------------------------------------------ hálózati segédek

canon_v4_net() {
  "$PYTHON" - "$1" <<'PY'
import ipaddress, sys
net = ipaddress.ip_network(sys.argv[1], strict=False)
if net.version != 4:
    sys.exit(1)
print(net)
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

# A telepítést futtató SSH-forrás (ha van).
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

# ------------------------------------------------------------------ értékek

PORTAL_URL_RE='^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$'
[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) \
  || die "érvénytelen port: $PORT"

SSH_SRC="$(detect_ssh_src || true)"

if [[ -z "$WAN_IF" ]]; then
  WAN_IF="$(default_wan_if || true)"
  if [[ -z "$WAN_IF" ]]; then
    WAN_IF="$(ask_value "Nincs alapértelmezett útvonal. Add meg a WAN interfészt" "eth0")"
  elif [[ $ASSUME_YES -eq 0 ]]; then
    WAN_IF="$(ask_value "WAN interfész (felfelé)" "$WAN_IF")"
  fi
fi
iface_ok "$WAN_IF" || die "nincs ilyen WAN interfész: $WAN_IF"

if [[ -z "$LAN_IF" ]]; then
  note "Elérhető IPv4-es interfészek:"
  ip -o -4 addr show scope global | awk '{print "  " $2 "  " $4}'
  LAN_IF="$(ask_value "LAN interfész (a kliensek felé)" "eth1")"
fi
iface_ok "$LAN_IF" || die "nincs ilyen LAN interfész: $LAN_IF"
[[ "$LAN_IF" != "$WAN_IF" ]] || die "a LAN és a WAN interfész nem lehet ugyanaz"

LAN_CIDR="$(first_v4_cidr "$LAN_IF" || true)"
[[ -n "$LAN_CIDR" ]] || die "a(z) $LAN_IF interfészen nincs IPv4-cím; állítsd be előbb"

if [[ -z "$GW_IP" ]]; then
  GW_IP="${LAN_CIDR%%/*}"
  GW_IP="$(ask_value "A kapu címe a LAN-on" "$GW_IP")"
fi
is_v4 "$GW_IP" || die "érvénytelen gateway IP: $GW_IP"

if [[ -z "$LAN_NET" ]]; then
  LAN_NET="$("$PYTHON" -c \
    'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)' \
    "$LAN_CIDR")"
  LAN_NET="$(ask_value "Belső hálózat" "$LAN_NET")"
fi
LAN_NET="$(canon_v4_net "$LAN_NET")" || die "érvénytelen LAN hálózat: $LAN_NET"
"$PYTHON" - "$GW_IP" "$LAN_NET" <<'PY' \
  || die "a gateway IP ($GW_IP) nincs benne a LAN hálózatban ($LAN_NET)"
import ipaddress, sys
sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2]) else 1)
PY

if [[ -z "$PORTAL_NET" ]]; then
  if [[ -n "$SSH_SRC" ]] && is_v4 "$SSH_SRC"; then
    PORTAL_NET="$SSH_SRC/32"
  else
    PORTAL_NET="$LAN_NET"
  fi
  PORTAL_NET="$(ask_value "Portál forrás-hálózata (0.0.0.0/0 = bárhonnan)" "$PORTAL_NET")"
fi
PORTAL_NET="$(canon_v4_net "$PORTAL_NET")" \
  || die "érvénytelen portál hálózat: $PORTAL_NET"

if [[ -z "$PORTAL_URL" ]]; then
  if [[ "$PORT" == "80" ]]; then
    PORTAL_URL="http://${GW_IP}"
  else
    PORTAL_URL="http://${GW_IP}:${PORT}"
  fi
fi
[[ "$PORTAL_URL" =~ $PORTAL_URL_RE ]] || die "érvénytelen portál URL: $PORTAL_URL"

if [[ -n "$SSH_SRC" ]] && is_v4 "$SSH_SRC"; then
  if ! "$PYTHON" - "$SSH_SRC" "$PORTAL_NET" <<'PY'
import ipaddress, sys
sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2]) else 1)
PY
  then
    warn "az SSH forrása ($SSH_SRC) nincs a portál forrás-hálózatában."
    warn "A mostani kapcsolatod túlélheti, de a portálon kívülről nem tudsz"
    warn "új SSH-munkamenetet nyitni. Nyilvános portálhoz: --portal-net 0.0.0.0/0."
    confirm "Mégis folytatod?" || die "megszakítva"
  fi
fi

note "Telepítési terv"
cat <<EOF
  Rendszer:            $DISTRO_NAME ($PKG_MANAGER)
  Python:              $PYTHON
  nft:                 $NFT_BIN
  WAN interfész:       $WAN_IF
  LAN interfész:       $LAN_IF
  LAN hálózat:         $LAN_NET
  Kapu címe:           $GW_IP
  Portál forrás:       $PORTAL_NET  Portál:              $PORTAL_URL  (port: $PORT)
  Program:             $APP_DIR
  Állapot:             $STATE_DIR
EOF

confirm "Folytatod a telepítést?" || die "megszakítva"

# ------------------------------------------------------------------ más tűzfalak

disable_conflicting_firewalls() {
  if systemctl is-enabled --quiet firewalld 2>/dev/null \
     || systemctl is-active --quiet firewalld 2>/dev/null; then
    warn "A firewalld aktív vagy engedélyezett, és ütközhet a saját szabályainkkal."
    if confirm "Kikapcsoljam és tiltsam le a firewalld-t?"; then
      systemctl disable --now firewalld >/dev/null 2>&1 || true
      DISABLED_OTHER_FIREWALL=1
    else
      die "a firewalld-t előbb kapcsold ki, különben a kapu nem fog működni"
    fi
  fi

  if command -v ufw >/dev/null 2>&1 \
     && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    warn "A ufw aktív, és ütközhet a saját szabályainkkal."
    if confirm "Kikapcsoljam a ufw-t?"; then
      ufw --force disable >/dev/null 2>&1 || true
      DISABLED_OTHER_FIREWALL=1
    else
      die "a ufw-t előbb kapcsold ki, különben a kapu nem fog működni"
    fi
  fi

  if systemctl is-enabled --quiet netfilter-persistent 2>/dev/null; then
    warn "A netfilter-persistent (iptables-persistent) engedélyezett."
    warn "A bootkor visszatöltött iptables-szabályok ütközhetnek a kapuval."
    if confirm "Kikapcsoljam a netfilter-persistent szolgáltatást?"; then
      systemctl disable --now netfilter-persistent >/dev/null 2>&1 || true
      DISABLED_OTHER_FIREWALL=1
    else
      die "a netfilter-persistent-et előbb kapcsold ki"
    fi
  fi

  local unit
  for unit in iptables ip6tables; do
    if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
      warn "A(z) $unit.service engedélyezett, bootkor iptables-szabályokat tölthet be."
      if confirm "Kikapcsoljam a(z) $unit.service-t?"; then
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
        DISABLED_OTHER_FIREWALL=1
      else
        die "a(z) $unit.service-t előbb kapcsold ki"
      fi
    fi
  done

  if systemctl is-enabled --quiet nftables 2>/dev/null \
     || systemctl is-active --quiet nftables 2>/dev/null; then
    warn "Az nftables.service aktív vagy engedélyezett."
    warn "A saját táblánk mellette is működik, de a benne lévő forward-"
    warn "szabályok ütközhetnek. Ellenőrizd: nft list ruleset"
    warn "A saját szabályaink a hatarvedelem-firewall.service-ben vannak."
  fi
}

disable_conflicting_firewalls

# ------------------------------------------------------------------ fájlok, user

note "Program telepítése"
install -d -m 0755 "$APP_DIR"
install -m 0644 "$SRC_DIR/server.py" "$SRC_DIR/gateway.py" \
  "$SRC_DIR/settings_store.py" "$SRC_DIR/fail2ban.py" "$SRC_DIR/droplog.py" \
  "$SRC_DIR/index.html" "$SRC_DIR/icon.png" "$SRC_DIR/blocked.png" \
  "$SRC_DIR/unauthorized.png" "$SRC_DIR/sus.png" \
  "$SRC_DIR/services.json" "$SRC_DIR/VERSION" "$APP_DIR/"
if [[ -f "$SRC_DIR/README.md" ]]; then
  install -m 0644 "$SRC_DIR/README.md" "$APP_DIR/"
fi
# A sablon a Docker-layouttal egyezően referencia-célból kerül ide; a natív
# tűzfal a /etc/nftables/hatarvedelem.nft renderelt példányát használja.
install -d -m 0755 "$APP_DIR/deploy"
install -m 0644 "$SRC_DIR/deploy/hatarvedelem.nft" "$APP_DIR/deploy/"

if ! getent group "$SERVICE_USER" >/dev/null; then
  groupadd --system "$SERVICE_USER"
fi
if ! getent passwd "$SERVICE_USER" >/dev/null; then
  useradd --system --home-dir "$STATE_DIR" --shell "$NOLOGIN" \
    --gid "$SERVICE_USER" "$SERVICE_USER"
fi
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR"

# ------------------------------------------------------------------ nftables

note "Tűzfalszabályok előkészítése"
TMP_NFT="$(mktemp)"
TMP_FW=""
TMP_UNIT=""
cleanup() {
  rm -f "$TMP_NFT" "$TMP_FW" "$TMP_UNIT"
}
trap cleanup EXIT

sed \
  -e "s|__LAN_IF__|$(sed_escape "$LAN_IF")|g" \
  -e "s|__WAN_IF__|$(sed_escape "$WAN_IF")|g" \
  -e "s|__LAN_NET__|$(sed_escape "$LAN_NET")|g" \
  -e "s|__PORTAL_NET__|$(sed_escape "$PORTAL_NET")|g" \
  -e "s|__PORT__|$(sed_escape "$PORT")|g" \
  -e "s|__FWD_MARK__|$(sed_escape "$FWD_MARK")|g" \
  -e "s|__DROP_LOG_GROUP__|$(sed_escape "$DROP_LOG_GROUP")|g" \
  -e "s|__PROXY__|# |g" \
  "$SRC_DIR/deploy/hatarvedelem.nft" > "$TMP_NFT"

if grep -qE '__[A-Z0-9_]+__' "$TMP_NFT"; then
  die "kitöltetlen helyőrző maradt a generált nftables-szabályokban"
fi
"$NFT_BIN" -c -f "$TMP_NFT" || die "a generált szabályok nem érvényesek"

install -d -m 0755 /etc/nftables
install -m 0600 "$TMP_NFT" "$NFT_FILE"

note "IP-továbbítás bekapcsolása"
cat > "$SYSCTL_FILE" <<'EOF'
# Dropjak: a gép routerként továbbítja a forgalmat.
net.ipv4.ip_forward = 1
EOF
if command -v sysctl >/dev/null 2>&1; then
  sysctl -q -w net.ipv4.ip_forward=1 >/dev/null
else
  printf '1\n' > /proc/sys/net/ipv4/ip_forward
fi

note "Tűzfal betöltése"
warn "A host SSH ezután csak akkor nyílik meg, ha ugyanarról az IP-ről"
warn "belépsz a portálra, és egy a felhasználóhoz rendelt host szabályban"
warn "kifejezetten engedélyezed a TCP 22-es portot."
warn "FIGYELEM: az első betöltés megszakítja a jelenlegi SSH-kapcsolatot,"
warn "ha a forrás IP-hez még nincs ilyen hozzárendelt szabály. A conntrack"
warn "önmagában nem tartja életben. Őrizd meg a szolgáltatói konzol"
warn "hozzáférését, vagy előbb HV_SKIP_FIREWALL=1 értékkel indíts, állítsd"
warn "be a szabályt, és utána töltsd be a tűzfalat."
confirm "Betöltöm a tűzfalszabályokat?" || die "megszakítva"
# A fájl idempotens: többszöri futtatás nem duplázza a szabályokat, és a
# belépett kliensek halmazelemei megmaradnak.
"$NFT_BIN" -f "$NFT_FILE"
for hv_set in allowed_v4 allowed_tcp allowed_udp allowed_icmp; do
  "$NFT_BIN" list set inet hatarvedelem "$hv_set" >/dev/null \
    || die "a tűzfal betöltődött, de a(z) $hv_set halmaz nem található"
done

# ------------------------------------------------------------------ systemd

note "Szolgáltatások telepítése"
TMP_FW="$(mktemp)"
sed -e "s|__NFT_BIN__|$NFT_BIN|g" \
  "$SRC_DIR/deploy/hatarvedelem-firewall.service" > "$TMP_FW"
install -m 0644 "$TMP_FW" "$FIREWALL_UNIT"

TMP_UNIT="$(mktemp)"
sed \
  -e "s|__PYTHON__|$PYTHON|g" \
  -e "s|__NFT_BIN__|$NFT_BIN|g" \
  -e "s|__PORT__|$PORT|g" \
  -e "s|__PORTAL_URL__|$PORTAL_URL|g" \
  "$SRC_DIR/deploy/hatarvedelem.service" > "$TMP_UNIT"
install -m 0644 "$TMP_UNIT" "$SYSTEMD_UNIT"

if grep -qE '__[A-Z0-9_]+__' "$SYSTEMD_UNIT" "$FIREWALL_UNIT"; then
  die "kitöltetlen helyőrző maradt a systemd unitokban"
fi

# A renderelt szabályok markjának és NFLOG-csoportjának egyeznie kell a
# portál és a drop-log figyelő által használt értékkel. A unit sablon ezeket
# nem tartalmazza, ezért drop-inként adjuk át őket.
ENV_DROPIN_DIR="${SYSTEMD_DIR}/${SERVICE}.service.d"
install -d -m 0755 "$ENV_DROPIN_DIR"
cat > "$ENV_DROPIN_DIR/10-hatarvedelem-env.conf" <<EOF
[Service]
Environment=HV_FWD_MARK=$FWD_MARK
Environment=HV_DROP_LOG_GROUP=$DROP_LOG_GROUP
EOF
chmod 0644 "$ENV_DROPIN_DIR/10-hatarvedelem-env.conf"

systemctl daemon-reload
systemctl enable "$FIREWALL_SERVICE" >/dev/null
systemctl enable "$SERVICE" >/dev/null

if ! systemctl restart "$FIREWALL_SERVICE"; then
  warn "a tűzfal-szolgáltatás nem indult el; napló:"
  journalctl -u "$FIREWALL_SERVICE" -n 30 --no-pager || true
  die "telepítés sikertelen"
fi
for hv_set in allowed_v4 allowed_tcp allowed_udp allowed_icmp; do
  "$NFT_BIN" list set inet hatarvedelem "$hv_set" >/dev/null \
    || die "a(z) $hv_set halmaz nem található a szolgáltatás indulása után"
done

if ! systemctl restart "$SERVICE"; then
  warn "a szolgáltatás nem indult el; napló:"
  journalctl -u "$SERVICE" -n 30 --no-pager || true
  die "telepítés sikertelen"
fi
sleep 1
if ! systemctl is-active --quiet "$SERVICE"; then
  warn "a szolgáltatás nem fut; napló:"
  journalctl -u "$SERVICE" -n 30 --no-pager || true
  die "telepítés sikertelen"
fi

# ------------------------------------------------------------------ első user

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
      warn "nem hoztam létre felhasználót (--yes). Később:"
      echo "  HV_USERS=$STATE_DIR/users.json $PYTHON $APP_DIR/server.py user add <név>"
    else
      echo
      ADMIN_NAME="$(ask_value "Első felhasználó neve" "admin")"
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
    >/dev/null 2>&1 || true
fi

# ------------------------------------------------------------------ összegzés

note "Kész"
cat <<EOF
  Rendszer:          $DISTRO_NAME ($PKG_MANAGER)
  Python:            $PYTHON
  nft:               $NFT_BIN
  Portál:            $PORTAL_URL
  Tűzfal állapot:    systemctl status $FIREWALL_SERVICE
  Portál állapot:    systemctl status $SERVICE
  Napló:             journalctl -u $SERVICE -f
  Tűzfal napló:      journalctl -u $FIREWALL_SERVICE -f
  Engedélyek:        $NFT_BIN list set inet hatarvedelem allowed_v4
  Felhasználó:       HV_USERS=$STATE_DIR/users.json $PYTHON $APP_DIR/server.py user add <név>

  A kliensek alapértelmezett átjárója: $GW_IP
  A belépés előtt HTTPS nem megy át (csak a HTTP-t tudjuk a portálra
  irányítani), ezért a portál címe: $PORTAL_URL

  A portál újraindítása minden belépést töröl (tiszta indulás).
  A tűzfal újratöltése (systemctl reload $FIREWALL_SERVICE) megőrzi a
  belépett klienseket.
EOF

if [[ $DISABLED_OTHER_FIREWALL -eq 1 ]]; then
  warn "Más tűzfalat is kikapcsoltunk. A bootkori maradék szabályok miatt"
  warn "érdemes újraindítani a gépet, mielőtt éles használatba veszed."
fi
