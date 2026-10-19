#!/usr/bin/env bash
#
# Dropjak — host előkészítése a Dockeres telepítéshez
#
# Ez a szkript a HOSTON fut, rootként. Egyetlen dolga, hogy a boot korai
# szakaszában is tiltva legyen a forward-forgalom, mielőtt a Docker daemon
# és a konténer elindul:
#
#   - /etc/nftables/hatarvedelem-boot.nft  (policy drop a forward-láncon)
#   - /etc/systemd/system/hatarvedelem-boot.service
#   - /etc/sysctl.d/90-hatarvedelem.conf   (net.ipv4.ip_forward = 1)
#
# A konténer a saját szabályainak betöltése után törli a boot-táblát, így
# a végleges szabályok veszik át a helyét.
#
# Használat:  sudo ./docker/setup-host.sh
#
# A szkript idempotens: többszöri futtatás után is ugyanaz az állapot.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)

BOOT_NFT=/etc/nftables/hatarvedelem-boot.nft
BOOT_UNIT=/etc/systemd/system/hatarvedelem-boot.service
SYSCTL_FILE=/etc/sysctl.d/90-hatarvedelem.conf

die() { printf 'HIBA: %s\n' "$*" >&2; exit 1; }
info() { printf '[hatarvedelem] %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || die "rootként futtasd: sudo $0"

[ -r "$REPO_DIR/deploy/hatarvedelem-boot.nft" ] \
    || die "hiányzó fájl: $REPO_DIR/deploy/hatarvedelem-boot.nft"
[ -r "$REPO_DIR/deploy/hatarvedelem-boot.service" ] \
    || die "hiányzó fájl: $REPO_DIR/deploy/hatarvedelem-boot.service"

# ------------------------------------------------------------- nft telepítése

NFT_BIN=$(command -v nft 2>/dev/null || true)
if [ -z "$NFT_BIN" ]; then
    info "az nftables nincs telepítve, telepítem"
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
        die "nem találom a csomagkezelőt; telepítsd kézzel az nftables csomagot"
    fi
    NFT_BIN=$(command -v nft 2>/dev/null || true)
fi
[ -n "$NFT_BIN" ] || die "az nft telepítés után sem található"

if ! command -v systemctl >/dev/null 2>&1; then
    die "ez a szkript systemd-t feltételez"
fi

info "nft: $NFT_BIN"

# --------------------------------------------------------------- fájlok

install -d -m 0755 /etc/nftables
install -m 0600 "$REPO_DIR/deploy/hatarvedelem-boot.nft" "$BOOT_NFT"

TMP_UNIT=$(mktemp)
trap 'rm -f "$TMP_UNIT"' EXIT
sed "s|__NFT_BIN__|$NFT_BIN|g" \
    "$REPO_DIR/deploy/hatarvedelem-boot.service" >"$TMP_UNIT"
grep -q '__[A-Z0-9_]*__' "$TMP_UNIT" && die "a unitban helyőrző maradt"
install -m 0644 "$TMP_UNIT" "$BOOT_UNIT"

if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$BOOT_NFT" "$BOOT_UNIT" >/dev/null 2>&1 || true
fi

# --------------------------------------------------------------- sysctl

cat >"$SYSCTL_FILE" <<'EOF'
# Dropjak: a VM átjáróként továbbítja a kliensek forgalmát.
# A tényleges engedélyezést az nftables allowed_v4 halmaza végzi.
net.ipv4.ip_forward = 1
EOF
chmod 0644 "$SYSCTL_FILE"

if command -v sysctl >/dev/null 2>&1; then
    sysctl -q -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
else
    echo 1 >/proc/sys/net/ipv4/ip_forward 2>/dev/null || true
fi
if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != "1" ]; then
    info "FIGYELEM: a net.ipv4.ip_forward most nem kapcsolható be; újraindítás után igen."
fi

# --------------------------------------------------------------- unit

systemctl daemon-reload

# Ha a Docker már fut, a konténer szabályai védik a forward-láncot; a
# boot-tábla azonnali betöltése megszakítaná a már belépett klienseket.
# Ebben az esetben csak engedélyezzük, a következő bootkor lép életbe.
if systemctl is-active --quiet docker.service 2>/dev/null; then
    systemctl enable hatarvedelem-boot.service >/dev/null
    info "a Docker már fut: a boot-táblát most nem töltöm be, hogy ne szakítsam meg a forgalmat."
    info "a következő újraindításkor már a Docker előtt lép életbe."
else
    "$NFT_BIN" -c -f "$BOOT_NFT" || die "érvénytelen boot-szabályfájl"
    systemctl enable --now hatarvedelem-boot.service
    systemctl is-active --quiet hatarvedelem-boot.service \
        || die "a hatarvedelem-boot.service nem indult el"
    info "a korai forward-tiltás aktív."
fi

# --------------------------------------------------------------- figyelmeztetés

for svc in firewalld ufw; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        info "FIGYELEM: a(z) $svc aktív a hoston. Az nftables-tábláink ettől"
        info "         függetlenül működnek, de más Docker-konténerek forward-forgalmát"
        info "         a hatarvedelem szabályai is érinthetik. Dedikált átjárón ajánlott."
    fi
done

info "kész."
info "Következő lépés: cp .env.example .env, szerkesztés, majd docker compose up -d --build"
