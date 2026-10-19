#!/bin/sh
# Dropjak — konténer belépési pont
#
# A konténer a HOST hálózati névterében fut (network_mode: host), ezért az itt
# betöltött nftables-szabályok a VM forward-láncára vonatkoznak. A sorrend:
#
#   1. a deploy/hatarvedelem.nft sablon kitöltése a HV_* változókkal,
#   2. a szabályok ellenőrzése és betöltése (idempotens),
#   3. a korai boot-védelmet adó hatarvedelem_boot tábla eltávolítása,
#   4. a portál indítása korlátozott jogosultságú felhasználóként.
#
# A szkript rootként fut, mert az nft a host hálózatához nyúl. A portál már a
# hatarvedelem felhasználóként indul, csak a szükséges képességekkel.
set -eu

APP_DIR=${HV_APP_DIR:-/opt/hatarvedelem}
TEMPLATE="$APP_DIR/deploy/hatarvedelem.nft"
STATE_DIR=${HV_STATE_DIR:-/var/lib/hatarvedelem}
PYTHON=${HV_PYTHON:-python3}
APP_USER=hatarvedelem

log() { printf '[hatarvedelem] %s\n' "$*"; }
die() { printf '[hatarvedelem] HIBA: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- ellenőrzés

valid_ifname() {
    # Linux interfésznév: legfeljebb 15 karakter; a sablonba kerül, ezért
    # csak biztonságos karaktereket engedünk meg.
    [ -n "$1" ] || return 1
    [ "${#1}" -le 15 ] || return 1
    case "$1" in
        [A-Za-z0-9]*) ;;
        *) return 1 ;;
    esac
    case "$1" in
        *[!A-Za-z0-9_.:@+-]*) return 1 ;;
    esac
    return 0
}

valid_network() {
    # $1: 4 vagy 6 (várt IP-verzió), $2: hálózat CIDR formában.
    "$PYTHON" - "$1" "$2" <<'PY'
import ipaddress
import sys

try:
    network = ipaddress.ip_network(sys.argv[2], strict=True)
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if network.version == int(sys.argv[1]) else 1)
PY
}

valid_port() {
    case "$1" in
        "" | *[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

require_env() {
    value=$(printenv "$1" 2>/dev/null || true)
    [ -n "$value" ] || die "hiányzó környezeti változó: $1"
}

# ------------------------------------------------------------------ felkészítés

ensure_state_dir() {
    mkdir -p "$STATE_DIR" || die "az állapotkönyvtár nem hozható létre: $STATE_DIR"
    if [ "$(id -u)" -eq 0 ]; then
        # A kötet első induláskor root tulajdonú lehet. A CLI és a portál is
        # a hatarvedelem felhasználóként ír, ezért itt rendezzük a jogokat.
        chown -R "$APP_USER:$APP_USER" "$STATE_DIR" \
            || die "az állapotkönyvtár tulajdonosa nem állítható be: $STATE_DIR"
        chmod 0750 "$STATE_DIR" || true
    fi
}

run_as_app() {
    if [ "$(id -u)" -ne 0 ] || [ "${HV_RUN_AS_ROOT:-0}" = "1" ]; then
        exec "$@"
    fi
    command -v setpriv >/dev/null 2>&1 \
        || die "a setpriv nem található (util-linux csomag szükséges)"
    # A setpriv ambient képességekkel adja tovább a NET_ADMIN-t, mert a
    # konténerben nem root felhasználó alapból nem kaphat képességet.
    exec setpriv \
        --reuid="$APP_USER" --regid="$APP_USER" --init-groups \
        --inh-caps=+net_admin,+net_bind_service \
        --ambient-caps=+net_admin,+net_bind_service \
        -- "$@"
}

# --------------------------------------------------------------------- tűzfal

render_ruleset() {
    [ -r "$TEMPLATE" ] || die "hiányzó sablon: $TEMPLATE"

    HV_LAN_IF=${HV_LAN_IF:-}
    HV_WAN_IF=${HV_WAN_IF:-}
    HV_LAN_NET=${HV_LAN_NET:-}
    HV_MGMT_NET=${HV_MGMT_NET:-}
    HV_PORTAL_NET=${HV_PORTAL_NET:-$HV_MGMT_NET}
    PORT=${PORT:-8100}
    HV_FWD_MARK=${HV_FWD_MARK:-0x44524a4b}

    require_env HV_LAN_IF
    require_env HV_WAN_IF
    require_env HV_LAN_NET
    require_env HV_PORTAL_NET

    valid_ifname "$HV_LAN_IF" || die "érvénytelen HV_LAN_IF: $HV_LAN_IF"
    valid_ifname "$HV_WAN_IF" || die "érvénytelen HV_WAN_IF: $HV_WAN_IF"
    valid_network 4 "$HV_LAN_NET" \
        || die "érvénytelen HV_LAN_NET (hálózati cím kell, pl. 192.168.10.0/24): $HV_LAN_NET"
    valid_network 4 "$HV_PORTAL_NET" \
        || die "érvénytelen HV_PORTAL_NET (IPv4 CIDR kell, pl. 0.0.0.0/0): $HV_PORTAL_NET"
    valid_port "$PORT" || die "érvénytelen PORT: $PORT"
    case "$HV_FWD_MARK" in
        0x[0-9A-Fa-f]*) ;;
        *) die "érvénytelen HV_FWD_MARK (0x kezdetű hex szám kell): $HV_FWD_MARK" ;;
    esac
    [ "${#HV_FWD_MARK}" -le 10 ] \
        || die "érvénytelen HV_FWD_MARK (32 bites hex szám lehet): $HV_FWD_MARK"
    [ "$HV_LAN_IF" != "$HV_WAN_IF" ] \
        || die "a HV_LAN_IF és a HV_WAN_IF nem lehet ugyanaz"

    # Ha a /run nem írható (pl. read-only gyökér, tmpfs nélkül), a /tmp a
    # tartalék. A compose konfiguráció mindkettőt tmpfs-ként biztosítja.
    RENDERED=${HV_NFT_FILE:-/run/hatarvedelem.nft}
    if ! ( : >"$RENDERED" ) 2>/dev/null; then
        RENDERED=/tmp/hatarvedelem.nft
    fi

    sed \
        -e "s|__LAN_IF__|$HV_LAN_IF|g" \
        -e "s|__WAN_IF__|$HV_WAN_IF|g" \
        -e "s|__LAN_NET__|$HV_LAN_NET|g" \
        -e "s|__PORTAL_NET__|$HV_PORTAL_NET|g" \
        -e "s|__PORT__|$PORT|g" \
        -e "s|__FWD_MARK__|$HV_FWD_MARK|g" \
        "$TEMPLATE" >"$RENDERED" || die "a szabálysablon nem tölthető ki"

    chmod 0600 "$RENDERED" || true
    if grep -Eq '__[A-Z0-9_]+__' "$RENDERED"; then
        die "a kitöltött szabályfájlban helyőrző maradt"
    fi
    log "szabályfájl elkészült: $RENDERED"
}

docker_forward_guard() {
    # A Docker ip filter FORWARD lánca a saját szabályaival (például a
    # publikált konténerportokkal) akkor is átengedné a forgalmat, ha a mi
    # inet táblánk eltűnne. A hivatalos DOCKER-USER láncon ezért MINDEN
    # forwardolt csomagot eldobunk, kivéve azt, amelyiket az inet
    # hatarvedelem forward lánca megjelölt. A jelölés csak akkor kerül a
    # csomagra, ha a mi szabályaink tényleg lefutottak és engedélyeztek.
    DOCKER_USER=$("$NFT_BIN" list chain ip filter DOCKER-USER 2>/dev/null || true)
    if [ -z "$DOCKER_USER" ]; then
        log "Docker DOCKER-USER lánc nincs; nincs szükség Docker-forward-védelemre"
        return 0
    fi
    # A régi szabályok listája még a beszúrás előtt készül; a handle-ök a
    # beszúrás után is érvényesek maradnak.
    OLD_RULES=$("$NFT_BIN" -a list chain ip filter DOCKER-USER 2>/dev/null || true)

    # A guard a lehető leghamarabb kerül a láncra: a régi széles acceptek
    # utána már csak a megjelölt csomagokra illeszkedhetnek.
    if ! "$NFT_BIN" insert rule ip filter DOCKER-USER \
            meta mark != "$HV_FWD_MARK" drop \
            comment '"hv-docker-fwd-guard"'; then
        log "HIBA: a Docker forward-védelme nem állítható be (DOCKER-USER drop)"
        return 1
    fi
    if ! "$NFT_BIN" insert rule ip filter DOCKER-USER \
            meta mark "$HV_FWD_MARK" accept \
            comment '"hv-docker-fwd-mark"'; then
        log "HIBA: a Docker forward-engedélye nem állítható be (DOCKER-USER accept)"
        return 1
    fi

    # A korábbi (széles) áthidaló szabályokat most már biztonságosan
    # eldobhatjuk.
    while IFS= read -r line; do
        case "$line" in
            *hv-docker-fwd-*)
                handle=${line##*# handle }
                [ "$handle" != "$line" ] || continue
                "$NFT_BIN" delete rule ip filter DOCKER-USER handle "$handle" || true
                ;;
        esac
    done <<EOF
$OLD_RULES
EOF
    # A policy drop a második védvonal arra az esetre, ha a DOCKER-USER
    # lánc valamilyen okból kimaradna a forgalom útjából.
    if ! "$NFT_BIN" add chain ip filter FORWARD '{ policy drop; }'; then
        log "FIGYELEM: a Docker FORWARD lánc policy drop beállítása nem sikerült"
    fi
    log "Docker forward-védelem beállítva (csak jelölt csomag mehet át)"
    return 0
}

start_firewall_watchdog() {
    [ "${HV_FIREWALL_WATCHDOG:-1}" = "1" ] || return 0
    (
        while :; do
            sleep 5
            forward=$("$NFT_BIN" list chain inet hatarvedelem forward 2>/dev/null || true)
            case "$forward" in
                *"policy drop"*) ;;
                *) forward="" ;;
            esac
            if [ -z "$forward" ] || ! printf '%s' "$forward" | grep -q '@client_mac'; then
                log "FIGYELEM: a hatarvedelem forward lánc hiányos; újratöltés"
                if "$NFT_BIN" -c -f "$RENDERED" && "$NFT_BIN" -f "$RENDERED"; then
                    log "a tűzfal újratöltve"
                else
                    log "HIBA: a tűzfal újratöltése nem sikerült"
                fi
                docker_forward_guard || true
            elif ! "$NFT_BIN" list chain ip filter DOCKER-USER 2>/dev/null \
                    | grep -q 'hv-docker-fwd-guard'; then
                log "FIGYELEM: a Docker forward-védelme hiányzik; újra beállítás"
                docker_forward_guard || true
            fi
        done
    ) &
    log "tűzfal-figyelő elindítva (5 másodperc)"
}

load_firewall() {
    NFT_BIN=${HV_NFT_BIN:-}
    if [ -z "$NFT_BIN" ]; then
        NFT_BIN=$(command -v nft 2>/dev/null || true)
    fi
    [ -n "$NFT_BIN" ] || NFT_BIN=/usr/sbin/nft
    [ -x "$NFT_BIN" ] || die "az nft nem található (HV_NFT_BIN=$NFT_BIN)"
    export HV_NFT_BIN="$NFT_BIN"

    render_ruleset

    log "szabályok ellenőrzése"
    "$NFT_BIN" -c -f "$RENDERED" \
        || die "az nftables szabályok érvénytelenek"
    log "szabályok betöltése (host hálózati névtér)"
    "$NFT_BIN" -f "$RENDERED" \
        || die "a szabályok betöltése sikertelen"
    "$NFT_BIN" list table inet hatarvedelem >/dev/null 2>&1 \
        || die "a hatarvedelem tábla nem jött létre"

    # Újraindításnál a kernelben maradt engedélyek ne maradjanak érvényben
    # a boot-védelem eltávolítása után. A portál is kiüríti a halmazt, de
    # így a rövid átadási időben sem marad nyitva senki.
    if [ "${HV_FLUSH_ON_START:-1}" = "1" ]; then
        for hv_set in allowed_v4 allowed_tcp allowed_udp allowed_icmp \
                host_ssh_v4 client_mac; do
            "$NFT_BIN" flush set inet hatarvedelem "$hv_set" \
                || die "a(z) $hv_set halmaz ürítése nem sikerült"
        done
        log "a dinamikus halmazok kiürítve (HV_FLUSH_ON_START=1)"
    fi

    # A hoston korán betöltött tartalék tábla már nem kell: a végleges
    # szabályok védik a forward-láncot. Ha nincs ilyen, ez nem hiba.
    if "$NFT_BIN" list table inet hatarvedelem_boot >/dev/null 2>&1; then
        "$NFT_BIN" delete table inet hatarvedelem_boot
        log "a korai boot-védelem átadta a helyét a végleges szabályoknak"
    fi

    docker_forward_guard \
        || die "a Docker forward-védelme nélkül a tűzfal kikerülhető; indulás leállítva"

    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != "1" ]; then
        if (echo 1 >/proc/sys/net/ipv4/ip_forward) 2>/dev/null; then
            log "net.ipv4.ip_forward bekapcsolva"
        else
            log "FIGYELEM: a net.ipv4.ip_forward nincs bekapcsolva."
            log "         A hoston: sysctl -w net.ipv4.ip_forward=1"
        fi
    fi
}

# ------------------------------------------------------------------------ main

ensure_state_dir
export HV_STATE_DIR="$STATE_DIR"

# Egyedi parancs (pl. felhasználókezelés): a tűzfalhoz nem nyúlunk.
if [ "$#" -gt 0 ]; then
    run_as_app "$@"
fi

if [ "${HV_SKIP_FIREWALL:-0}" = "1" ]; then
    log "FIGYELEM: a tűzfalszabályok betöltése kihagyva (HV_SKIP_FIREWALL=1)"
else
    load_firewall
    start_firewall_watchdog
fi

if [ -z "${HV_CONNTRACK_BIN:-}" ]; then
    CONNTRACK=$(command -v conntrack 2>/dev/null || true)
    [ -n "$CONNTRACK" ] && export HV_CONNTRACK_BIN="$CONNTRACK"
fi

log "portál indítása a ${PORT:-8100}-as porton"
run_as_app "$PYTHON" "$APP_DIR/server.py"
