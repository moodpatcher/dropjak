#!/usr/bin/env bash
#
# Dropjak — interactive configuration
#
# Asks for the installation mode (single-NIC or LAN+WAN), the interfaces,
# the networks, the portal exposure and the first admin account, then writes
# the .env file with mode 0600.
#
#   ./configure.sh
#
# Re-running it is safe: the current .env values are offered as defaults and
# the old file is backed up first.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ENV_FILE="$SCRIPT_DIR/.env"
PYTHON=${PYTHON:-python3}

usage() {
    cat <<'EOF'
Usage: ./configure.sh [--env-file PATH]

Asks for the installation mode (single-NIC, where the WAN interface is also
the client side, or LAN+WAN), the interfaces, the networks, the portal source
network, the management network, the portal port and the first admin account,
then writes the .env file (mode 0600). Current values are offered as defaults.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --env-file)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            ENV_FILE=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '[dropjak] %s\n' "$*" >&2; }

command -v "$PYTHON" >/dev/null 2>&1 || die "python3 is required"
command -v ip >/dev/null 2>&1 || die "the ip command (iproute2) is required"

# ------------------------------------------------------------- reading input

env_get() {
    [ -r "$ENV_FILE" ] || return 0
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$ENV_FILE" \
        | tail -n 1 | sed 's/[[:space:]]*$//; s/^["'\'']//; s/["'\'']$//'
}

ask() {
    # ask <prompt> [default] -> prints the answer
    local prompt=$1 default=${2:-} answer
    if [ -n "$default" ]; then
        printf '%s [%s]: ' "$prompt" "$default" >&2
    else
        printf '%s: ' "$prompt" >&2
    fi
    if ! IFS= read -r answer; then
        answer=""
    fi
    [ -n "$answer" ] || answer=$default
    printf '%s\n' "$answer"
}

ask_secret() {
    # ask_secret <prompt> -> prints the answer without echo on a terminal
    local prompt=$1 answer
    printf '%s: ' "$prompt" >&2
    if [ -t 0 ]; then
        IFS= read -r -s answer || answer=""
        printf '\n' >&2
    else
        IFS= read -r answer || answer=""
    fi
    printf '%s\n' "$answer"
}

confirm() {
    # confirm <prompt> <default y|n>; returns 0 for yes
    local prompt=$1 default=${2:-n} answer hint
    case "$default" in
        [yY]*) hint="Y/n" ;;
        *) hint="y/N" ;;
    esac
    while :; do
        printf '%s [%s]: ' "$prompt" "$hint" >&2
        if ! IFS= read -r answer; then
            answer=""
        fi
        answer=${answer:-$default}
        case "$answer" in
            [yY]|[yY][eE][sS]) return 0 ;;
            [nN]|[nN][oO]) return 1 ;;
            *) info "please answer y or n" ;;
        esac
    done
}

# ---------------------------------------------------------------- validation

valid_net() {
    "$PYTHON" -c 'import ipaddress,sys; ipaddress.ip_network(sys.argv[1], strict=False)' \
        "$1" >/dev/null 2>&1
}

valid_port() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

valid_ifname() {
    case "$1" in
        ''|*[!A-Za-z0-9_.:@+-]*) return 1 ;;
    esac
    [ "${#1}" -le 15 ]
}

interface_exists() {
    ip link show dev "$1" >/dev/null 2>&1
}

# --------------------------------------------------------------- interfaces

interfaces=$(ip -br link 2>/dev/null | awk '$1 != "lo" {print $1}' | sed 's/@.*//' || true)

show_interfaces() {
    if [ -z "$interfaces" ]; then
        info "no network interface found (is iproute2 installed?)"
        return
    fi
    info "available interfaces:"
    while IFS= read -r iface; do
        [ -n "$iface" ] || continue
        addr=$(ip -4 -o addr show dev "$iface" scope global 2>/dev/null \
            | awk '{print $4; exit}' || true)
        printf '    %-16s %s\n' "$iface" "${addr:-(no IPv4 address)}" >&2
    done <<<"$interfaces"
}

default_lan_if() {
    local iface cidr
    while IFS= read -r iface; do
        [ -n "$iface" ] || continue
        cidr=$(ip -4 -o addr show dev "$iface" scope global 2>/dev/null \
            | awk '{print $4; exit}' || true)
        [ -n "$cidr" ] || continue
        if "$PYTHON" -c 'import ipaddress,sys; sys.exit(0 if ipaddress.ip_interface(sys.argv[1]).ip.is_private else 1)' \
                "$cidr" 2>/dev/null; then
            printf '%s\n' "$iface"
            return 0
        fi
    done <<<"$interfaces"
}

default_wan_if() {
    ip -4 route show default 2>/dev/null \
        | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}' || true
}

default_lan_net() {
    local cidr
    cidr=$(ip -4 -o addr show dev "$1" scope global 2>/dev/null | awk '{print $4; exit}' || true)
    [ -n "$cidr" ] || return 0
    "$PYTHON" -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)' \
        "$cidr" 2>/dev/null || true
}

# ------------------------------------------------------------------- asking

info "Dropjak configuration — press Enter to accept the value in brackets."
show_interfaces

old_single=$(env_get HV_SINGLE_NIC)
old_lan_if=$(env_get HV_LAN_IF)
old_wan_if=$(env_get HV_WAN_IF)
old_lan_net=$(env_get HV_LAN_NET)
old_portal_net=$(env_get HV_PORTAL_NET)
old_mgmt_net=$(env_get HV_MGMT_NET)
old_port=$(env_get PORT)
old_admin_user=$(env_get HV_ADMIN_USER)

# ---------------------------------------------------------------- mode
# Default: single-NIC when there is no private IPv4 interface or only one
# non-loopback interface (a VPS with a single public NIC). An existing
# HV_SINGLE_NIC wins when it is set.
nonlo_count=$(printf '%s\n' "$interfaces" | awk 'NF { n++ } END { print n + 0 }')
private_lan_if=$(default_lan_if || true)
if [ "$old_single" = "1" ]; then
    SINGLE_DEFAULT=y
elif [ -n "$old_single" ]; then
    SINGLE_DEFAULT=n
elif [ -z "$private_lan_if" ] || [ "$nonlo_count" -le 1 ]; then
    SINGLE_DEFAULT=y
else
    SINGLE_DEFAULT=n
fi
if confirm "Single-NIC host (no separate client LAN)?" "$SINGLE_DEFAULT"; then
    SINGLE_NIC=1
    info "single-NIC mode: the WAN interface is also the client side."
else
    SINGLE_NIC=0
fi

if [ "$SINGLE_NIC" -eq 1 ]; then
    LAN_IF=""
    LAN_NET=""

    WAN_IF_DEFAULT=${old_wan_if:-$(default_wan_if)}
    [ -n "$WAN_IF_DEFAULT" ] || WAN_IF_DEFAULT=eth0
    while :; do
        WAN_IF=$(ask "WAN (internet and client) interface" "$WAN_IF_DEFAULT")
        valid_ifname "$WAN_IF" \
            || { info "invalid interface name: $WAN_IF"; continue; }
        break
    done
    interface_exists "$WAN_IF" \
        || info "WARNING: interface $WAN_IF does not exist right now; the rules apply once it appears."
else
    LAN_IF_DEFAULT=${old_lan_if:-$(default_lan_if)}
    while :; do
        LAN_IF=$(ask "LAN (client) interface" "${LAN_IF_DEFAULT:-eth1}")
        valid_ifname "$LAN_IF" \
            || { info "invalid interface name: $LAN_IF"; continue; }
        break
    done

    WAN_IF_DEFAULT=${old_wan_if:-$(default_wan_if)}
    [ -n "$WAN_IF_DEFAULT" ] || WAN_IF_DEFAULT=eth0
    while :; do
        WAN_IF=$(ask "WAN (internet) interface" "$WAN_IF_DEFAULT")
        valid_ifname "$WAN_IF" \
            || { info "invalid interface name: $WAN_IF"; continue; }
        [ "$WAN_IF" != "$LAN_IF" ] \
            || { info "the LAN and WAN interfaces must differ"; continue; }
        break
    done

    interface_exists "$LAN_IF" \
        || info "WARNING: interface $LAN_IF does not exist right now; the rules apply once it appears."
    interface_exists "$WAN_IF" \
        || info "WARNING: interface $WAN_IF does not exist right now; the rules apply once it appears."

    LAN_NET_DEFAULT=${old_lan_net:-$(default_lan_net "$LAN_IF")}
    while :; do
        LAN_NET=$(ask "Internal (client) network in CIDR form" "${LAN_NET_DEFAULT:-192.168.10.0/24}")
        valid_net "$LAN_NET" \
            || { info "invalid network: $LAN_NET"; continue; }
        break
    done
fi

if [ "$SINGLE_NIC" -eq 1 ]; then
    info "The portal is reached by source-IP matching (there is no LAN"
    info "interface). 0.0.0.0/0 makes it public, a CIDR restricts it."
else
    info "The portal is reachable from the LAN always. This value controls the"
    info "WAN: 0.0.0.0/0 makes it public, a CIDR keeps it off the internet."
fi
PORTAL_NET_DEFAULT=${old_portal_net:-0.0.0.0/0}
while :; do
    PORTAL_NET=$(ask "Portal source network" "$PORTAL_NET_DEFAULT")
    valid_net "$PORTAL_NET" || { info "invalid network: $PORTAL_NET"; continue; }
    break
done

info "The management network is used for fail2ban exemptions; it does not"
info "narrow the portal and does not allow SSH."
if [ "$SINGLE_NIC" -eq 1 ]; then
    info "It may be left empty."
    MGMT_NET_DEFAULT=${old_mgmt_net:-}
    while :; do
        MGMT_NET=$(ask "Management network (optional)" "$MGMT_NET_DEFAULT")
        [ -z "$MGMT_NET" ] && break
        valid_net "$MGMT_NET" \
            || { info "invalid network: $MGMT_NET"; continue; }
        break
    done
else
    MGMT_NET_DEFAULT=${old_mgmt_net:-$LAN_NET}
    while :; do
        MGMT_NET=$(ask "Management network" "$MGMT_NET_DEFAULT")
        valid_net "$MGMT_NET" \
            || { info "invalid network: $MGMT_NET"; continue; }
        break
    done
fi

PORT_DEFAULT=${old_port:-8100}
while :; do
    PORT=$(ask "Portal port on the host" "$PORT_DEFAULT")
    valid_port "$PORT" || { info "invalid port: $PORT"; continue; }
    break
done

info "Optional: a DNS name the portal is opened under (for example"
info "gw.example.com). Leave it empty to open the portal by IP address."
PORTAL_DOMAIN=$(ask "Portal DNS name (optional)" "")

if confirm "Create/update the admin account at every start?" "y"; then
    ADMIN_ENABLED=1
    ADMIN_USER=$(ask "Admin username" "${old_admin_user:-admin}")
    info "Leave the password empty to generate a random one."
    ADMIN_PASSWORD=$(ask_secret "Admin password")
    if [ -z "$ADMIN_PASSWORD" ]; then
        ADMIN_PASSWORD=$("$PYTHON" -c 'import secrets; print(secrets.token_hex(16))')
        info "generated admin password: $ADMIN_PASSWORD"
        info "(it is written to the .env file; read it back with: grep HV_ADMIN_PASSWORD .env)"
    fi
else
    ADMIN_ENABLED=0
    ADMIN_USER=""
    ADMIN_PASSWORD=""
fi

# -------------------------------------------------------------------- write

env_quote() {
    # Compose reads unquoted values with interpolation; single quotes keep
    # the value literal. A single quote cannot be represented in that form.
    case "$1" in
        *"'"*) die "the value must not contain a single quote" ;;
        *[!A-Za-z0-9_./:@%+,-]*) printf "'%s'\n" "$1" ;;
        *) printf '%s\n' "$1" ;;
    esac
}

if [ -e "$ENV_FILE" ]; then
    backup="$ENV_FILE.bak-$(date +%Y%m%d-%H%M%S)"
    cp -p "$ENV_FILE" "$backup"
    info "previous .env saved: $backup"
fi

umask 077
tmp=$(mktemp "${ENV_FILE}.XXXXXX")
trap 'rm -f "$tmp"' EXIT
{
    printf '# Dropjak — generated by configure.sh on %s\n' "$(date -Iseconds)"
    printf '# Re-run ./configure.sh to change these values.\n\n'
    printf 'HV_SINGLE_NIC=%s\n' "$SINGLE_NIC"
    printf 'HV_LAN_IF=%s\n' "$LAN_IF"
    printf 'HV_WAN_IF=%s\n' "$WAN_IF"
    printf 'HV_LAN_NET=%s\n' "$LAN_NET"
    printf 'HV_PORTAL_NET=%s\n' "$PORTAL_NET"
    printf 'HV_MGMT_NET=%s\n' "$MGMT_NET"
    printf 'PORT=%s\n' "$PORT"
    if [ -n "$PORTAL_DOMAIN" ]; then
        printf '\n# The portal answers under this DNS name too (instead of a redirect to the IP).\n'
        printf 'HV_PORTAL_HOSTS=%s,%s:%s\n' "$PORTAL_DOMAIN" "$PORTAL_DOMAIN" "$PORT"
        printf 'HV_PORTAL_URL=http://%s:%s\n' "$PORTAL_DOMAIN" "$PORT"
    fi
    printf '\nHV_ADMIN_ENABLED=%s\n' "$ADMIN_ENABLED"
    if [ "$ADMIN_ENABLED" = 1 ]; then
        printf 'HV_ADMIN_USER=%s\n' "$ADMIN_USER"
        printf 'HV_ADMIN_PASSWORD=%s\n' "$(env_quote "$ADMIN_PASSWORD")"
        printf '# Safer alternative: store the password in ./secrets/dropjak_admin_password\n'
        printf '# (0600, owner root) and use HV_ADMIN_PASSWORD_FILE instead.\n'
    fi
} >"$tmp"
chmod 600 "$tmp"
mv -f "$tmp" "$ENV_FILE"
chmod 600 "$ENV_FILE"
trap - EXIT

# ------------------------------------------------------------------- summary

wan_addr=$(ip -4 -o addr show dev "$WAN_IF" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)
portal_hint=${PORTAL_DOMAIN:-${wan_addr:-<host-ip>}}
case "$PORTAL_NET" in
    0.0.0.0/0) public="yes (0.0.0.0/0)" ;;
    *) public="no ($PORTAL_NET)" ;;
esac

info "wrote $ENV_FILE (mode 0600)"
if [ "$SINGLE_NIC" -eq 1 ]; then
    info "  mode:   single-NIC (the WAN interface is also the client side)"
    info "  WAN:    $WAN_IF"
else
    info "  mode:   LAN+WAN"
    info "  LAN:    $LAN_IF $LAN_NET"
    info "  WAN:    $WAN_IF"
fi
info "  portal: http://$portal_hint:$PORT/  — public from the WAN: $public"
info "  admin:  ${ADMIN_USER:-(disabled)}"
info "next steps:"
info "  sudo ./docker/setup-host.sh"
info "  DOCKER_BUILDKIT=0 docker build --network host -t dropjak:2 ."
info "  docker compose up -d"
info "the first start closes host SSH; keep the provider console open until"
info "you have signed in on the portal and created a host rule that allows TCP 22."
