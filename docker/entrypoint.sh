#!/bin/sh
# Dropjak — container entrypoint
#
# The container runs in the HOST network namespace (network_mode: host), so the
# nftables rules loaded here apply to the VM's forward chain. The order:
#
#   1. fill in the deploy/dropjak.nft template with the HV_* variables,
#   2. validate and load the rules (idempotent),
#   3. remove the hatarvedelem_boot table providing early boot protection,
#   4. start the portal as a restricted-privilege user.
#
# The script runs as root because nft touches the host network. The portal is
# already started as the hatarvedelem user, with only the necessary capabilities.
set -eu

APP_DIR=${HV_APP_DIR:-/opt/hatarvedelem}
TEMPLATE="$APP_DIR/deploy/dropjak.nft"
BOOT_NFT=${HV_BOOT_NFT:-$APP_DIR/deploy/dropjak-boot.nft}
STATE_DIR=${HV_STATE_DIR:-/var/lib/hatarvedelem}
PYTHON=${HV_PYTHON:-python3}
APP_USER=hatarvedelem

# Prints the elements of the old host_service_* sets in "22, 80, 8000-8100" form
# before rebuilding the table. It outputs only numbers, so it can be placed
# in a shell variable; on invalid or unknown JSON it stays empty.
HOST_PORTS_JSON='
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
parts = []
for top in data.get("nftables", []):
    item = top.get("set") if isinstance(top, dict) else None
    for raw in (item or {}).get("elem") or []:
        value = raw
        for _ in range(3):
            if not isinstance(value, dict):
                break
            if isinstance(value.get("range"), list) and len(value["range"]) == 2:
                low, high = value["range"]
                if all(isinstance(v, int) and not isinstance(v, bool) for v in (low, high)):
                    parts.append(str(low) if low == high else f"{low}-{high}")
                value = None
                break
            value = value.get("elem", value.get("val"))
        if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535:
            parts.append(str(value))
print(", ".join(parts))
'

log() { printf '[dropjak] %s\n' "$*"; }
die() { printf '[dropjak] ERROR: %s\n' "$*" >&2; exit 1; }

# Same logic as gateway.py's _env_bool(): 1/true/yes/on is true,
# 0/false/no/off is false, empty or unknown value uses the default.
# Independent of case and surrounding whitespace.
env_bool() {
    # $1: environment variable name, $2: default (1 or 0)
    _value=$(printenv "$1" 2>/dev/null || true)
    _value=$(
        printf '%s' "$_value" \
            | tr '[:upper:]' '[:lower:]' \
            | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
    )
    case "$_value" in
        1 | true | yes | on) printf '%s' 1 ;;
        0 | false | no | off) printf '%s' 0 ;;
        *) printf '%s' "$2" ;;
    esac
}

# ---------------------------------------------------------------- validation

valid_ifname() {
    # Linux interface name: at most 15 characters; it goes into the template, so
    # we allow only safe characters.
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
    # $1: 4 or 6 (expected IP version), $2: network in CIDR form.
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
    [ -n "$value" ] || die "missing environment variable: $1"
}

# ------------------------------------------------------------------ preparation

ensure_state_dir() {
    mkdir -p "$STATE_DIR" || die "cannot create the state directory: $STATE_DIR"
    if [ "$(id -u)" -eq 0 ]; then
        # The volume may be root-owned on first start. Both the CLI and the portal
        # write as the hatarvedelem user, so we fix the permissions here.
        chown -R "$APP_USER:$APP_USER" "$STATE_DIR" \
            || die "cannot set the owner of the state directory: $STATE_DIR"
        chmod 0750 "$STATE_DIR" || true
    fi
}

ensure_tunnel_run_dir() {
    # The 0600 temporary WireGuard key files go here; the portal does not
    # run as root, so we create the directory here with its privileges.
    _dir=${HV_TUNNEL_RUN_DIR:-/run/dropjak}
    if [ "$(id -u)" -eq 0 ]; then
        mkdir -p "$_dir" \
            || die "cannot create the tunnel key directory: $_dir"
        chown "$APP_USER:$APP_USER" "$_dir" \
            || die "cannot set the owner of the tunnel key directory: $_dir"
        chmod 0700 "$_dir" || true
    fi
}

ensure_caddy_admin_dir() {
    # The directory for Caddy's admin socket (a shared volume with the caddy container).
    # Caddy, running as root but without DAC_OVERRIDE, creates the socket in it
    # as the owner; the portal accesses it through the group, no one else.
    # The setgid bit makes the socket inherit the group, so the Caddyfile can
    # use mode 0660 instead of a world-writable socket.
    _sock=${HV_CADDY_ADMIN:-}
    [ -n "$_sock" ] && [ "$(id -u)" -eq 0 ] || return 0
    _dir=$(dirname "$_sock")
    [ -d "$_dir" ] || return 0
    chown "0:$APP_USER" "$_dir" && chmod 2750 "$_dir" \
        || log "WARNING: cannot set the permissions of the Caddy admin directory: $_dir"
}

stage_admin_secret() {
    # HV_ADMIN_PASSWORD_FILE usually points at a root-owned file on the
    # read-only /run/secrets mount (docker-compose.yml). The portal runs as
    # $APP_USER, so we copy it to the private tunnel run directory, readable
    # only by that user, and point the variable there. The password never
    # enters the environment this way.
    _src=${HV_ADMIN_PASSWORD_FILE:-}
    [ -n "$_src" ] && [ -r "$_src" ] && [ "$(id -u)" -eq 0 ] || return 0
    _dir=${HV_TUNNEL_RUN_DIR:-/run/dropjak}
    _dst="$_dir/admin-password"
    if ( umask 077 && cat "$_src" >"$_dst" ) \
            && chown "$APP_USER:$APP_USER" "$_dst" && chmod 0400 "$_dst"; then
        HV_ADMIN_PASSWORD_FILE=$_dst
        export HV_ADMIN_PASSWORD_FILE
    else
        rm -f "$_dst"
        log "WARNING: cannot stage the admin password file: $_src"
    fi
}

run_as_app() {
    # The boolean switches are interpreted by env_bool() (1/true/yes/on).
    if [ "$(id -u)" -ne 0 ] || [ "$(env_bool HV_RUN_AS_ROOT 0)" = "1" ]; then
        exec "$@"
    fi
    command -v setpriv >/dev/null 2>&1 \
        || die "setpriv not found (util-linux package required)"
    # setpriv passes NET_ADMIN with ambient capabilities, because a non-root
    # user cannot get capabilities by default in the container. The bounding
    # set is cut to the same two: CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID
    # and SETPCAP are needed only by this script, never by the portal.
    # Dropping from the bounding set needs SETPCAP (docker-compose.yml).
    exec setpriv \
        --reuid="$APP_USER" --regid="$APP_USER" --init-groups \
        --bounding-set=-all,+net_admin,+net_bind_service \
        --inh-caps=+net_admin,+net_bind_service \
        --ambient-caps=+net_admin,+net_bind_service \
        -- "$@"
}

check_proxy_key() {
    # With HV_PROXY=1 the portal trusts Caddy's X-Forwarded-For and serves it
    # the certificate private keys. Without the shared key every host process
    # (and every host-network container) would pass as Caddy, so the key is
    # mandatory. Checked before the firewall is touched: the loaded table
    # stays as it is.
    [ "$(env_bool HV_PROXY 0)" = "1" ] || return 0
    _key=${HV_PROXY_KEY:-}
    [ "${#_key}" -ge 32 ] && return 0
    die "HV_PROXY=1 requires HV_PROXY_KEY of at least 32 characters (now ${#_key}). Generate one with: openssl rand -hex 32 ; put HV_PROXY_KEY=<that value> in the .env file next to docker-compose.yml, then run: docker compose up -d (both the dropjak and the caddy service read it)."
}

# --------------------------------------------------------------------- firewall

render_ruleset() {
    [ -r "$TEMPLATE" ] || die "missing template: $TEMPLATE"

    HV_SINGLE_NIC=$(env_bool HV_SINGLE_NIC 0)
    HV_LAN_IF=${HV_LAN_IF:-}
    HV_WAN_IF=${HV_WAN_IF:-}
    HV_LAN_NET=${HV_LAN_NET:-}
    # The portal is public by default: the admin account, the proof-of-work
    # captcha and fail2ban guard the login. HV_MGMT_NET does not narrow it;
    # set HV_PORTAL_NET to a CIDR to keep the portal off the WAN.
    HV_PORTAL_NET=${HV_PORTAL_NET:-0.0.0.0/0}
    # A plain assignment does not export a variable that was absent from the
    # environment, and require_env reads the environment (printenv).
    export HV_PORTAL_NET
    PORT=${PORT:-8100}
    HV_FWD_MARK=${HV_FWD_MARK:-0x44524a4b}
    HV_DROP_LOG_GROUP=${HV_DROP_LOG_GROUP:-5}

    require_env HV_WAN_IF
    require_env HV_PORTAL_NET

    valid_ifname "$HV_WAN_IF" || die "invalid HV_WAN_IF: $HV_WAN_IF"

    if [ "$HV_SINGLE_NIC" = "1" ]; then
        # One interface does both jobs: the WAN interface is also the client
        # side, and the portal is reached by source-IP matching. Every
        # __LANONLY__ template line becomes a comment.
        LAN_PREFIX="# "
        if [ -n "$HV_LAN_IF" ] || [ -n "$HV_LAN_NET" ]; then
            log "single-NIC mode: HV_LAN_IF/HV_LAN_NET are set but ignored ($HV_LAN_IF / $HV_LAN_NET)"
        fi
        log "single-NIC mode (HV_SINGLE_NIC=1): DHCP server, LAN DNS, HTTP captive redirect, masquerade, MAC binding and the LAN input block are disabled"
    else
        LAN_PREFIX=""
        [ -n "$HV_LAN_IF" ] || die "missing environment variable: HV_LAN_IF (set HV_SINGLE_NIC=1 for a host with a single NIC)"
        [ -n "$HV_LAN_NET" ] || die "missing environment variable: HV_LAN_NET (set HV_SINGLE_NIC=1 for a host with a single NIC)"
        valid_ifname "$HV_LAN_IF" || die "invalid HV_LAN_IF: $HV_LAN_IF"
        valid_network 4 "$HV_LAN_NET" \
            || die "invalid HV_LAN_NET (a network address is required, e.g. 192.168.10.0/24; set HV_SINGLE_NIC=1 for a host with a single NIC): $HV_LAN_NET"
        [ "$HV_LAN_IF" != "$HV_WAN_IF" ] \
            || die "HV_LAN_IF and HV_WAN_IF cannot be the same"
    fi

    valid_network 4 "$HV_PORTAL_NET" \
        || die "invalid HV_PORTAL_NET (an IPv4 CIDR is required, e.g. 0.0.0.0/0): $HV_PORTAL_NET"
    valid_port "$PORT" || die "invalid PORT: $PORT"
    valid_port "$HV_DROP_LOG_GROUP" \
        || die "invalid HV_DROP_LOG_GROUP (1–65535): $HV_DROP_LOG_GROUP"
    case "$HV_FWD_MARK" in
        0x[0-9A-Fa-f]*) ;;
        *) die "invalid HV_FWD_MARK (expected a hex number starting with 0x): $HV_FWD_MARK" ;;
    esac
    [ "${#HV_FWD_MARK}" -le 10 ] \
        || die "invalid HV_FWD_MARK (must be a 32-bit hex number): $HV_FWD_MARK"

    # The portal and the drop-log listener read the same value.
    export HV_FWD_MARK HV_DROP_LOG_GROUP

    # The proxy 80/443 accept rules only live when HV_PROXY=1;
    # otherwise they remain as comments in the filled-in file.
    if [ "$(env_bool HV_PROXY 0)" = "1" ]; then
        HV_PROXY_PREFIX=""
    else
        HV_PROXY_PREFIX="# "
    fi

    # If /run is not writable (e.g. read-only root without tmpfs), /tmp is
    # the fallback. The compose configuration provides both as tmpfs.
    RENDERED=${HV_NFT_FILE:-/run/dropjak.nft}
    if ! ( : >"$RENDERED" ) 2>/dev/null; then
        RENDERED=/tmp/dropjak.nft
    fi

    # __LANONLY__ must be substituted first: it selects whether the marked
    # lines become comments. The other substitutions also run on commented
    # lines, so no placeholder may remain in either mode.
    sed \
        -e "s|__LANONLY__|$LAN_PREFIX|g" \
        -e "s|__LAN_IF__|$HV_LAN_IF|g" \
        -e "s|__WAN_IF__|$HV_WAN_IF|g" \
        -e "s|__LAN_NET__|$HV_LAN_NET|g" \
        -e "s|__PORTAL_NET__|$HV_PORTAL_NET|g" \
        -e "s|__PORT__|$PORT|g" \
        -e "s|__FWD_MARK__|$HV_FWD_MARK|g" \
        -e "s|__DROP_LOG_GROUP__|$HV_DROP_LOG_GROUP|g" \
        -e "s|__PROXY__|$HV_PROXY_PREFIX|g" \
        "$TEMPLATE" >"$RENDERED" || die "cannot fill in the rule template"

    chmod 0600 "$RENDERED" || true
    if grep -Eq '__[A-Z0-9_]+__' "$RENDERED"; then
        die "a placeholder remained in the filled-in rule file"
    fi
    log "rule file ready: $RENDERED"
}

detect_bridges() {
    # Prints the host's bridge interfaces, space separated, except the LAN
    # and WAN interfaces themselves (a bridged LAN or WAN must keep its
    # normal forwarding). Docker networks with a custom
    # com.docker.network.bridge.name do not match docker*/br-*, so the
    # forward chain also needs their names. Without the ip tool the list is
    # empty and only the name patterns apply.
    command -v ip >/dev/null 2>&1 || return 0
    ip -o link show type bridge 2>/dev/null | while IFS= read -r _line; do
        _name=${_line#*: }
        _name=${_name%%:*}
        _name=${_name%%@*}
        [ "$_name" != "${HV_LAN_IF:-}" ] || continue
        [ "$_name" != "${HV_WAN_IF:-}" ] || continue
        valid_ifname "$_name" || continue
        printf '%s\n' "$_name"
    done | sort -u | tr '\n' ' ' | sed 's/ *$//'
}

DOCKER_BRIDGES=""
DOCKER_BRIDGES_APPLIED="-"

sync_docker_bridges() {
    # Fills the docker_bridges set (forward chain: a new flow into a bridge
    # needs DNAT). $1 = force rewrites it even if the list is unchanged, for
    # example after a template reload left the set empty. Flush and add run
    # in one nft transaction, so there is no moment without the old names.
    _bridges=$(detect_bridges)
    if [ "${1:-}" != "force" ] && [ "$_bridges" = "$DOCKER_BRIDGES_APPLIED" ]; then
        return 0
    fi
    _elements=""
    for _br in $_bridges; do
        _elements="${_elements:+$_elements, }\"$_br\""
    done
    if ! {
        printf 'flush set inet hatarvedelem docker_bridges\n'
        if [ -n "$_elements" ]; then
            printf 'add element inet hatarvedelem docker_bridges { %s }\n' "$_elements"
        fi
    } | "$NFT_BIN" -f -; then
        log "WARNING: cannot update the docker_bridges set; the docker*/br-* patterns still apply"
        return 1
    fi
    DOCKER_BRIDGES=$_bridges
    DOCKER_BRIDGES_APPLIED=$_bridges
    log "container bridges that need DNAT for new flows: docker*, br-*$(printf '%s' "$_bridges" | sed 's/ /, /g; s/^./, &/')"
    return 0
}

DOCKER_GUARD_PROBLEM=""

docker_forward_guard() {
    # Docker's ip filter FORWARD chain would pass traffic with its own rules
    # (for example the published container ports) even if our inet table
    # disappeared. Therefore on the official DOCKER-USER chain we drop EVERY
    # forwarded packet except the one marked by the inet hatarvedelem forward
    # chain. The mark is only put on the packet if our rules actually ran and
    # permitted it.
    # Returns 1 with the reason in DOCKER_GUARD_PROBLEM when no guard can be
    # installed; the caller logs it. That is never fatal: stopping the
    # container would leave the host in a crash loop behind the boot table.
    DOCKER_GUARD_PROBLEM=""
    DOCKER_USER=$("$NFT_BIN" list chain ip filter DOCKER-USER 2>/dev/null || true)
    if [ -z "$DOCKER_USER" ]; then
        if "$NFT_BIN" list table ip docker-bridges >/dev/null 2>&1; then
            DOCKER_GUARD_PROBLEM="Docker uses its nftables firewall backend, which has no DOCKER-USER chain"
        else
            DOCKER_GUARD_PROBLEM="the Docker DOCKER-USER chain (ip filter) is missing"
        fi
        return 1
    fi
    # The list of old rules is taken before insertion; the handles remain valid
    # after insertion.
    OLD_RULES=$("$NFT_BIN" -a list chain ip filter DOCKER-USER 2>/dev/null || true)

    # The guard is added to the chain as early as possible: the old broad accepts
    # can then only match the marked packets.
    if ! "$NFT_BIN" insert rule ip filter DOCKER-USER \
            meta mark != "$HV_FWD_MARK" drop \
            comment '"hv-docker-fwd-guard"'; then
        DOCKER_GUARD_PROBLEM="cannot insert the DOCKER-USER drop rule"
        return 1
    fi
    # A marked packet is accepted here only if it does not leave through a
    # container bridge (docker*, br-* and the detected custom bridges).
    # Toward a bridge it continues to Docker's own rules (published-port
    # DNAT, isolation, Docker 28's block of unpublished ports); an accept
    # here would skip them. A plain return for every marked packet would not
    # work: Docker's FORWARD chain has no rule for LAN->WAN traffic, and its
    # policy is drop.
    set -- meta mark "$HV_FWD_MARK" oifname != '"docker*"' oifname != '"br-*"'
    for _br in $DOCKER_BRIDGES; do
        case "$_br" in
            docker* | br-*) ;;
            *) set -- "$@" oifname != "\"$_br\"" ;;
        esac
    done
    if ! "$NFT_BIN" insert rule ip filter DOCKER-USER \
            "$@" accept comment '"hv-docker-fwd-mark"'; then
        DOCKER_GUARD_PROBLEM="cannot insert the DOCKER-USER accept rule for marked packets"
        return 1
    fi
    # Logging only: sends unmarked (i.e. to-be-dropped) packets
    # to NFLOG. If logging cannot be set up, protection still
    # works, so this is not a fatal error.
    if ! "$NFT_BIN" insert rule ip filter DOCKER-USER \
            meta mark != "$HV_FWD_MARK" \
            limit rate 30/minute burst 60 packets \
            log prefix '"dropjak-drop reason=docker-guard "' \
            group "$HV_DROP_LOG_GROUP" \
            comment '"hv-docker-fwd-log"'; then
        log "WARNING: cannot set up logging of the Docker guard drop"
    fi

    # The previous (broad) bridging rules can now be safely
    # dropped.
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
    # The policy drop is the second line of defense in case the DOCKER-USER
    # chain is left out of the traffic path for some reason.
    if ! "$NFT_BIN" add chain ip filter FORWARD '{ policy drop; }'; then
        log "WARNING: failed to set policy drop on the Docker FORWARD chain"
    fi
    log "Docker forward protection configured (only marked packets may pass)"
    return 0
}

log_guard_error() {
    log "ERROR: Docker forward protection is NOT installed: $DOCKER_GUARD_PROBLEM. Published container ports are guarded only by the inet hatarvedelem table; if that table disappears, Docker's own rules pass them. The portal keeps running; the watchdog retries every 5 seconds and repeats this error every minute until the guard is in place (Docker iptables backend with DOCKER-USER)."
}

start_firewall_watchdog() {
    [ "$(env_bool HV_FIREWALL_WATCHDOG 1)" = "1" ] || return 0
    (
        guard_error_at=0
        while :; do
            sleep 5
            reloaded=0
            forward=$("$NFT_BIN" list chain inet hatarvedelem forward 2>/dev/null || true)
            case "$forward" in
                *"policy drop"*) ;;
                *) forward="" ;;
            esac
            # @allowed_tcp exists in both modes; @client_mac does not in
            # single-NIC mode (its rules are comments there).
            if [ -z "$forward" ] || ! printf '%s' "$forward" | grep -q '@allowed_tcp'; then
                log "WARNING: the Dropjak forward chain is incomplete; reloading"
                if "$NFT_BIN" -c -f "$RENDERED" && "$NFT_BIN" -f "$RENDERED"; then
                    # The reload restores only the template. The portal
                    # notices the new table within seconds and refills the
                    # block/pre-auth chains, bans and host guards
                    # (Gateway.check_firewall_state); until then it issues
                    # no new grant.
                    log "firewall reloaded"
                    reloaded=1
                else
                    log "ERROR: firewall reload failed"
                fi
            fi
            # New or removed bridges (docker network create/rm), and the
            # empty set after a reload.
            bridges_before=$DOCKER_BRIDGES_APPLIED
            if [ "$reloaded" = "1" ]; then
                sync_docker_bridges force || true
            else
                sync_docker_bridges || true
            fi
            if [ "$reloaded" = "1" ] \
                    || [ "$DOCKER_BRIDGES_APPLIED" != "$bridges_before" ] \
                    || ! "$NFT_BIN" list chain ip filter DOCKER-USER 2>/dev/null \
                        | grep -q 'hv-docker-fwd-guard'; then
                if ! docker_forward_guard; then
                    # Loud, but at most once a minute; every round retries.
                    now=$(date +%s)
                    if [ $((now - guard_error_at)) -ge 60 ]; then
                        log_guard_error
                        guard_error_at=$now
                    fi
                fi
            fi
        done
    ) &
    log "firewall watchdog started (5 seconds)"
}

warn_lockout() {
    # Loading the firewall takes effect immediately: host SSH remains reachable only
    # from the same source IP that has an active, authorized portal session, and the
    # session uses a host (input) rule assigned to the user that explicitly allows
    # TCP port 22. There is no built-in admin rule.
    log "WARNING: after loading the firewall, host SSH (22/TCP) is reachable only from the same source IP that has an active, authorized portal session and a host rule assigned to the user that explicitly allows TCP port 22."
    log "WARNING: if you start Dropjak over SSH, loading the firewall may drop the current SSH connection."
    log "WARNING: keep the provider (out-of-band) console open so you can restore access if you are locked out."
    # We accept the same true values as gateway.py's
    # _env_bool() function (1, true, yes, on; case-insensitive).
    admin_enabled=$(
        printf '%s' "${HV_ADMIN_ENABLED:-}" \
            | tr '[:upper:]' '[:lower:]' \
            | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
    )
    case "$admin_enabled" in
        1 | true | yes | on) admin_enabled=1 ;;
        *) admin_enabled=0 ;;
    esac
    if [ "$admin_enabled" -ne 1 ] \
            || { [ -z "${HV_ADMIN_PASSWORD:-}" ] \
                 && [ -z "${HV_ADMIN_PASSWORD_FILE:-}" ]; }; then
        log "WARNING: no startup admin credentials are configured (HV_ADMIN_ENABLED=1/true/yes/on and HV_ADMIN_PASSWORD or HV_ADMIN_PASSWORD_FILE are required)."
        log "WARNING: if, in addition, no admin account exists, you cannot log in to the portal, and host SSH stays closed. Set these in the .env file first, or create an admin account with the CLI."
    fi
}

ensure_boot_guard() {
    # Between deleting the old table and loading the new one, the host may only be
    # under the early boot protection (fail-closed).
    if "$NFT_BIN" list table inet hatarvedelem_boot >/dev/null 2>&1; then
        return 0
    fi
    [ -r "$BOOT_NFT" ] \
        || die "early boot protection not found ($BOOT_NFT); the old nft table cannot be deleted safely"
    "$NFT_BIN" -f "$BOOT_NFT" \
        || die "loading the early boot protection failed: $BOOT_NFT"
    log "early boot protection loaded for rebuilding the old nft table"
}

# Because of the 3.14.0 interval flags, the old sets cannot be updated in place
# (the flag of an existing set cannot be changed, and the referenced set cannot
# be deleted). Therefore we delete the existing table under the early boot
# protection BEFORE validating the rule file: with the old sets `nft -c`
# would fail with an "existing set lacks interval flag" error, and the container
# would enter a crash loop while the input chain stands without rules, with a
# policy drop. The host_service_* guard ports are saved first, so that existing
# host connections do not stay open after the upgrade.
migrate_interval_sets() {
    migrated=0
    saved_tcp=""
    saved_udp=""
    for hv_set in allowed_tcp allowed_udp allowed_input_tcp \
            allowed_input_udp host_service_tcp host_service_udp; do
        if "$NFT_BIN" list set inet hatarvedelem "$hv_set" 2>/dev/null \
                | grep -q 'flags interval'; then
            continue
        fi
        if "$NFT_BIN" list set inet hatarvedelem "$hv_set" >/dev/null 2>&1; then
            migrated=1
        fi
    done
    [ "$migrated" = "1" ] || return 0
    ensure_boot_guard
    saved_tcp=$("$NFT_BIN" -j list set inet hatarvedelem host_service_tcp \
        2>/dev/null | "$PYTHON" -c "$HOST_PORTS_JSON" 2>/dev/null || true)
    saved_udp=$("$NFT_BIN" -j list set inet hatarvedelem host_service_udp \
        2>/dev/null | "$PYTHON" -c "$HOST_PORTS_JSON" 2>/dev/null || true)
    log "due to the old nft set flags, the Dropjak table is rebuilt"
    "$NFT_BIN" delete table inet hatarvedelem \
        || die "deleting the old nft table failed; the early boot protection remained in effect"
}

load_firewall() {
    NFT_BIN=${HV_NFT_BIN:-}
    if [ -z "$NFT_BIN" ]; then
        NFT_BIN=$(command -v nft 2>/dev/null || true)
    fi
    [ -n "$NFT_BIN" ] || NFT_BIN=/usr/sbin/nft
    [ -x "$NFT_BIN" ] || die "nft not found (HV_NFT_BIN=$NFT_BIN)"
    export HV_NFT_BIN="$NFT_BIN"

    render_ruleset

    # The migration check and deletion of the old table run BEFORE `nft -c`,
    # otherwise validation would fail because of the old set flags.
    migrate_interval_sets

    log "validating rules"
    if ! "$NFT_BIN" -c -f "$RENDERED"; then
        if [ "$migrated" = "1" ]; then
            die "the nftables rules are invalid; the old table has already been deleted, the early boot protection remained in effect (fail-closed)"
        fi
        die "the nftables rules are invalid"
    fi

    log "loading rules (host network namespace)"
    if ! "$NFT_BIN" -f "$RENDERED"; then
        if [ "$migrated" = "1" ]; then
            die "loading the rules failed; the early boot protection remained in effect (fail-closed)"
        fi
        die "loading the rules failed"
    fi
    if [ -n "$saved_tcp" ]; then
        "$NFT_BIN" add element inet hatarvedelem host_service_tcp \
            "{ $saved_tcp }" \
            || log "WARNING: restoring the old host_service_tcp ports failed"
    fi
    if [ -n "$saved_udp" ]; then
        "$NFT_BIN" add element inet hatarvedelem host_service_udp \
            "{ $saved_udp }" \
            || log "WARNING: restoring the old host_service_udp ports failed"
    fi
    "$NFT_BIN" list table inet hatarvedelem >/dev/null 2>&1 \
        || die "the Dropjak table was not created"

    # On restart, permissions left in the kernel must not remain in effect
    # after the boot protection is removed. The portal also clears the set, but
    # this way no one stays open during the short handover window either.
    #
    # HV_FLUSH_ON_START uses the same interpretation as
    # gateway.py (1/true/yes/on). If disabled, the default safe
    # behavior is to reconcile (flush) orphaned grants; only the explicit,
    # unsafe HV_ALLOW_STALE_GRANTS_ON_START=1 opt-in
    # allows the previous grants to stay alive until the kernel TTL.
    flush_on_start=$(env_bool HV_FLUSH_ON_START 1)
    allow_stale_grants=$(env_bool HV_ALLOW_STALE_GRANTS_ON_START 0)
    log "effective value of HV_FLUSH_ON_START: $flush_on_start"
    if [ "$flush_on_start" != "1" ] && [ "$allow_stale_grants" = "1" ]; then
        log "WARNING: HV_FLUSH_ON_START is disabled, and HV_ALLOW_STALE_GRANTS_ON_START=1 is set. The previous process's permissions left in the kernel may remain in effect until the TTL (up to 30 days), without a session!"
    else
        if [ "$flush_on_start" != "1" ]; then
            log "WARNING: HV_FLUSH_ON_START is disabled, but orphaned grants must not remain in the kernel; the dynamic sets are aligned to the in-memory (empty) session table."
        fi
        for hv_set in allowed_v4 allowed_tcp allowed_udp \
                allowed_input_tcp allowed_input_udp allowed_icmp \
                client_mac banned_v4; do
            "$NFT_BIN" flush set inet hatarvedelem "$hv_set" \
                || die "failed to flush set $hv_set"
        done
        log "dynamic sets flushed (HV_FLUSH_ON_START=$flush_on_start)"
    fi

    # The host_ssh_v4 set from earlier versions is no longer part of the template.
    # The old accept rule is removed by reloading the template's input chain (flush
    # chain input), so the remaining set is harmless; still, we delete it
    # for hygiene. Its absence is not an error.
    if "$NFT_BIN" list set inet hatarvedelem host_ssh_v4 >/dev/null 2>&1; then
        if "$NFT_BIN" delete set inet hatarvedelem host_ssh_v4; then
            log "old host_ssh_v4 set deleted"
        else
            # The new rule set is already loaded and the grants are flushed:
            # startup must not stop here, otherwise the firewall would be live but the
            # portal would not start, and SSH would stay closed from outside.
            # The set no longer grants access alongside the new input chain.
            log "WARNING: deleting the old host_ssh_v4 set failed; alongside the loaded input chain the set no longer grants access, the portal continues to start."
        fi
    fi

    # The fallback table loaded early on the host is no longer needed: the final
    # rules protect the forward chain. If there is none, this is not an error.
    if "$NFT_BIN" list table inet hatarvedelem_boot >/dev/null 2>&1; then
        "$NFT_BIN" delete table inet hatarvedelem_boot
        log "the early boot protection has handed over to the final rules"
    fi

    sync_docker_bridges force || true
    # Never fatal (see docker_forward_guard); the watchdog keeps retrying
    # and repeats the error every minute.
    docker_forward_guard || log_guard_error

    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != "1" ]; then
        if (echo 1 >/proc/sys/net/ipv4/ip_forward) 2>/dev/null; then
            log "net.ipv4.ip_forward enabled"
        else
            log "WARNING: net.ipv4.ip_forward is not enabled."
            log "         On the host: sysctl -w net.ipv4.ip_forward=1"
        fi
    fi
}

# ------------------------------------------------------------------------ main

ensure_state_dir
ensure_tunnel_run_dir
ensure_caddy_admin_dir
stage_admin_secret
export HV_STATE_DIR="$STATE_DIR"

# Custom command (e.g. user management): we do not touch the firewall.
if [ "$#" -gt 0 ]; then
    run_as_app "$@"
fi

check_proxy_key

skip_firewall=$(env_bool HV_SKIP_FIREWALL 0)
if [ "$skip_firewall" = "1" ]; then
    log "WARNING: loading the firewall rules skipped (HV_SKIP_FIREWALL=$skip_firewall)"
else
    warn_lockout
    load_firewall
    start_firewall_watchdog
fi

if [ -z "${HV_CONNTRACK_BIN:-}" ]; then
    CONNTRACK=$(command -v conntrack 2>/dev/null || true)
    [ -n "$CONNTRACK" ] && export HV_CONNTRACK_BIN="$CONNTRACK"
fi

log "starting portal on port ${PORT:-8100}"
run_as_app "$PYTHON" "$APP_DIR/server.py"
