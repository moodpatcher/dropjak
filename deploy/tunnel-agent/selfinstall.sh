#!/bin/sh
# Dropjak home tunnel agent - self-extracting installer.
#
# Single file: the tar.gz package (agent.json, sources) is appended at the end.
# Usage:  sudo sh dropjak-agent-<id>.sh             # install/update
#         sudo sh dropjak-agent-<id>.sh delete      # remove the container
#         (also accepts --delete or -d)
#
# The installer is idempotent. Run as root it installs into its own root-owned
# directory, /opt/dropjak-agent/<container name> (DROPJAK_DIR overrides it; an
# earlier install in the current directory is updated in place). Rootless, it
# installs into the current directory. A group- or world-writable directory,
# or one owned by another user, is refused. On a TTY it asks for the network interactively from a numbered
# list, and the agent joins EXACTLY ONE network: the one selected. It never
# joins multiple networks. It can reach only containers on that network, by
# container name (DNS), like the playit.gg agent. In non-interactive use
# (stdin is not a TTY, or DROPJAK_NO_PROMPT=1) it uses DROPJAK_NETWORK if set,
# otherwise the default network (playitgg-net if present; otherwise the playit
# container's network). If there is no bridge network, it asks for
# DROPJAK_NETWORK=<network>.

set -eu

MARKER='__DROPJAK_PAYLOAD__'

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

if [ "$(id -u)" -ne 0 ]; then
    if ! docker info >/dev/null 2>&1; then
        printf '%s\n' "Administrator privileges are required (sudo); restarting." >&2
        # $PWD after sudo is not guaranteed, so pass it through. DROPJAK_DIR
        # is passed only if the user set it: otherwise root picks its own
        # fixed directory.
        exec sudo env DROPJAK_PWD="$PWD" \
            ${DROPJAK_DIR:+DROPJAK_DIR="$DROPJAK_DIR"} \
            ${DROPJAK_NETWORK:+DROPJAK_NETWORK="$DROPJAK_NETWORK"} \
            ${DROPJAK_NO_PROMPT:+DROPJAK_NO_PROMPT="$DROPJAK_NO_PROMPT"} \
            sh "$0" "$@"
    fi
fi
# The directory the installer was started from; the install directory is
# chosen once the bundled agent.json names the agent (see choose_install_dir).
ORIG_PWD="${DROPJAK_PWD:-${PWD:-.}}"
DIR="${DROPJAK_DIR:-$ORIG_PWD}"
# Keep an absolute installer path for the delete hint printed after install.
SCRIPT_PATH=$0
case "$SCRIPT_PATH" in
    /*) ;;
    *) SCRIPT_PATH="$PWD/$SCRIPT_PATH" ;;
esac

# First argument: delete/uninstall action (never installs, never picks a
# network). No argument means install/update.
ACTION=install
case "${1:-}" in
    delete|--delete|-d) ACTION=delete ;;
    '') ;;
    *) die "unknown argument: $1 (supported: delete, --delete, -d)" ;;
esac

if ! command -v docker >/dev/null 2>&1; then
    printf '%s\n' "Error: Docker is not installed." \
        "Install it (https://docs.docker.com/engine/install/), then run again." >&2
    exit 1
fi

# --- Agent container name -------------------------------------------------
# The container name is derived from the bundled agent.json:
#   dropjak-tunnel-agent-<label-slug>-<id>
# The label keeps the container recognisable, the id keeps it unique when two
# agents share a label. The slug is lowercase ASCII; Hungarian accents are
# transliterated, other characters collapse to "-", and the whole name is at
# most 63 characters. Without an id/label we keep the legacy fixed name.
json_agent_field() {
    # Print one direct string field of the "agent" object in agent.json.
    # Pure awk so the installer does not depend on jq or python.
    _json_file=$1
    _json_key=$2
    [ -f "$_json_file" ] || return 0
    LC_ALL=C awk -v want="$_json_key" '
    function skipws() {
        while (i <= n) {
            c = substr(s, i, 1)
            if (c == " " || c == "\t" || c == "\n" || c == "\r") i++
            else return
        }
    }
    function readstr(   out, c, e) {
        i++
        out = ""
        while (i <= n) {
            c = substr(s, i, 1)
            if (c == "\\") {
                i++
                e = substr(s, i, 1)
                if (e == "n") out = out "\n"
                else if (e == "t") out = out "\t"
                else if (e == "r") out = out "\r"
                else out = out e
                i++
            } else if (c == "\"") {
                i++
                return out
            } else {
                out = out c
                i++
            }
        }
        return out
    }
    function skipval(   c, depth) {
        skipws()
        if (i > n) return
        c = substr(s, i, 1)
        if (c == "\"") { readstr(); return }
        if (c == "{" || c == "[") {
            depth = 0
            while (i <= n) {
                c = substr(s, i, 1)
                if (c == "\"") { readstr(); continue }
                if (c == "{" || c == "[") depth++
                else if (c == "}" || c == "]") {
                    depth--
                    if (depth == 0) { i++; return }
                }
                i++
            }
            return
        }
        while (i <= n) {
            c = substr(s, i, 1)
            if (c == "," || c == "}" || c == "]" || c == " " ||
                    c == "\t" || c == "\n" || c == "\r") return
            i++
        }
    }
    BEGIN { RS = "\001" }
    {
        s = $0
        n = length(s)
        i = index(s, "\"agent\"")
        if (i == 0) exit
        i += 7
        skipws()
        if (substr(s, i, 1) != ":") exit
        i++
        skipws()
        if (substr(s, i, 1) != "{") exit
        i++
        while (i <= n) {
            skipws()
            if (substr(s, i, 1) == "}") exit
            if (substr(s, i, 1) != "\"") exit
            key = readstr()
            skipws()
            if (substr(s, i, 1) != ":") exit
            i++
            skipws()
            if (substr(s, i, 1) == "\"") {
                val = readstr()
            } else {
                skipval()
                val = ""
            }
            if (key == want) {
                print val
                exit
            }
            skipws()
            if (substr(s, i, 1) == ",") i++
            else if (substr(s, i, 1) != "}") exit
        }
    }
    ' "$_json_file"
}

slugify_label() {
    printf '%s' "${1:-}" | LC_ALL=C sed \
        -e 's/Á/a/g' -e 's/á/a/g' \
        -e 's/É/e/g' -e 's/é/e/g' \
        -e 's/Í/i/g' -e 's/í/i/g' \
        -e 's/Ó/o/g' -e 's/ó/o/g' \
        -e 's/Ö/o/g' -e 's/ö/o/g' \
        -e 's/Ő/o/g' -e 's/ő/o/g' \
        -e 's/Ú/u/g' -e 's/ú/u/g' \
        -e 's/Ü/u/g' -e 's/ü/u/g' \
        -e 's/Ű/u/g' -e 's/ű/u/g' \
        | LC_ALL=C tr '[:upper:]' '[:lower:]' \
        | LC_ALL=C sed -e 's/[^a-z0-9][^a-z0-9]*/-/g' \
            -e 's/^-//' -e 's/-$//'
}

container_name_from_parts() {
    _cn_label=${1:-}
    _cn_id=${2:-}
    _cn_prefix=dropjak-tunnel-agent
    if [ -z "$_cn_id" ]; then
        printf '%s\n' "$_cn_prefix"
        return 0
    fi
    _cn_slug=$(slugify_label "$_cn_label")
    if [ -n "$_cn_slug" ]; then
        # prefix + "-" + slug + "-" + id must stay within 63 characters.
        _cn_max=$((63 - ${#_cn_prefix} - 2 - ${#_cn_id}))
        [ "$_cn_max" -ge 1 ] || _cn_max=1
        _cn_slug=$(printf '%s' "$_cn_slug" | cut -c1-"$_cn_max" \
            | sed 's/-*$//')
    fi
    if [ -n "$_cn_slug" ]; then
        _cn_name="$_cn_prefix-$_cn_slug-$_cn_id"
    else
        _cn_name="$_cn_prefix-$_cn_id"
    fi
    printf '%s\n' "$_cn_name" | cut -c1-63 | sed 's/-*$//'
}

container_name_from_json() {
    _cn_json_id=$(json_agent_field "$1" id)
    _cn_json_label=$(json_agent_field "$1" label)
    container_name_from_parts "$_cn_json_label" "$_cn_json_id"
}

# Resolve the name for the delete action. Prefer the file written at install
# time, then the bundled agent.json; empty means "legacy fixed name".
resolve_container_name() {
    _rcn_name=""
    if [ -f "$DIR/container-name" ]; then
        _rcn_name=$(sed -n '1p' "$DIR/container-name" 2>/dev/null \
            | tr -d '[:space:]' || true)
    fi
    if [ -z "$_rcn_name" ] && [ -f "$DIR/agent.json" ]; then
        _rcn_name=$(container_name_from_json "$DIR/agent.json")
    fi
    printf '%s\n' "$_rcn_name"
}

# On a TTY, offer the action as a small numbered menu. Non-interactive runs
# (or DROPJAK_NO_PROMPT=1) go straight to install and never prompt.
select_action_interactively() {
    printf '%s\n' "Choose an action:"
    printf '%s\n' \
        "  1) Install/update (default)" \
        "  2) Delete container"
    _attempt=1
    while [ "$_attempt" -le 3 ]; do
        printf 'Action [1-2] (default: 1): '
        if ! read -r _answer; then
            _answer=""
        fi
        _answer=$(printf '%s' "$_answer" \
            | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        case "$_answer" in
            ''|1)
                ACTION=install
                return 0
                ;;
            2)
                ACTION=delete
                return 0
                ;;
            *)
                printf 'Error: invalid choice: "%s". Enter 1 or 2.\n' \
                    "$_answer" >&2
                ;;
        esac
        _attempt=$((_attempt + 1))
    done
    die "stopping after 3 invalid answers. Run with 'delete' to remove the container."
}

# Remove the agent container. The name comes from container-name/agent.json
# in the install directory; the legacy fixed name is always tried as a
# fallback so old installs can still be deleted. Prefer compose down (named
# volumes, including agent-state, are kept because -v is not passed); fall
# back to docker rm -f.
# Idempotent: if there is nothing to remove, print a clear line and exit 0.
delete_agent() {
    _derived=$(resolve_container_name)
    _names=""
    if [ -n "$_derived" ]; then
        _names=$_derived
    fi
    case " $_names " in
        *" dropjak-tunnel-agent "*) ;;
        *) _names="${_names:+$_names }dropjak-tunnel-agent" ;;
    esac
    _display=${_derived:-dropjak-tunnel-agent}

    _had=0
    for _candidate in $_names; do
        if docker inspect "$_candidate" >/dev/null 2>&1; then
            _had=1
            break
        fi
    done

    if [ -f "$DIR/compose.yml" ] \
            && docker compose version >/dev/null 2>&1; then
        if docker compose -f "$DIR/compose.yml" down --remove-orphans; then
            _remaining=0
            for _candidate in $_names; do
                if docker inspect "$_candidate" >/dev/null 2>&1; then
                    _remaining=1
                fi
            done
            if [ "$_remaining" -eq 0 ]; then
                if [ "$_had" -eq 1 ]; then
                    printf 'The Dropjak tunnel agent container (%s) has been removed.\n' \
                        "$_display"
                else
                    printf 'No Dropjak tunnel agent container is running; nothing to delete.\n'
                fi
                return 0
            fi
        fi
    fi

    # Compose was unavailable (or did not remove every matching name): remove
    # the derived name and/or the legacy fixed name directly.
    _removed=0
    _failed=0
    _failed_name=""
    for _candidate in $_names; do
        if docker inspect "$_candidate" >/dev/null 2>&1; then
            if docker rm -f "$_candidate" >/dev/null 2>&1; then
                _removed=1
            else
                _failed=1
                _failed_name=$_candidate
            fi
        fi
    done
    if [ "$_failed" -eq 1 ] && [ "$_removed" -eq 0 ]; then
        die "could not remove container $_failed_name"
    fi
    if [ "$_removed" -eq 1 ]; then
        printf 'The Dropjak tunnel agent container (%s) has been removed.\n' \
            "$_display"
        return 0
    fi
    printf 'No Dropjak tunnel agent container is running; nothing to delete.\n'
    return 0
}

# --- Integrity, staging and the install directory -------------------------
# This file holds the agent's one-time enrollment token (a legacy bundle:
# its private key). Print its SHA-256 first, so the
# admin can match it against the value the Dropjak admin page showed for this
# download (verify with sha256sum before running, too).
INSTALLER_SHA256=$(sha256sum "$0" 2>/dev/null | cut -d' ' -f1 || true)
printf 'Installer SHA-256: %s\n' "${INSTALLER_SHA256:-unavailable}"

# The package is extracted into a private (0700) staging directory, never
# straight into the install directory; it is removed on every exit.
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/dropjak-agent.XXXXXX") \
    || die "cannot create a private staging directory"
trap 'rm -rf "$STAGE"' EXIT
trap 'exit 130' HUP INT TERM
PAYLOAD_LINE=$(grep -anm1 "^$MARKER\$" "$0" | cut -d: -f1)
PAYLOAD_LINE=$((PAYLOAD_LINE + 1))
tail -n +"$PAYLOAD_LINE" "$0" | tar -xz -C "$STAGE" \
    || die "the package at the end of this file is damaged"
if [ ! -f "$STAGE/agent.json" ] || [ -L "$STAGE/agent.json" ]; then
    die "the package does not contain agent.json."
fi

# The bundled configuration names this agent: the label makes the container
# recognisable on a host that runs more than one agent, the id keeps the name
# unique. The same value is written to container-name for the delete action
# and for check-containment.sh.
CONTAINER_NAME=$(container_name_from_json "$STAGE/agent.json")

# DROPJAK_DIR wins. An earlier install in the starting directory is updated
# in place (its container keeps its compose project). Otherwise root uses a
# fixed root-owned directory, and a rootless run the starting directory.
choose_install_dir() {
    if [ -n "${DROPJAK_DIR:-}" ]; then
        DIR=$DROPJAK_DIR
    elif [ -f "$ORIG_PWD/container-name" ] && [ -f "$ORIG_PWD/compose.yml" ]; then
        DIR=$ORIG_PWD
    elif [ "$(id -u)" -eq 0 ]; then
        DIR="${DROPJAK_BASE:-/opt/dropjak-agent}/$CONTAINER_NAME"
    else
        DIR=$ORIG_PWD
    fi
}

# Root writes the key and runs chmod/chown in this directory, so nobody else
# may be able to change it: no symlink, owned by root or the invoking user,
# no group or world write bit.
check_install_dir() {
    _cid=$1
    [ ! -L "$_cid" ] || die "refusing a symbolic link as install directory: $_cid"
    [ -e "$_cid" ] || return 0
    [ -d "$_cid" ] || die "the install path is not a directory: $_cid"
    _cid_owner=$(stat -c '%u' "$_cid" 2>/dev/null) \
        && _cid_mode=$(stat -c '%a' "$_cid" 2>/dev/null) \
        || die "cannot read the owner and mode of $_cid"
    case "$_cid_owner" in
        0|"${SUDO_UID:-$(id -u)}") ;;
        *) die "refusing $_cid: it is owned by another user (uid $_cid_owner)" ;;
    esac
    if [ $((0$_cid_mode & 022)) -ne 0 ]; then
        die "refusing $_cid: other users can write to it (mode $_cid_mode); use a private directory or DROPJAK_DIR"
    fi
}

choose_install_dir
check_install_dir "$DIR"

if [ "$ACTION" = "install" ] && [ -t 0 ] \
        && [ "${DROPJAK_NO_PROMPT:-0}" != "1" ]; then
    select_action_interactively
fi

if [ "$ACTION" = "delete" ]; then
    delete_agent
    exit 0
fi

# Installing needs the compose plugin; deleting does not (it has a fallback).
if ! docker compose version >/dev/null 2>&1; then
    printf '%s\n' "Error: the Docker Compose plugin is missing." \
        "Install the docker-compose-plugin package, then run again." >&2
    exit 1
fi

network_exists() {
    docker network inspect "$1" >/dev/null 2>&1
}

network_driver() {
    docker network inspect -f '{{.Driver}}' "$1" 2>/dev/null || true
}

# Accept only valid Docker network names, so the generated YAML is always
# correct and no line or structure can be injected.
valid_network_name() {
    case "$1" in
        ''|*[!A-Za-z0-9_.-]*) return 1 ;;
        [A-Za-z0-9]*) return 0 ;;
        *) return 1 ;;
    esac
}

# Names of running containers (used to count network membership).
running_container_names() {
    docker ps --format '{{.Names}}' 2>/dev/null || true
}

# Number of running containers attached to a network (informational, for the
# list).
network_container_count() {
    _net=$1
    _count=0
    for _cname in $(running_container_names); do
        _nets=$(docker inspect --format \
            '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' \
            "$_cname" 2>/dev/null || true)
        for _n in $_nets; do
            if [ "$_n" = "$_net" ]; then
                _count=$((_count + 1))
            fi
        done
    done
    printf '%s\n' "$_count"
}

# Networks of running playit.gg containers (the image name contains "playit"),
# filtered to the bridge driver, unique and sorted.
playit_bridge_networks() {
    docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null \
        | awk 'tolower($2) ~ /playit/ {print $1}' \
        | while IFS= read -r cname; do
            [ -n "$cname" ] || continue
            docker inspect --format \
                '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' \
                "$cname" 2>/dev/null || true
        done \
        | tr ' ' '\n' \
        | grep -E '^[A-Za-z0-9][A-Za-z0-9_.-]*$' \
        | sort -u \
        | while IFS= read -r net; do
            driver=$(network_driver "$net")
            case "$(printf '%s' "$driver" | tr '[:upper:]' '[:lower:]')" in
                bridge) printf '%s\n' "$net" ;;
            esac
        done
}

# All bridge-driver networks, sorted; playitgg-net first if it exists.
# host/none and every non-bridge network are excluded, and the list never
# contains an "all" or multi-select option.
collect_candidates() {
    _list=$(docker network ls --format '{{.Name}} {{.Driver}}' 2>/dev/null \
        | awk 'tolower($2) == "bridge" {print $1}' \
        | grep -E '^[A-Za-z0-9][A-Za-z0-9_.-]*$' \
        | sort -u || true)
    CANDIDATES=""
    if printf '%s\n' "$_list" | grep -qxF 'playitgg-net'; then
        CANDIDATES="playitgg-net"
        _others=$(printf '%s\n' "$_list" \
            | grep -vxF 'playitgg-net' || true)
        if [ -n "$_others" ]; then
            CANDIDATES="$CANDIDATES
$_others"
        fi
    else
        CANDIDATES=$_list
    fi
}

candidate_count() {
    _n=0
    for _item in ${CANDIDATES:-}; do
        _n=$((_n + 1))
    done
    printf '%s\n' "$_n"
}

candidate_contains() {
    [ -n "${CANDIDATES:-}" ] || return 1
    printf '%s\n' "$CANDIDATES" | grep -qxF -- "$1"
}

# Default network: playitgg-net if it exists; otherwise the running playit
# container's bridge network (the first sorted one if there are several);
# otherwise the first candidate. Always exactly one network.
default_network() {
    _default=""
    if candidate_contains playitgg-net; then
        _default=playitgg-net
    else
        for _net in $(playit_bridge_networks); do
            if candidate_contains "$_net"; then
                _default=$_net
                break
            fi
        done
    fi
    if [ -z "$_default" ]; then
        _default=$(printf '%s\n' "$CANDIDATES" | sed -n '1p')
    fi
    printf '%s\n' "$_default"
}

network_index() {
    _want=$1
    _i=0
    for _net in ${CANDIDATES:-}; do
        _i=$((_i + 1))
        if [ "$_net" = "$_want" ]; then
            printf '%s\n' "$_i"
            return 0
        fi
    done
    return 1
}

# Interactive selection: numbered list, empty answer = default.
# At most 3 attempts; after that stop with an error (never guess further).
select_network_interactively() {
    _total=$(candidate_count)
    _default=$(default_network)
    _default_index=$(network_index "$_default")
    printf '%s\n' \
        "Select a network (the agent will join exactly one network):"
    _i=0
    for _net in $CANDIDATES; do
        _i=$((_i + 1))
        _containers=$(network_container_count "$_net")
        if [ "$_containers" -eq 1 ]; then
            _unit=container
        else
            _unit=containers
        fi
        printf '  %s) %s (bridge, %s %s)\n' \
            "$_i" "$_net" "$_containers" "$_unit"
    done
    _attempt=1
    while [ "$_attempt" -le 3 ]; do
        printf 'Network [1-%s] (default: %s - %s): ' \
            "$_total" "$_default_index" "$_default"
        if ! read -r _answer; then
            _answer=""
        fi
        _answer=$(printf '%s' "$_answer" \
            | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        if [ -z "$_answer" ]; then
            NET=$_default
            NET_SOURCE="default"
            return 0
        fi
        case "$_answer" in
            *[!0-9]*)
                printf 'Error: invalid choice: "%s". Enter a number between 1 and %s, or leave it empty to accept the default (%s).\n' \
                    "$_answer" "$_total" "$_default" >&2
                ;;
            *)
                _num=$(printf '%s' "$_answer" | sed 's/^0*//')
                [ -n "$_num" ] || _num=0
                if [ "$_num" -ge 1 ] && [ "$_num" -le "$_total" ]; then
                    _i=0
                    for _net in $CANDIDATES; do
                        _i=$((_i + 1))
                        if [ "$_i" -eq "$_num" ]; then
                            NET=$_net
                            NET_SOURCE="interactive selection"
                            return 0
                        fi
                    done
                fi
                printf 'Error: invalid choice: %s. The number must be between 1 and %s, or leave it empty to accept the default (%s).\n' \
                    "$_answer" "$_total" "$_default" >&2
                ;;
        esac
        _attempt=$((_attempt + 1))
    done
    die "stopping after 3 invalid answers. Choose from the list, or specify explicitly: DROPJAK_NETWORK=<network> sh $0"
}

# Select exactly one network:
#   1. DROPJAK_NETWORK (explicit override; always wins, no question),
#   2. on a TTY, the interactive numbered list (with a default),
#   3. in non-interactive mode (not a TTY or DROPJAK_NO_PROMPT=1), the
#      default network,
#   4. if there is no bridge network: error.
# We never fall back to "bridge" and never join all of them.
NET=""
NET_SOURCE=""

if [ -n "${DROPJAK_NETWORK:-}" ]; then
    NET=$DROPJAK_NETWORK
    NET_SOURCE="DROPJAK_NETWORK"
    valid_network_name "$NET" \
        || die "the DROPJAK_NETWORK value is an invalid network name: $NET"
else
    collect_candidates
    if [ -z "${CANDIDATES:-}" ]; then
        die "no bridge network found in Docker. Specify explicitly: DROPJAK_NETWORK=<network> sh $0"
    fi
    if [ -t 0 ] && [ "${DROPJAK_NO_PROMPT:-0}" != "1" ]; then
        select_network_interactively
    else
        NET=$(default_network)
        NET_SOURCE="default (non-interactive)"
    fi
fi

network_exists "$NET" \
    || die "the selected network does not exist: $NET (source: $NET_SOURCE)"
NET_DRIVER=$(network_driver "$NET")
case "$(printf '%s' "$NET_DRIVER" | tr '[:upper:]' '[:lower:]')" in
    bridge) ;;
    host|none|null|'')
        die "the selected network driver is not bridge: $NET (${NET_DRIVER:-unknown})" ;;
    *)
        die "the selected network driver is not bridge: $NET ($NET_DRIVER)" ;;
esac

# Create the install directory (a fresh root directory is 0700) and check it
# again: it must still be private after mkdir.
if [ ! -e "$DIR" ]; then
    mkdir -p "$DIR"
    if [ "$(id -u)" -eq 0 ]; then
        chmod 0700 "$DIR"
    fi
fi
check_install_dir "$DIR"
# An earlier, interrupted compose run may have created agent.json as an empty
# directory; only a file may be there.
if [ -d "$DIR/agent.json" ]; then
    rmdir "$DIR/agent.json" 2>/dev/null \
        || die "$DIR/agent.json is a directory; remove it and run again"
fi

# Clean up an earlier version's installation: the multi-network model's
# reconcile helper and its 30-second timer must not remain on the host.
# Only the precisely named files are removed; if they are absent, continue
# silently.
cleanup_unit_dir() {
    _dir=$1
    _mode=$2
    [ -d "$_dir" ] || return 0
    _timer="$_dir/dropjak-agent-networks.timer"
    _service="$_dir/dropjak-agent-networks.service"
    [ -e "$_timer" ] || [ -e "$_service" ] || return 0
    if [ "${DROPJAK_NO_SYSTEMD:-0}" != "1" ] \
            && command -v systemctl >/dev/null 2>&1; then
        if [ "$_mode" = "user" ]; then
            systemctl --user disable --now dropjak-agent-networks.timer \
                >/dev/null 2>&1 || true
            systemctl --user daemon-reload >/dev/null 2>&1 || true
        else
            systemctl disable --now dropjak-agent-networks.timer \
                >/dev/null 2>&1 || true
            systemctl daemon-reload >/dev/null 2>&1 || true
        fi
    fi
    rm -f "$_timer" "$_service" 2>/dev/null || true
}

cleanup_legacy() {
    # Under sudo, also clean up the calling user's rootless installation.
    SUDO_HOME=""
    if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
        SUDO_HOME=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
    fi

    # Old helper files (both root and rootless locations).
    for helper in \
            "${DROPJAK_LIB_DIR:+$DROPJAK_LIB_DIR/reconcile-networks.sh}" \
            "/usr/local/lib/dropjak-agent/reconcile-networks.sh" \
            "${XDG_DATA_HOME:-${HOME:-/nonexistent}/.local/share}/dropjak-agent/reconcile-networks.sh" \
            "${HOME:-/nonexistent}/.local/share/dropjak-agent/reconcile-networks.sh" \
            "${SUDO_HOME:+$SUDO_HOME/.local/share/dropjak-agent/reconcile-networks.sh}"; do
        [ -n "$helper" ] || continue
        rm -f "$helper" 2>/dev/null || true
    done

    # Old systemd units (both system and user level).
    cleanup_unit_dir "/etc/systemd/system" system
    cleanup_unit_dir "${XDG_CONFIG_HOME:-${HOME:-/nonexistent}/.config}/systemd/user" user
    cleanup_unit_dir "${HOME:-/nonexistent}/.config/systemd/user" user
    if [ -n "$SUDO_HOME" ]; then
        cleanup_unit_dir "$SUDO_HOME/.config/systemd/user" user
    fi
    if [ -n "${DROPJAK_SYSTEMD_UNIT_DIR:-}" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            cleanup_unit_dir "$DROPJAK_SYSTEMD_UNIT_DIR" system
        else
            cleanup_unit_dir "$DROPJAK_SYSTEMD_UNIT_DIR" user
        fi
    fi
}

cleanup_legacy

# Generate the compose file: the agent is on exactly one network. The key is
# neutral (n1); the name: field carries the actual network name, so the YAML
# is valid even if a network name starts with a digit. The container name is
# derived from the bundled agent.json so several agents on one host can be
# told apart; each agent still needs its own install directory.
write_compose() {
    compose_tmp="$STAGE/compose.yml"
    {
        cat <<YAML
# Dropjak home tunnel agent - file generated by the installer.
# The agent is on exactly one network: $NET (the network selected in the
# installer). It can reach only containers on this network, by container
# name (DNS), so there is no host-gateway entry.
services:
  tunnel-agent:
    build: .
    image: dropjak-tunnel-agent:1
    container_name: $CONTAINER_NAME
    restart: unless-stopped
    networks:
      - n1
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /run
      - /tmp
    sysctls:
      # Under rootless Podman /proc/sys is read-only; the runtime sets it.
      net.ipv4.ip_forward: 1
    volumes:
      # The ,Z is required for volume labelling on SELinux hosts (RHEL/Fedora).
      - ./agent.json:/etc/dropjak/agent.json:ro,Z
      - agent-state:/var/lib/dropjak-agent

networks:
  n1:
    external: true
    name: "$NET"

volumes:
  agent-state:
YAML
    } > "$compose_tmp"
}

write_compose
if ! docker compose -f "$STAGE/compose.yml" config -q >/dev/null 2>&1; then
    printf 'Error: the generated compose.yml is invalid.\n' >&2
    exit 1
fi
# Remember the resolved name next to compose.yml: the delete action and
# check-containment.sh read it, so both use the same name without re-parsing
# agent.json.
printf '%s\n' "$CONTAINER_NAME" > "$STAGE/container-name"

# Owners and modes are set in the private staging directory; then each file
# is renamed into place. A rename replaces whatever is at the target path
# (even a symlink) instead of following it. The key is 0600.
for file in compose.yml container-name Dockerfile agent.py \
        check-containment.sh agent.json; do
    [ -e "$STAGE/$file" ] || continue
    if [ "$(id -u)" -eq 0 ]; then
        chown root:root "$STAGE/$file" || true
    fi
done
chmod 600 "$STAGE/agent.json"
chmod 644 "$STAGE/compose.yml" "$STAGE/container-name" "$STAGE/Dockerfile"
chmod 755 "$STAGE/agent.py" "$STAGE/check-containment.sh"
for file in compose.yml container-name Dockerfile agent.py \
        check-containment.sh agent.json; do
    [ -e "$STAGE/$file" ] || continue
    mv -f "$STAGE/$file" "$DIR/$file" \
        || die "cannot move $file into $DIR"
done

printf '%s\n' "Building and starting the agent: $CONTAINER_NAME ($DIR)"
cd "$DIR"
docker compose up -d --build

printf '\n%s\n' \
    "Done. Agent logs:  cd $DIR && docker compose logs -f" \
    "It will be online in the Dropjak admin Proxy and tunnels page within half a minute."
printf 'Agent container name: %s\n' "$CONTAINER_NAME"
printf 'The agent is on exactly one network: %s\n' "$NET"
printf '%s\n' \
    "It can reach only containers on this network; the target is the container" \
    "name and port on this network (e.g. purpur:25565)." \
    "No other network and no host gateway are reachable."
printf 'To check the container and the network:  sudo DROPJAK_CONTAINER=%s sh "%s/check-containment.sh"\n' \
    "$CONTAINER_NAME" "$DIR"
printf 'To delete the agent container (%s):  sudo sh "%s" delete\n' \
    "$CONTAINER_NAME" "$SCRIPT_PATH"
# A legacy bundle carries the agent's private key; a current one only a
# one-time enrollment token (the agent generates its own keys).
if grep -q '"private_key"' "$DIR/agent.json" 2>/dev/null; then
    printf '%s\n' \
        "This installer file contains the agent's private key. Delete it once you" \
        "no longer need it:  shred -u \"$SCRIPT_PATH\""
else
    printf '%s\n' \
        "The agent generates its own WireGuard keys and enrolls with the one-time" \
        "token in this installer file (valid for 30 minutes from its creation," \
        "single use). Delete the file once the agent is online:" \
        "  shred -u \"$SCRIPT_PATH\""
fi
printf '%s\n' \
    "Without it the agent is removed with:  sudo docker compose -f \"$DIR/compose.yml\" down"

exit 0
__DROPJAK_PAYLOAD__
