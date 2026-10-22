#!/bin/sh
# Dropjak home tunnel agent - network and container check.
#
# The agent is on exactly ONE network: the one the installer selected (by
# default the playit.gg agent's network, playitgg-net). It can reach only
# containers on that network, so there is nothing to "close" on the service
# side. This script verifies that
#   * the Dropjak tunnel agent container is running,
#   * it is connected to exactly one bridge network (zero or more is an error),
#   * the network is not host or none, and its driver is bridge,
#   * if DROPJAK_NETWORK is set, the connected network matches it,
#   * the host Docker socket is not mounted,
#   * the compose security settings (read-only rootfs, no-new-privileges,
#     cap_drop ALL, only NET_ADMIN) are in effect.
# It changes nothing.
#
# Usage:
#   sh deploy/tunnel-agent/check-containment.sh
#   DROPJAK_CONTAINER=dropjak-tunnel-agent-home-home-1 \
#       sh deploy/tunnel-agent/check-containment.sh
#   DROPJAK_NETWORK=playitgg-net sh deploy/tunnel-agent/check-containment.sh
#
# Environment:
#   DROPJAK_CONTAINER   container name. If unset, the script reads
#                       ./container-name when run from an install directory,
#                       otherwise it discovers containers whose name starts
#                       with dropjak-tunnel-agent. Exactly one match is
#                       required; with several, set DROPJAK_CONTAINER.
#   DROPJAK_NETWORK     expected network (if empty: accept the single
#                                         connected network)
#
# Exit: 0 = OK, 1 = mismatch, 2 = the check could not run.

set -u

CONTAINER=${DROPJAK_CONTAINER:-}
EXPECTED=${DROPJAK_NETWORK:-}
FAIL=0

pass() { printf 'ok   %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*" >&2; FAIL=1; }
fail() { printf 'FAIL %s\n' "$*" >&2; exit 2; }

command -v docker >/dev/null 2>&1 || fail "docker is required"

# Resolve the container name. Precedence: DROPJAK_CONTAINER, the
# container-name file of the current install directory, then discovery.
# Discovery by prefix is essential for the legacy installs and for the
# multi-agent case, where the prefix alone is ambiguous.
if [ -z "$CONTAINER" ] && [ -f ./container-name ]; then
    CONTAINER=$(sed -n '1p' ./container-name 2>/dev/null \
        | tr -d ' \t\r\n' || true)
fi
if [ -z "$CONTAINER" ]; then
    DISCOVERED=$(docker ps -a --format '{{.Names}}' 2>/dev/null \
        | grep -E '^dropjak-tunnel-agent' || true)
    DISCOVERED_COUNT=0
    for candidate in $DISCOVERED; do
        DISCOVERED_COUNT=$((DISCOVERED_COUNT + 1))
    done
    case "$DISCOVERED_COUNT" in
        0)
            fail "no container whose name starts with dropjak-tunnel-agent (install the agent first)"
            ;;
        1)
            CONTAINER=$DISCOVERED
            ;;
        *)
            fail "several Dropjak tunnel agent containers found: $(printf '%s\n' "$DISCOVERED" | tr '\n' ' '); set DROPJAK_CONTAINER=<name> to choose one"
            ;;
    esac
fi

docker inspect "$CONTAINER" >/dev/null 2>&1 || \
    fail "no such container: $CONTAINER (install the agent first)"

# Rootless Podman/Docker grants capabilities in its own user namespace and
# expands cap_drop: ALL to its base set; the check accounts for this so it
# does not report a false error.
ROOTLESS=0
if command -v podman >/dev/null 2>&1 \
        && [ "$(podman info --format '{{.Host.Security.Rootless}}' \
            2>/dev/null)" = "true" ]; then
    ROOTLESS=1
elif docker info 2>/dev/null | grep -qi 'rootless'; then
    ROOTLESS=1
fi

RUNNING=$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)
[ "$RUNNING" = "true" ] || fail "$CONTAINER is not running"

ATTACHED=$(docker inspect -f \
    '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' \
    "$CONTAINER" 2>/dev/null) || ATTACHED=""
ATTACHED=$(printf '%s' "$ATTACHED" | tr -s ' ' \
    | sed 's/^ *//;s/ *$//')
[ -n "$ATTACHED" ] || fail "$CONTAINER is not connected to any network"

COUNT=0
for net in $ATTACHED; do
    COUNT=$((COUNT + 1))
done

if [ "$COUNT" -gt 1 ]; then
    EXTRA=""
    FIRST=1
    for net in $ATTACHED; do
        if [ "$FIRST" -eq 1 ]; then
            FIRST=0
            continue
        fi
        EXTRA="$EXTRA $net"
    done
    bad "the agent must be on exactly one network; extra connections:$EXTRA"
fi

# Check the single connected network: not host/none, and bridge.
SINGLE=""
for net in $ATTACHED; do
    [ -n "$SINGLE" ] || SINGLE=$net
done
if [ -n "$SINGLE" ]; then
    case "$SINGLE" in
        host|none)
            bad "the agent is on a forbidden network: $SINGLE"
            ;;
        *)
            driver=$(docker network inspect -f '{{.Driver}}' "$SINGLE" \
                2>/dev/null || true)
            lower=$(printf '%s' "$driver" | tr '[:upper:]' '[:lower:]')
            case "$lower" in
                bridge)
                    pass "network: $SINGLE (bridge)"
                    ;;
                host|none|null|"")
                    bad "the agent network driver cannot be verified: $SINGLE (${driver:-unknown})"
                    ;;
                *)
                    bad "the agent network driver is not bridge: $SINGLE ($driver)"
                    ;;
            esac
            ;;
    esac
fi

if [ -n "$EXPECTED" ]; then
    # Explicit expected network: the connected network must match it exactly.
    if [ "$ATTACHED" = "$EXPECTED" ]; then
        pass "expected network connected: $EXPECTED"
    else
        bad "the connected network ($ATTACHED) does not match DROPJAK_NETWORK: $EXPECTED"
    fi
fi

# The host Docker socket must never be mounted into the agent.
MOUNTS=$(docker inspect -f '{{range .Mounts}}{{.Source}} {{end}}' \
    "$CONTAINER" 2>/dev/null) || MOUNTS=""
case " $MOUNTS " in
    *"/docker.sock "*|*"/podman.sock "*)
        bad "the host Docker/Podman socket is mounted into the agent" ;;
    *)
        pass "no host Docker socket in the agent" ;;
esac

READONLY=$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' \
    "$CONTAINER" 2>/dev/null)
case "$READONLY" in
    true|True) pass "read-only rootfs" ;;
    *) bad "the rootfs is not read-only ($READONLY)" ;;
esac

SECOPT=$(docker inspect -f '{{range .HostConfig.SecurityOpt}}{{.}} {{end}}' \
    "$CONTAINER" 2>/dev/null) || SECOPT=""
case "$SECOPT" in
    *no-new-privileges*) pass "no-new-privileges" ;;
    *) bad "no-new-privileges is missing" ;;
esac

CAPDROP=$(docker inspect -f '{{range .HostConfig.CapDrop}}{{.}} {{end}}' \
    "$CONTAINER" 2>/dev/null) || CAPDROP=""
ALL_EQ=0
if [ "$ROOTLESS" -eq 1 ]; then
    # Podman expands cap_drop: ALL into an explicit base set.
    ALL_EQ=1
    for cap in CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_FSETID CAP_KILL \
            CAP_NET_BIND_SERVICE CAP_SETFCAP CAP_SETGID CAP_SETPCAP \
            CAP_SETUID CAP_SYS_CHROOT; do
        case " $CAPDROP " in
            *" $cap "*) ;;
            *) ALL_EQ=0 ;;
        esac
    done
fi
case " $CAPDROP " in
    *" ALL "*) pass "cap_drop: ALL" ;;
    *)
        if [ "$ALL_EQ" -eq 1 ]; then
            pass "cap_drop: ALL (rootless: expanded to the base set)"
        else
            bad "cap_drop is not ALL ($CAPDROP)"
        fi
        ;;
esac

CAPADD=$(docker inspect -f '{{range .HostConfig.CapAdd}}{{.}} {{end}}' \
    "$CONTAINER" 2>/dev/null) || CAPADD=""
# Docker writes the short name (NET_ADMIN); Podman writes CAP_NET_ADMIN.
case " $CAPADD " in
    *" NET_ADMIN "*|*" CAP_NET_ADMIN "*) pass "cap_add: NET_ADMIN" ;;
    *)
        # In a rootless namespace NET_ADMIN comes from the userns; the real
        # probe is nft (reading the running ruleset needs NET_ADMIN).
        if [ "$ROOTLESS" -eq 1 ] \
                && docker exec "$CONTAINER" \
                    nft list table inet dropjak_agent >/dev/null 2>&1; then
            pass "cap_add: NET_ADMIN (effective in the rootless namespace)"
        else
            bad "NET_ADMIN is missing ($CAPADD)"
        fi
        ;;
esac

if [ "$FAIL" -ne 0 ]; then
    printf 'FAIL the agent network/security check found differences\n' >&2
    exit 1
fi
printf 'PASS the agent is on exactly one bridge network and the security settings are in order\n'
exit 0
