#!/usr/bin/env bash
#
# Dropjak — graceful stop
#
# Stops the portal (and the Caddy proxy) of a Docker Compose checkout or a
# native systemd installation. The firewall is NOT touched: the nftables
# table inet hatarvedelem stays loaded on purpose (fail-closed), so forwarded
# traffic stays blocked while the portal is down, and the existing grants
# (including the one carrying a host SSH session) simply expire on their TTL.
#
# Usage:
#   sudo ./stop.sh [--yes] [--down] [--dry-run] [--compose|--native]
#
#   --yes        do not ask for confirmation over SSH
#   --down       Compose only: also remove the containers (docker compose
#                down, never -v: the volumes are kept)
#   --dry-run    print what would be done, change nothing; works without
#                root (also: -n)
#   --compose    force the Docker Compose style
#   --native     force the native systemd style
#   --dir DIR    the checkout to operate on (default: the script's directory)
#   -h, --help   show this help
#
set -euo pipefail

SYSTEMD_DIR="${HV_SYSTEMD_DIR:-/etc/systemd/system}"
PORTAL_CONTAINER="dropjak"
CADDY_CONTAINER="dropjak-caddy"
PORTAL_UNIT="dropjak.service"
HELPER_UNIT="dropjak-helper.service"
FIREWALL_UNIT="dropjak-firewall.service"

ASSUME_YES=0
DRY_RUN=0
DOWN=0
STYLE=""
INSTALL_DIR=""

# Output never aborts the script: a dropped SSH terminal must not stop it
# half-way.
die()  { printf 'ERROR: %s\n' "$*" >&2 || true; exit 1; }
info() { printf '[dropjak] %s\n' "$*" || true; }
warn() { printf '[dropjak] WARNING: %s\n' "$*" >&2 || true; }

# Echo and skip when DRY_RUN=1, otherwise execute the command.
run() {
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '[dry-run] %s\n' "$*" || true
    return 0
  fi
  "$@"
}

usage() {
  cat <<'EOF'
Usage: sudo ./stop.sh [--yes] [--down] [--dry-run] [--compose|--native]

  --yes        do not ask for confirmation when run over SSH
  --down       Compose only: also remove the containers with
               `docker compose down` (never -v; the volumes are kept)
  --dry-run    print what would be done, change nothing (also: -n);
               works without root
  --compose    force the Docker Compose style
  --native     force the native systemd style
  --dir DIR    the checkout to operate on (default: the script's directory)
  -h, --help   this help

Docker Compose (a checkout with docker-compose.yml and .env): stops Caddy
first, then the portal, with the profiles from COMPOSE_PROFILES in .env.
Containers and volumes are kept unless --down is given.

Native (dropjak.service installed): stops dropjak.service, then
dropjak-helper.service. dropjak-firewall.service and the check timer keep
running.

The nftables table inet hatarvedelem is never flushed or deleted: the host
stays fail-closed. Forwarded traffic stays blocked, and the existing grants
(including host SSH) are not removed; they expire on their TTL and cannot be
renewed until the portal runs again (./start.sh). Starting the portal flushes
every grant, so host SSH must be re-authorized in the portal afterwards.

Environment:
  HV_SYSTEMD_DIR   the systemd unit directory (default: /etc/systemd/system)
EOF
}

# ---------------------------------------------------------------- arguments

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes)        ASSUME_YES=1; shift ;;
    --down)       DOWN=1; shift ;;
    --dry-run|-n) DRY_RUN=1; shift ;;
    --compose)    STYLE="compose"; shift ;;
    --native)     STYLE="native"; shift ;;
    --dir)
      [[ $# -ge 2 && -n "$2" ]] || die "--dir needs a directory"
      INSTALL_DIR="$2"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *)            die "unknown option: $1 (see: --help)" ;;
  esac
done

# The dry run is read-only and must work without root.
if [[ $DRY_RUN -eq 0 && "$(id -u)" -ne 0 ]]; then
  die "this script must be run as root: sudo ./stop.sh"
fi

if [[ -z "$INSTALL_DIR" ]]; then
  INSTALL_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)" \
    || die "cannot determine the script's directory"
else
  INSTALL_DIR="$(cd -P -- "$INSTALL_DIR" >/dev/null 2>&1 && pwd)" \
    || die "no such directory: $INSTALL_DIR"
fi

# ---------------------------------------------------------------- helpers

# A value from .env (the last assignment wins, quotes stripped).
env_get() {
  [[ -r "$INSTALL_DIR/.env" ]] || return 0
  sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$INSTALL_DIR/.env" \
    | tail -n 1 | sed 's/[[:space:]]*$//; s/^["'\'']//; s/["'\'']$//' || true
}

# A Compose setting: the shell environment wins over .env, as in Compose.
setting() {
  if printenv "$1" >/dev/null 2>&1; then
    printenv "$1"
  else
    env_get "$1"
  fi
}

# The deployment style, detected like uninstall.sh: a checkout with
# docker-compose.yml (and .env) is Compose, an installed dropjak.service is
# native.
detect_style() {
  [[ -z "$STYLE" ]] || return 0
  if [[ -f "$INSTALL_DIR/docker-compose.yml" && -f "$INSTALL_DIR/.env" ]]; then
    STYLE="compose"
  elif [[ -e "$SYSTEMD_DIR/$PORTAL_UNIT" ]]; then
    STYLE="native"
  elif [[ -f "$INSTALL_DIR/docker-compose.yml" ]]; then
    STYLE="compose"
  else
    die "cannot detect the deployment style: no docker-compose.yml in $INSTALL_DIR and no $SYSTEMD_DIR/$PORTAL_UNIT (use --compose or --native)"
  fi
}

PROFILE_ARGS=()
HAS_PROXY_PROFILE=0
read_profiles() {
  local profiles profile
  profiles="$(setting COMPOSE_PROFILES)"
  for profile in ${profiles//,/ }; do
    [[ "$profile" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] \
      || die "invalid COMPOSE_PROFILES entry: $profile"
    PROFILE_ARGS+=(--profile "$profile")
    [[ "$profile" != "proxy" ]] || HAS_PROXY_PROFILE=1
  done
}

# docker compose in the checkout, with the profiles from .env.
compose() {
  ( cd -- "$INSTALL_DIR" && run docker compose ${PROFILE_ARGS[@]+"${PROFILE_ARGS[@]}"} "$@" )
}

detect_style
[[ $DOWN -eq 0 || "$STYLE" == "compose" ]] \
  || die "--down applies to the Docker Compose deployment only"

SSH_SRC=""
if [[ -n "${SSH_CONNECTION:-}" ]]; then
  SSH_SRC="${SSH_CONNECTION%% *}"
fi

# ---------------------------------------------------------------- summary

printf '\n'
info "Dropjak stop plan"
if [[ "$STYLE" == "compose" ]]; then
  read_profiles
  if [[ $DOWN -eq 1 ]]; then
    containers_note="removed (docker compose down, volumes kept)"
  else
    containers_note="kept (stopped)"
  fi
  cat <<EOF
  Deployment:            Docker Compose ($INSTALL_DIR)
  Profiles:              ${PROFILE_ARGS[*]:-(none)}
  Stop order:            $(if [[ $HAS_PROXY_PROFILE -eq 1 ]]; then printf '%s, ' "$CADDY_CONTAINER"; fi)$PORTAL_CONTAINER
  Containers:            $containers_note
EOF
else
  cat <<EOF
  Deployment:            native systemd ($SYSTEMD_DIR)
  Stop order:            $PORTAL_UNIT, $HELPER_UNIT
  Kept running:          $FIREWALL_UNIT, dropjak-firewall-check.timer
EOF
fi
cat <<EOF
  Firewall:              inet hatarvedelem stays loaded (fail-closed);
                         forwarded traffic stays blocked
  Grants:                not removed; they expire on their TTL and cannot be
                         renewed until ./start.sh
EOF

if [[ -n "$SSH_SRC" ]]; then
  warn "you are connected over SSH from $SSH_SRC."
  warn "stop does not remove your SSH grant, but it cannot be renewed while the"
  warn "portal is down; when it expires, a new SSH connection needs the console."
  warn "start.sh flushes every grant: re-authorize TCP 22 in the portal after it."
fi
if [[ "$STYLE" == "compose" ]]; then
  warn "do not reboot the host while stopped: the stopped container does not"
  warn "come back by itself, and the boot protection then closes every port,"
  warn "including SSH. Run ./start.sh before a reboot."
fi

if [[ $DRY_RUN -eq 1 ]]; then
  info "dry run: nothing will be changed"
elif [[ -n "$SSH_SRC" && $ASSUME_YES -eq 0 ]]; then
  printf '\n'
  printf 'Stop the portal anyway? [y/N] '
  answer=""
  read -r answer || true
  case "$answer" in
    y|Y|yes|YES) ;;
    *) die "aborted: nothing was stopped" ;;
  esac
fi

# ---------------------------------------------------------------- compose

stop_compose() {
  if [[ $DRY_RUN -eq 0 ]]; then
    command -v docker >/dev/null 2>&1 || die "docker not found"
    docker compose version >/dev/null 2>&1 \
      || die "the Docker Compose plugin was not found"
  fi

  if [[ $HAS_PROXY_PROFILE -eq 1 ]]; then
    info "stopping Caddy ($CADDY_CONTAINER)"
    compose stop caddy || die "docker compose stop caddy failed"
  fi
  info "stopping the portal ($PORTAL_CONTAINER)"
  compose stop || die "docker compose stop failed"

  if [[ $DOWN -eq 1 ]]; then
    # Never -v: the dropjak-state volume holds users, rules and settings.
    info "removing the containers (the volumes are kept)"
    compose down --remove-orphans || die "docker compose down failed"
  fi
}

# ---------------------------------------------------------------- native

stop_native() {
  if [[ $DRY_RUN -eq 0 ]]; then
    command -v systemctl >/dev/null 2>&1 || die "systemctl not found"
  fi
  local unit
  for unit in "$PORTAL_UNIT" "$HELPER_UNIT"; do
    if [[ $DRY_RUN -eq 0 && ! -e "$SYSTEMD_DIR/$unit" ]]; then
      info "$unit not installed, skipped"
      continue
    fi
    info "stopping $unit"
    run systemctl stop "$unit" || die "systemctl stop $unit failed"
  done
  info "$FIREWALL_UNIT is left running (the rules stay loaded)"
}

if [[ "$STYLE" == "compose" ]]; then
  stop_compose
else
  stop_native
fi

# ---------------------------------------------------------------- done

if [[ $DRY_RUN -eq 1 ]]; then
  info "dry run: nothing was changed"
  exit 0
fi
info "stopped. The nftables table inet hatarvedelem is still loaded: forwarded"
info "traffic stays blocked and existing grants expire on their TTL."
info "start again with: sudo $INSTALL_DIR/start.sh"
