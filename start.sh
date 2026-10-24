#!/usr/bin/env bash
#
# Dropjak — careful start
#
# Runs a preflight first and aborts before touching anything if a check
# fails: a portal that crash-loops leaves the fail-closed host without any
# open port (SSH included), which then needs the provider console. Only
# after a clean preflight does it start the portal, wait for it to become
# healthy, then start Caddy (Compose with the proxy profile) and print
# /api/status.
#
# Usage:
#   sudo ./start.sh [--yes] [--dry-run] [--timeout SEC] [--build]
#                   [--skip-caddy-validate] [--rollback-on-fail]
#                   [--compose|--native]
#
# Exit status: 0 started and healthy; 1 preflight or start failed; 2 the new
# image failed and the stack runs on the rolled-back pre-update image.
#
set -euo pipefail

SYSTEMD_DIR="${HV_SYSTEMD_DIR:-/etc/systemd/system}"
NFT_FILE="/etc/nftables/dropjak.nft"
APP_DIR="/opt/hatarvedelem"
PORTAL_CONTAINER="dropjak"
CADDY_CONTAINER="dropjak-caddy"
PORTAL_UNIT="dropjak.service"
HELPER_UNIT="dropjak-helper.service"
FIREWALL_UNIT="dropjak-firewall.service"
CHECK_TIMER="dropjak-firewall-check.timer"
PRE_UPDATE_REPO="dropjak"

ASSUME_YES=0
DRY_RUN=0
TIMEOUT=120
BUILD=0
SKIP_CADDY_VALIDATE=0
ROLLBACK=0
STYLE=""
INSTALL_DIR=""

# Output never aborts the script: when the start flushes the grants, the SSH
# terminal may go away, and the health wait must still finish.
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
Usage: sudo ./start.sh [--yes] [--dry-run] [--timeout SEC] [--build]
                       [--skip-caddy-validate] [--rollback-on-fail]
                       [--compose|--native]

  --yes                  do not ask for confirmation when run over SSH
  --dry-run              run the read-only preflight checks and print the
                         start commands, change nothing (also: -n); works
                         without root
  --timeout SEC          how long to wait for the portal to become healthy
                         (default: 120)
  --build                build the image first (host-network build) instead
                         of requiring it to exist locally
  --skip-caddy-validate  do not run `caddy validate` on deploy/Caddyfile
  --rollback-on-fail     Compose only: when the portal is not healthy in
                         time, retag the newest dropjak:pre-update-* image
                         as the compose image and start again
  --compose              force the Docker Compose style
  --native               force the native systemd style
  --dir DIR              the checkout to operate on (default: the script's
                         directory)
  -h, --help             this help

Preflight (any failure aborts before anything is started):
  Compose: .env exists and is not world-readable; HV_PROXY=1 requires an
  HV_PROXY_KEY of at least 32 characters; `sh -n docker/entrypoint.sh`;
  `docker compose config -q`; the compose image exists locally (or --build);
  with the proxy profile, `caddy validate` of deploy/Caddyfile in the pinned
  caddy image.
  Native: dropjak.service, dropjak-helper.service and dropjak-firewall.service
  are installed; `nft -c -f /etc/nftables/dropjak.nft` when nft is present.

Start:
  Compose: `docker compose up -d dropjak` (profiles from COMPOSE_PROFILES),
  wait for the healthcheck, then `docker compose up -d` (Caddy), then print
  /api/status from 127.0.0.1:PORT.
  Native: start dropjak-helper.service, then dropjak.service, and wait for
  /api/status.

When the portal is not healthy in time the last log lines are printed. The
rollback (--rollback-on-fail) only swaps the image; the checkout and .env stay
as they are. For a full rollback to the state before an update use
./restore.sh.

Starting the portal flushes every grant (HV_FLUSH_ON_START=1), including
the one carrying a host SSH session. Over SSH, re-authorize TCP 22 in the
portal right after the start, and preferably run the script detached:
  nohup ./start.sh --yes > /root/dropjak-start.log 2>&1 &

Exit status: 0 healthy, 1 failed, 2 healthy only after the rollback.

Environment:
  HV_SYSTEMD_DIR   the systemd unit directory (default: /etc/systemd/system)
EOF
}

# ---------------------------------------------------------------- arguments

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes)                 ASSUME_YES=1; shift ;;
    --dry-run|-n)          DRY_RUN=1; shift ;;
    --timeout)
      [[ $# -ge 2 && "${2:-}" =~ ^[0-9]+$ && "$2" -ge 1 ]] \
        || die "--timeout needs a positive number of seconds"
      TIMEOUT="$2"; shift 2 ;;
    --build)               BUILD=1; shift ;;
    --skip-caddy-validate) SKIP_CADDY_VALIDATE=1; shift ;;
    --rollback-on-fail)    ROLLBACK=1; shift ;;
    --compose)             STYLE="compose"; shift ;;
    --native)              STYLE="native"; shift ;;
    --dir)
      [[ $# -ge 2 && -n "$2" ]] || die "--dir needs a directory"
      INSTALL_DIR="$2"; shift 2 ;;
    -h|--help)             usage; exit 0 ;;
    *)                     die "unknown option: $1 (see: --help)" ;;
  esac
done

# The dry run is read-only and must work without root.
if [[ $DRY_RUN -eq 0 && "$(id -u)" -ne 0 ]]; then
  die "this script must be run as root: sudo ./start.sh"
fi

if [[ -z "$INSTALL_DIR" ]]; then
  INSTALL_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)" \
    || die "cannot determine the script's directory"
else
  INSTALL_DIR="$(cd -P -- "$INSTALL_DIR" >/dev/null 2>&1 && pwd)" \
    || die "no such directory: $INSTALL_DIR"
fi

# A lost SSH terminal must not kill the start half-way.
trap '' HUP

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

# The same truth values as env_bool in docker/entrypoint.sh.
is_true() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' \
    | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  case "$value" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
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

# The image of a service in docker-compose.yml: the first `image:` value
# starting with the given name (dropjak:2, caddy:...@sha256:...).
compose_file_image() {
  sed -n "s/^[[:space:]]*image:[[:space:]]*\(${1}[^[:space:]]*\).*/\1/p" \
    "$INSTALL_DIR/docker-compose.yml" 2>/dev/null | head -n 1 || true
}

# The newest dropjak:pre-update-<timestamp> tag, or nothing.
newest_pre_update_tag() {
  docker images --format '{{.Repository}}:{{.Tag}}' "$PRE_UPDATE_REPO" 2>/dev/null \
    | grep -E "^${PRE_UPDATE_REPO}:pre-update-[0-9]{8}-[0-9]{6}\$" \
    | sort | tail -n 1 || true
}

detect_style

SSH_SRC=""
if [[ -n "${SSH_CONNECTION:-}" ]]; then
  SSH_SRC="${SSH_CONNECTION%% *}"
fi

COMPOSE_IMAGE=""
CADDY_IMAGE=""
PORT=""
DOCKER_OK=0
if [[ "$STYLE" == "compose" ]]; then
  read_profiles
  COMPOSE_IMAGE="$(compose_file_image dropjak)"
  [[ -n "$COMPOSE_IMAGE" ]] || COMPOSE_IMAGE="dropjak:2"
  CADDY_IMAGE="$(compose_file_image caddy)"
  PORT="$(setting PORT)"
  [[ -n "$PORT" ]] || PORT="8100"
  if command -v docker >/dev/null 2>&1 \
      && docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
    DOCKER_OK=1
  fi
else
  PORT="$(sed -n 's/^[[:space:]]*Environment=PORT=\([0-9]*\).*/\1/p' \
    "$SYSTEMD_DIR/$PORTAL_UNIT" 2>/dev/null | tail -n 1 || true)"
  [[ -n "$PORT" ]] || PORT="80"
fi
[[ "$PORT" =~ ^[0-9]+$ ]] || die "invalid PORT: $PORT"

BUILD_CMD="DOCKER_BUILDKIT=0 docker build --network host -t $COMPOSE_IMAGE ."

# ---------------------------------------------------------------- summary

printf '\n'
info "Dropjak start plan"
if [[ "$STYLE" == "compose" ]]; then
  cat <<EOF
  Deployment:            Docker Compose ($INSTALL_DIR)
  Profiles:              ${PROFILE_ARGS[*]:-(none)}
  Image:                 $COMPOSE_IMAGE$(if [[ $BUILD -eq 1 ]]; then printf ' (built first)'; fi)
  Start order:           $PORTAL_CONTAINER (wait for healthy, up to ${TIMEOUT} s)$(if [[ $HAS_PROXY_PROFILE -eq 1 ]]; then printf ', then %s' "$CADDY_CONTAINER"; fi)
  Status check:          http://127.0.0.1:$PORT/api/status
  Rollback on failure:   $(if [[ $ROLLBACK -eq 1 ]]; then printf 'yes (newest %s:pre-update-* image)' "$PRE_UPDATE_REPO"; else printf 'no'; fi)
EOF
else
  cat <<EOF
  Deployment:            native systemd ($SYSTEMD_DIR)
  Start order:           $HELPER_UNIT, $PORTAL_UNIT (wait up to ${TIMEOUT} s)
  Status check:          http://127.0.0.1:$PORT/api/status
EOF
  [[ $ROLLBACK -eq 0 ]] \
    || warn "--rollback-on-fail applies to the Docker Compose deployment only; ignored"
  [[ $BUILD -eq 0 ]] \
    || warn "--build applies to the Docker Compose deployment only; ignored"
fi

# ---------------------------------------------------------------- preflight

FAILURES=0
fail() { printf '[dropjak] preflight FAILED: %s\n' "$*" >&2 || true; FAILURES=$((FAILURES + 1)); }
pass() { printf '[dropjak] preflight ok: %s\n' "$*" || true; }

preflight_compose() {
  local env_file="$INSTALL_DIR/.env" mode proxy key key_len

  if [[ ! -f "$env_file" ]]; then
    fail ".env not found in $INSTALL_DIR (create it with ./configure.sh)"
  else
    mode="$(stat -c '%a' -- "$env_file" 2>/dev/null || true)"
    if [[ ! "$mode" =~ ^[0-7]+$ ]]; then
      fail "cannot read the mode of $env_file"
    elif (( (8#$mode & 8#007) != 0 )); then
      fail "$env_file is accessible to other users (mode $mode); fix: chmod 600 $env_file"
    else
      pass ".env present, mode $mode"
    fi
  fi

  proxy="$(setting HV_PROXY)"
  if is_true "$proxy"; then
    key="$(setting HV_PROXY_KEY)"
    key_len=${#key}
    unset key
    if (( key_len < 32 )); then
      fail "HV_PROXY=1 requires HV_PROXY_KEY of at least 32 characters (now $key_len); the entrypoint would refuse to start. Generate one with: openssl rand -hex 32"
    else
      pass "HV_PROXY_KEY has $key_len characters"
    fi
    [[ $HAS_PROXY_PROFILE -eq 1 ]] \
      || warn "HV_PROXY=1 but COMPOSE_PROFILES has no proxy profile: Caddy will not start"
  elif [[ $HAS_PROXY_PROFILE -eq 1 ]]; then
    warn "the proxy profile is active but HV_PROXY is not 1: the firewall keeps 80/443 closed for Caddy"
  fi

  if [[ ! -f "$INSTALL_DIR/docker/entrypoint.sh" ]]; then
    fail "docker/entrypoint.sh not found in $INSTALL_DIR"
  elif sh -n "$INSTALL_DIR/docker/entrypoint.sh"; then
    pass "sh -n docker/entrypoint.sh"
  else
    fail "docker/entrypoint.sh has a syntax error"
  fi

  if [[ $DOCKER_OK -eq 0 ]]; then
    if [[ $DRY_RUN -eq 1 ]]; then
      info "dry run: the Docker daemon is not reachable for this user; the Docker checks are only printed"
      printf '[dry-run] docker compose %s config -q\n' "${PROFILE_ARGS[*]:-}"
      printf '[dry-run] docker image inspect %s\n' "$COMPOSE_IMAGE"
      if [[ $HAS_PROXY_PROFILE -eq 1 && $SKIP_CADDY_VALIDATE -eq 0 ]]; then
        printf '[dry-run] docker run --rm --network none ... %s caddy validate --config /etc/caddy/Caddyfile\n' "${CADDY_IMAGE:-caddy}"
      fi
      return 0
    fi
    fail "docker is not available or the daemon is not reachable"
    return 0
  fi

  if ! docker compose version >/dev/null 2>&1; then
    fail "the Docker Compose plugin was not found"
    return 0
  fi

  if ( cd -- "$INSTALL_DIR" && docker compose ${PROFILE_ARGS[@]+"${PROFILE_ARGS[@]}"} config -q ); then
    pass "docker compose config -q"
  else
    fail "docker compose config -q reported an error"
  fi

  if [[ $BUILD -eq 1 ]]; then
    info "the image $COMPOSE_IMAGE is built before the start (--build)"
  elif docker image inspect "$COMPOSE_IMAGE" >/dev/null 2>&1; then
    pass "image $COMPOSE_IMAGE exists locally"
  else
    fail "image $COMPOSE_IMAGE not found locally; build it on the host network (or re-run with --build): $BUILD_CMD"
  fi

  if [[ $HAS_PROXY_PROFILE -eq 1 ]]; then
    if [[ $SKIP_CADDY_VALIDATE -eq 1 ]]; then
      info "caddy validate skipped (--skip-caddy-validate)"
    elif [[ ! -f "$INSTALL_DIR/deploy/Caddyfile" ]]; then
      fail "deploy/Caddyfile not found in $INSTALL_DIR"
    elif [[ -z "$CADDY_IMAGE" ]]; then
      fail "no caddy image found in docker-compose.yml"
    elif [[ $DRY_RUN -eq 1 ]]; then
      printf '[dry-run] docker run --rm --network none -e PORT -e HV_PROXY_KEY -v %q:/etc/caddy/Caddyfile:ro %s caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile\n' \
        "$INSTALL_DIR/deploy/Caddyfile" "$CADDY_IMAGE"
    else
      # The key goes through the environment, never onto the command line.
      if ( export PORT HV_PROXY_KEY
           HV_PROXY_KEY="$(setting HV_PROXY_KEY)"
           docker run --rm --network none -e PORT -e HV_PROXY_KEY \
             -v "$INSTALL_DIR/deploy/Caddyfile:/etc/caddy/Caddyfile:ro" \
             "$CADDY_IMAGE" caddy validate --config /etc/caddy/Caddyfile \
             --adapter caddyfile >/dev/null 2>&1 ); then
        pass "caddy validate deploy/Caddyfile"
      else
        fail "caddy validate rejected deploy/Caddyfile (check: docker run --rm --network none -e PORT -e HV_PROXY_KEY -v $INSTALL_DIR/deploy/Caddyfile:/etc/caddy/Caddyfile:ro $CADDY_IMAGE caddy validate --config /etc/caddy/Caddyfile; or skip with --skip-caddy-validate)"
      fi
    fi
  fi
}

preflight_native() {
  local unit
  for unit in "$PORTAL_UNIT" "$HELPER_UNIT" "$FIREWALL_UNIT"; do
    if [[ -e "$SYSTEMD_DIR/$unit" ]]; then
      pass "$unit installed"
    else
      fail "$SYSTEMD_DIR/$unit not installed (run install.sh first)"
    fi
  done
  [[ -e "$SYSTEMD_DIR/$CHECK_TIMER" ]] \
    || warn "$CHECK_TIMER is not installed (the native firewall watchdog)"

  if [[ $DRY_RUN -eq 1 ]]; then
    printf '[dry-run] nft -c -f %s\n' "$NFT_FILE"
  elif ! command -v nft >/dev/null 2>&1; then
    warn "nft not found; the installed ruleset is not checked"
  elif [[ ! -f "$NFT_FILE" ]]; then
    warn "$NFT_FILE not found; the installed ruleset is not checked"
  elif nft -c -f "$NFT_FILE"; then
    pass "nft -c -f $NFT_FILE"
  else
    fail "nft -c -f $NFT_FILE rejected the installed ruleset"
  fi

  if [[ $DRY_RUN -eq 0 ]]; then
    command -v systemctl >/dev/null 2>&1 || fail "systemctl not found"
    [[ -f "$APP_DIR/server.py" ]] || fail "$APP_DIR/server.py not found (run install.sh first)"
  fi
}

printf '\n'
info "preflight"
if [[ "$STYLE" == "compose" ]]; then
  preflight_compose
else
  preflight_native
fi
if (( FAILURES > 0 )); then
  die "preflight failed ($FAILURES check(s)); nothing was started"
fi

# ---------------------------------------------------------------- confirmation

if [[ -n "$SSH_SRC" ]]; then
  warn "you are connected over SSH from $SSH_SRC."
  warn "the start flushes every grant, including this SSH session's; the SSH"
  warn "guard then closes it. Log in to the portal from $SSH_SRC and"
  warn "re-authorize TCP 22 right after the start. Prefer running detached:"
  warn "  nohup $INSTALL_DIR/start.sh --yes > /root/dropjak-start.log 2>&1 &"
fi

if [[ $DRY_RUN -eq 1 ]]; then
  info "dry run: nothing will be changed"
elif [[ -n "$SSH_SRC" && $ASSUME_YES -eq 0 ]]; then
  printf '\n'
  printf 'Start the portal now? [y/N] '
  answer=""
  read -r answer || true
  case "$answer" in
    y|Y|yes|YES) ;;
    *) die "aborted: nothing was started" ;;
  esac
fi

# ---------------------------------------------------------------- status

print_status() {
  local body
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '[dry-run] curl -sS -m 5 http://127.0.0.1:%s/api/status\n' "$PORT"
    return 0
  fi
  if ! command -v curl >/dev/null 2>&1; then
    info "curl not found; /api/status is not printed"
    return 0
  fi
  if body="$(curl -sS -m 5 "http://127.0.0.1:$PORT/api/status" 2>&1)"; then
    info "/api/status (127.0.0.1:$PORT):"
    printf '  %s\n' "$body" || true
  else
    warn "/api/status on 127.0.0.1:$PORT did not answer: $body"
  fi
}

# ---------------------------------------------------------------- compose

container_state() {
  docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
    "$1" 2>/dev/null || printf 'missing missing\n'
}

# 0 when the portal container is healthy within TIMEOUT seconds.
wait_portal_healthy() {
  local deadline=$((SECONDS + TIMEOUT)) state="" last=""
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '[dry-run] wait up to %s s for %s to become healthy\n' "$TIMEOUT" "$PORTAL_CONTAINER"
    return 0
  fi
  info "waiting up to ${TIMEOUT} s for $PORTAL_CONTAINER to become healthy"
  while :; do
    state="$(container_state "$PORTAL_CONTAINER")"
    if [[ "$state" != "$last" ]]; then
      info "  $PORTAL_CONTAINER: $state"
      last="$state"
    fi
    case "$state" in
      "running healthy"|"running none") return 0 ;;
      *" unhealthy") return 1 ;;
    esac
    (( SECONDS < deadline )) || return 1
    sleep 2
  done
}

# Caddy has no healthcheck: it must be running and stay running for a while.
wait_caddy_running() {
  local deadline=$((SECONDS + 30)) state="" stable=0
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '[dry-run] wait for %s to be running\n' "$CADDY_CONTAINER"
    return 0
  fi
  while :; do
    state="$(container_state "$CADDY_CONTAINER")"
    if [[ "$state" == running* ]]; then
      stable=$((stable + 1))
      (( stable < 3 )) || return 0
    else
      stable=0
    fi
    (( SECONDS < deadline )) || return 1
    sleep 2
  done
}

show_compose_logs() {
  [[ $DRY_RUN -eq 0 ]] || return 0
  warn "the last log lines of $1:"
  ( cd -- "$INSTALL_DIR" && docker compose ${PROFILE_ARGS[@]+"${PROFILE_ARGS[@]}"} \
      logs --no-color --tail=50 "$2" ) 2>&1 | sed 's/^/  /' || true
}

lockout_hint() {
  warn "while the portal is down the host stays fail-closed: every port,"
  warn "including SSH, is dropped for a source without a live grant. If you"
  warn "lose access, use the provider console (DOKUMENTACIO.md 10.6)."
}

compose_up_portal() {
  compose up -d "$PORTAL_CONTAINER" && wait_portal_healthy
}

# Swap in the newest pre-update image and start again. 0 when it is healthy.
rollback_compose() {
  local tag ts
  tag="$(newest_pre_update_tag)"
  if [[ -z "$tag" ]]; then
    warn "rollback: no ${PRE_UPDATE_REPO}:pre-update-* image found; nothing to roll back to"
    return 1
  fi
  ts="$(date +%Y%m%d-%H%M%S)"
  warn "rollback: retagging $tag as $COMPOSE_IMAGE"
  if docker image inspect "$COMPOSE_IMAGE" >/dev/null 2>&1; then
    # Keep the failed image reachable for debugging.
    run docker tag "$COMPOSE_IMAGE" "${PRE_UPDATE_REPO}:failed-$ts" \
      || warn "could not tag the failed image"
  fi
  run docker tag "$tag" "$COMPOSE_IMAGE" || return 1
  compose up -d --force-recreate "$PORTAL_CONTAINER" || return 1
  wait_portal_healthy
}

start_compose() {
  local rolled_back=0

  if [[ $BUILD -eq 1 ]]; then
    # The fail-closed forward chain blocks the build container's egress, and
    # Compose cannot grant BuildKit the network.host entitlement.
    info "building $COMPOSE_IMAGE on the host network"
    ( cd -- "$INSTALL_DIR" && run env DOCKER_BUILDKIT=0 docker build --network host \
        -t "$COMPOSE_IMAGE" . ) || die "the image build failed; nothing was started"
  fi

  info "starting the portal ($PORTAL_CONTAINER)"
  if ! compose_up_portal; then
    warn "the portal did not become healthy within ${TIMEOUT} s"
    show_compose_logs "$PORTAL_CONTAINER" "$PORTAL_CONTAINER"
    if [[ $ROLLBACK -eq 1 ]] && rollback_compose; then
      rolled_back=1
      warn "the portal is healthy on the rolled-back image; the checkout and .env are unchanged"
      warn "for a full rollback to the state before the update: sudo $INSTALL_DIR/restore.sh"
    else
      [[ $ROLLBACK -eq 1 ]] || info "re-run with --rollback-on-fail to start the newest pre-update image"
      lockout_hint
      die "the portal is not healthy"
    fi
  fi

  if [[ $HAS_PROXY_PROFILE -eq 1 ]]; then
    info "starting Caddy ($CADDY_CONTAINER)"
    compose up -d || die "docker compose up -d failed for the remaining services"
    if ! wait_caddy_running; then
      show_compose_logs "$CADDY_CONTAINER" caddy
      warn "Caddy is not running; the portal itself is up on port $PORT"
    fi
  else
    compose up -d || die "docker compose up -d failed for the remaining services"
  fi

  print_status
  return $(( rolled_back ? 2 : 0 ))
}

# ---------------------------------------------------------------- native

wait_native_healthy() {
  local deadline=$((SECONDS + TIMEOUT))
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '[dry-run] wait up to %s s for %s and /api/status\n' "$TIMEOUT" "$PORTAL_UNIT"
    return 0
  fi
  info "waiting up to ${TIMEOUT} s for $PORTAL_UNIT and /api/status"
  while :; do
    if systemctl is-failed --quiet "$PORTAL_UNIT"; then
      return 1
    fi
    if systemctl is-active --quiet "$PORTAL_UNIT"; then
      if ! command -v curl >/dev/null 2>&1; then
        return 0
      fi
      if curl -sS -m 3 -o /dev/null "http://127.0.0.1:$PORT/api/status" 2>/dev/null; then
        return 0
      fi
    fi
    (( SECONDS < deadline )) || return 1
    sleep 2
  done
}

start_native() {
  local unit
  for unit in "$HELPER_UNIT" "$PORTAL_UNIT"; do
    info "starting $unit"
    if ! run systemctl start "$unit"; then
      journalctl -u "$unit" -n 30 --no-pager 2>&1 | sed 's/^/  /' || true
      lockout_hint
      die "systemctl start $unit failed"
    fi
  done
  if ! wait_native_healthy; then
    warn "the portal did not become healthy within ${TIMEOUT} s; the last log lines:"
    journalctl -u "$PORTAL_UNIT" -n 50 --no-pager 2>&1 | sed 's/^/  /' || true
    lockout_hint
    die "the portal is not healthy"
  fi
  print_status
}

# ---------------------------------------------------------------- start

status=0
if [[ "$STYLE" == "compose" ]]; then
  start_compose || status=$?
else
  start_native
fi

if [[ $DRY_RUN -eq 1 ]]; then
  if [[ "$STYLE" == "compose" && $ROLLBACK -eq 1 && $DOCKER_OK -eq 1 ]]; then
    tag="$(newest_pre_update_tag)"
    if [[ -n "$tag" ]]; then
      printf '[dry-run] on failure: docker tag %s %s; docker compose up -d --force-recreate %s\n' \
        "$tag" "$COMPOSE_IMAGE" "$PORTAL_CONTAINER"
    else
      info "dry run: no ${PRE_UPDATE_REPO}:pre-update-* image exists to roll back to"
    fi
  fi
  info "dry run: nothing was changed"
  exit 0
fi

info "started. The start flushes the grants (HV_FLUSH_ON_START=1, the default):"
info "log in to the portal again and re-authorize host SSH (TCP 22) if needed."
exit "$status"
