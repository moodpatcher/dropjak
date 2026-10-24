#!/usr/bin/env bash
#
# Dropjak — uninstaller
#
# Removes a Dropjak installation from the host, whether it was deployed with
# Docker Compose or natively with install.sh. The script is idempotent: every
# resource that is already missing is skipped with a note.
#
# The uninstaller also removes the directory it runs from (together with
# itself) as the very last step. It refuses to do that when the directory is
# not an absolute, sufficiently deep path containing a Dropjak marker file.
#
# Usage:
#   sudo ./uninstall.sh [--yes] [--keep-data] [--dry-run]
#
#   --yes        do not ask for confirmation
#   --keep-data  keep the Docker volume dropjak-state and
#                /var/lib/hatarvedelem (users, rules, settings, certificates)
#   --dry-run    print what would be done and change nothing; works without
#                root (also: -n)
#   -h, --help   show this help
#
# /root/dropjak-backups is always kept.
#
set -euo pipefail

APP_DIR="/opt/hatarvedelem"
STATE_DIR="/var/lib/hatarvedelem"
RUNTIME_DIR="/run/dropjak"
SERVICE_USER="hatarvedelem"
BACKUP_DIR="${HV_BACKUPS:-/root/dropjak-backups}"
NFT_TABLES=("hatarvedelem" "hatarvedelem_boot")
SYSTEMD_DIR="/etc/systemd/system"
SYSTEMD_UNITS=(
  "dropjak.service"
  "dropjak-helper.service"
  "dropjak-firewall.service"
  "dropjak-boot.service"
  "hatarvedelem.service"
  "hatarvedelem-firewall.service"
  "hatarvedelem-boot.service"
)
HOST_FILES=(
  "/etc/nftables/dropjak.nft"
  "/etc/nftables/dropjak-boot.nft"
  "/etc/nftables/hatarvedelem-boot.nft"
  "/etc/sysctl.d/90-dropjak.conf"
)

ASSUME_YES=0
KEEP_DATA=0
DRY_RUN=0

die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '[dropjak] %s\n' "$*"; }
warn() { printf '[dropjak] WARNING: %s\n' "$*" >&2; }

# Echo and skip when DRY_RUN=1, otherwise execute the command.
run() {
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '[dry-run] %s\n' "$*"
    return 0
  fi
  "$@"
}

# The Compose project name: COMPOSE_PROJECT_NAME from .env or the environment,
# otherwise the directory name Compose derives. Used to limit the Caddy volume
# cleanup to this project, so an unrelated Caddy stack is never touched.
compose_project_name() {
  local name=""
  if [[ -f "$INSTALL_DIR/.env" ]]; then
    name=$(sed -n 's/^[[:space:]]*COMPOSE_PROJECT_NAME[[:space:]]*=[[:space:]]*//p' \
        "$INSTALL_DIR/.env" | tail -n 1 \
        | sed 's/[[:space:]]*$//; s/^["'\'']//; s/["'\'']$//')
  fi
  [[ -n "$name" ]] || name="${COMPOSE_PROJECT_NAME:-}"
  [[ -n "$name" ]] || name="$(basename -- "$INSTALL_DIR")"
  printf '%s\n' "$name" | tr '[:upper:]' '[:lower:]' \
    | sed 's/[^a-z0-9_-]/-/g; s/^[-_]*//; s/[-_]*$//'
}

usage() {
  cat <<'EOF'
Usage: sudo ./uninstall.sh [--yes] [--keep-data] [--dry-run]

  --yes        do not ask for confirmation
  --keep-data  keep the Docker volume dropjak-state and /var/lib/hatarvedelem
               (users, rules, settings, certificates); everything else is
               still removed
  --dry-run    print what would be done, change nothing (also: -n)
  -h, --help   this help

The script removes the Docker Compose stack, the systemd units, the nftables
tables, the WireGuard interface, the installed files, the system account and,
last, the directory it runs from (including this script). Backups in
/root/dropjak-backups are always kept.
EOF
}

# ---------------------------------------------------------------- arguments

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes)       ASSUME_YES=1; shift ;;
    --keep-data) KEEP_DATA=1; shift ;;
    --dry-run|-n) DRY_RUN=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *)           die "unknown option: $1 (see: --help)" ;;
  esac
done

# The dry run is read-only and must work without root.
if [[ $DRY_RUN -eq 0 && "$(id -u)" -ne 0 ]]; then
  die "this script must be run as root: sudo ./uninstall.sh"
fi

SCRIPT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)" \
  || die "cannot determine the script's directory"
INSTALL_DIR="$SCRIPT_DIR"

# ------------------------------------------------------- install dir guard

guard_install_dir() {
  local dir="$1" banned marker count remainder trimmed found=0

  [[ "$dir" == /* ]] \
    || die "refusing to remove a relative installation directory: $dir"

  for banned in / /root /home /usr /etc /var /tmp "${HOME:-}"; do
    [[ -n "$banned" ]] || continue
    [[ "$dir" != "$banned" ]] \
      || die "refusing to remove $dir: this is a protected system directory"
  done

  # At least two path components: /srv/dropjak is accepted, /dropjak is not.
  trimmed="${dir#/}"
  count=0
  if [[ -n "$trimmed" ]]; then
    count=1
    remainder="$trimmed"
    while [[ "$remainder" == */* ]]; do
      remainder="${remainder#*/}"
      count=$((count + 1))
    done
  fi
  (( count >= 2 )) \
    || die "refusing to remove $dir: the path is too shallow for an installation directory"

  for marker in docker-compose.yml install.sh configure.sh server.py; do
    if [[ -f "$dir/$marker" ]]; then
      found=1
      break
    fi
  done
  (( found == 1 )) \
    || die "refusing to remove $dir: it does not look like a Dropjak installation (no docker-compose.yml, install.sh, configure.sh or server.py)"
}

guard_install_dir "$INSTALL_DIR"

# ---------------------------------------------------------------- detection

HAS_DOCKER=0
HAS_COMPOSE=0
HAS_SYSTEMCTL=0
HAS_NFT=0
HAS_IP=0

command -v docker >/dev/null 2>&1 && HAS_DOCKER=1
if [[ $HAS_DOCKER -eq 1 ]] && docker compose version >/dev/null 2>&1; then
  HAS_COMPOSE=1
fi
command -v systemctl >/dev/null 2>&1 && HAS_SYSTEMCTL=1
command -v nft >/dev/null 2>&1 && HAS_NFT=1
command -v ip >/dev/null 2>&1 && HAS_IP=1

COMPOSE_INSTALL=0
[[ -f "$INSTALL_DIR/docker-compose.yml" ]] && COMPOSE_INSTALL=1

if [[ $COMPOSE_INSTALL -eq 1 ]]; then
  if [[ $HAS_DOCKER -eq 0 ]]; then
    info "Docker not found, the Compose stack will be skipped"
  elif [[ $HAS_COMPOSE -eq 0 ]]; then
    info "Docker Compose plugin not found, the Compose stack will be skipped"
  fi
elif [[ $HAS_DOCKER -eq 1 ]]; then
  info "docker-compose.yml not found in $INSTALL_DIR, the Docker deployment is skipped"
fi

# ---------------------------------------------------------------- summary

printf '\n'
info "Dropjak uninstall plan"
cat <<EOF
  Installation directory: $INSTALL_DIR  (and this script)
  Docker Compose stack:    dropjak, dropjak-caddy
  Docker volumes:          dropjak-state, project scoped caddy-data/config/admin
  systemd units:           dropjak.service, dropjak-helper.service,
                           dropjak-firewall.service,
                           dropjak-boot.service (and the legacy
                           hatarvedelem.service names)
  nftables tables:         inet hatarvedelem, inet hatarvedelem_boot
  WireGuard interface:     dropjak0
  Files:                   /etc/nftables/dropjak.nft,
                           /etc/nftables/dropjak-boot.nft,
                           /etc/nftables/hatarvedelem-boot.nft,
                           /etc/sysctl.d/90-dropjak.conf,
                           $APP_DIR,
                           $STATE_DIR,
                           $RUNTIME_DIR
  System account:          user and group $SERVICE_USER
  Kept:                    $BACKUP_DIR
EOF
if [[ $KEEP_DATA -eq 1 ]]; then
  cat <<EOF
  Kept (--keep-data):      Docker volume dropjak-state, $STATE_DIR
                           (the $SERVICE_USER account is also kept)
EOF
fi

if [[ $DRY_RUN -eq 1 ]]; then
  info "dry run: nothing will be changed"
elif [[ $ASSUME_YES -eq 0 ]]; then
  printf '\n'
  printf 'Type UNINSTALL to continue: '
  answer=""
  read -r answer || true
  [[ "$answer" == "UNINSTALL" ]] || die "aborted: the confirmation did not match UNINSTALL"
fi

# ---------------------------------------------------------------- docker

remove_volume() {
  local name="$1"
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '[dry-run] docker volume rm -f %s\n' "$name"
    return 0
  fi
  if docker volume inspect "$name" >/dev/null 2>&1; then
    info "removing Docker volume $name"
    docker volume rm -f "$name" >/dev/null 2>&1 \
      || warn "could not remove Docker volume $name"
  else
    info "Docker volume $name not found, skipped"
  fi
}

if [[ $COMPOSE_INSTALL -eq 1 && $HAS_DOCKER -eq 1 ]]; then
  if [[ $HAS_COMPOSE -eq 1 ]]; then
    info "removing the Docker Compose stack"
    if [[ $KEEP_DATA -eq 1 ]]; then
      # -v would delete the named state volume that --keep-data preserves.
      ( cd -- "$INSTALL_DIR" && run docker compose --profile proxy down --remove-orphans ) \
        || warn "docker compose down returned an error; continuing"
    else
      ( cd -- "$INSTALL_DIR" && run docker compose --profile proxy down -v --remove-orphans ) \
        || warn "docker compose down returned an error; continuing"
    fi
  fi

  info "removing the containers (if they still exist)"
  if [[ $DRY_RUN -eq 1 ]]; then
    run docker rm -f dropjak dropjak-caddy
  else
    docker rm -f dropjak dropjak-caddy >/dev/null 2>&1 || true
  fi

  if [[ $KEEP_DATA -eq 1 ]]; then
    info "keeping the Docker volume dropjak-state (--keep-data)"
  else
    remove_volume "dropjak-state"
  fi

  # The Caddy volumes of this Compose project. With --keep-data the stack was
  # stopped without -v, so these would otherwise stay behind. The project
  # label keeps the volumes of an unrelated Caddy stack safe.
  compose_project="$(compose_project_name)"
  caddy_volumes=()
  while IFS= read -r volume; do
    [[ -n "$volume" ]] && caddy_volumes+=("$volume")
  done < <(docker volume ls -q \
             --filter "label=com.docker.compose.project=$compose_project" \
             2>/dev/null \
             | grep -E '(^|_)caddy-(data|config|admin)$' || true)
  if [[ ${#caddy_volumes[@]} -eq 0 ]]; then
    if [[ $DRY_RUN -eq 1 ]]; then
      printf '[dry-run] docker volume rm -f <project>_caddy-data <project>_caddy-config <project>_caddy-admin (if present)\n'
    else
      info "Caddy volumes of project $compose_project not found, skipped"
    fi
  fi
  for volume in "${caddy_volumes[@]}"; do
    remove_volume "$volume"
  done

  info "removing the local dropjak image tags"
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '[dry-run] docker images -q dropjak | xargs -r docker rmi -f\n'
  else
    docker images -q dropjak 2>/dev/null | xargs -r docker rmi -f >/dev/null 2>&1 \
      || true
  fi
else
  info "Docker deployment not found, skipped"
fi

# ---------------------------------------------------------------- systemd

if [[ $HAS_SYSTEMCTL -eq 0 ]]; then
  info "systemctl not found, stopping/disabling the units is skipped"
else
  for unit in "${SYSTEMD_UNITS[@]}"; do
    if [[ -e "$SYSTEMD_DIR/$unit" ]]; then
      info "stopping and disabling $unit"
      run systemctl disable --now "$unit" || warn "could not stop/disable $unit"
    else
      info "$unit not found, skipped"
    fi
  done
fi

for unit in "${SYSTEMD_UNITS[@]}"; do
  if [[ -e "$SYSTEMD_DIR/$unit" ]]; then
    info "removing the unit file $SYSTEMD_DIR/$unit"
    run rm -f -- "$SYSTEMD_DIR/$unit"
  fi
done

for DROPIN_DIR in "$SYSTEMD_DIR/dropjak.service.d" \
    "$SYSTEMD_DIR/dropjak-helper.service.d"; do
  if [[ -d "$DROPIN_DIR" ]]; then
    info "removing the systemd drop-in directory $DROPIN_DIR"
    run rm -rf -- "$DROPIN_DIR"
  else
    info "$DROPIN_DIR not found, skipped"
  fi
done

if [[ $HAS_SYSTEMCTL -eq 1 ]]; then
  info "reloading the systemd manager configuration"
  run systemctl daemon-reload || warn "systemctl daemon-reload failed"
  run systemctl reset-failed "${SYSTEMD_UNITS[@]}" \
    || warn "systemctl reset-failed failed"
fi

# ---------------------------------------------------------------- wireguard

if [[ $HAS_IP -eq 0 ]]; then
  info "ip not found, the WireGuard interface is skipped"
elif ! ip link show dropjak0 >/dev/null 2>&1; then
  info "WireGuard interface dropjak0 not found, skipped"
else
  info "deleting the WireGuard interface dropjak0"
  run ip link del dropjak0 || warn "could not delete dropjak0"
fi

# ---------------------------------------------------------------- nftables

if [[ $DRY_RUN -eq 1 ]]; then
  for table in "${NFT_TABLES[@]}"; do
    printf '[dry-run] nft delete table inet %s\n' "$table"
  done
  [[ $HAS_NFT -eq 1 ]] \
    || info "nftables not installed; a real run would skip these tables"
elif [[ $HAS_NFT -eq 0 ]]; then
  info "nftables not installed, nftables tables skipped"
else
  for table in "${NFT_TABLES[@]}"; do
    if nft list table inet "$table" >/dev/null 2>&1; then
      info "deleting nftables table inet $table"
      nft delete table inet "$table" \
        || warn "could not delete nftables table inet $table"
    else
      info "nftables table inet $table not found, skipped"
    fi
  done
fi

# ---------------------------------------------------------------- host files

for file in "${HOST_FILES[@]}"; do
  if [[ -e "$file" ]]; then
    info "removing $file"
    run rm -f -- "$file"
  else
    info "$file not found, skipped"
  fi
done

if [[ -d "$APP_DIR" ]]; then
  if [[ "$INSTALL_DIR" == "$APP_DIR" ]]; then
    info "$APP_DIR is the installation directory; removing it last"
  else
    info "removing $APP_DIR"
    run rm -rf -- "$APP_DIR"
  fi
else
  info "$APP_DIR not found, skipped"
fi

if [[ $KEEP_DATA -eq 1 ]]; then
  info "keeping $STATE_DIR (--keep-data)"
else
  if [[ -e "$STATE_DIR" ]]; then
    info "removing $STATE_DIR"
    run rm -rf -- "$STATE_DIR"
  else
    info "$STATE_DIR not found, skipped"
  fi
fi

if [[ $KEEP_DATA -eq 1 ]]; then
  info "keeping $RUNTIME_DIR (--keep-data)"
else
  if [[ -e "$RUNTIME_DIR" ]]; then
    info "removing $RUNTIME_DIR"
    run rm -rf -- "$RUNTIME_DIR"
  else
    info "$RUNTIME_DIR not found, skipped"
  fi
fi

# ---------------------------------------------------------------- user/group

if [[ $KEEP_DATA -eq 1 ]]; then
  info "keeping the $SERVICE_USER user and group (--keep-data)"
elif ! command -v getent >/dev/null 2>&1; then
  info "getent not found, the $SERVICE_USER account cannot be checked; skipped"
else
  if getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
    if command -v userdel >/dev/null 2>&1; then
      info "removing the $SERVICE_USER user"
      run userdel "$SERVICE_USER" || warn "could not remove the $SERVICE_USER user"
    else
      info "userdel not found, the $SERVICE_USER user is skipped"
    fi
  else
    info "user $SERVICE_USER not found, skipped"
  fi

  if getent group "$SERVICE_USER" >/dev/null 2>&1; then
    group_members="$(getent group "$SERVICE_USER" | cut -d: -f4 || true)"
    if [[ -n "$group_members" ]]; then
      info "group $SERVICE_USER still has members, kept"
    elif command -v groupdel >/dev/null 2>&1; then
      info "removing the $SERVICE_USER group"
      run groupdel "$SERVICE_USER" || warn "could not remove the $SERVICE_USER group"
    else
      info "groupdel not found, the $SERVICE_USER group is skipped"
    fi
  else
    info "group $SERVICE_USER not found, skipped"
  fi
fi

# ---------------------------------------------------------------- backups

info "backups in $BACKUP_DIR were kept"

# ---------------------------------------------------- install dir and script

info "removing the installation directory and this script: $INSTALL_DIR"
if [[ $DRY_RUN -eq 1 ]]; then
  run rm -rf -- "$INSTALL_DIR"
else
  if ! rm -rf -- "$INSTALL_DIR"; then
    warn "could not remove $INSTALL_DIR; remove it manually"
  fi
fi

info "uninstall complete"
