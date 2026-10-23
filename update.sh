#!/usr/bin/env bash
#
# Dropjak — updater
#
# Makes a backup of the configuration and the runtime state, then performs a
# fast-forward-only git pull in the installation directory (the checkout the
# script runs from). The backup is always written outside the repository, by
# default to /root/hatarvedelem-backups, so the working tree stays clean.
#
# Usage:
#   sudo ./update.sh [--yes] [--dry-run]
#
#   --yes        do not ask for confirmation
#   --dry-run    print the commands and the backup paths, change nothing;
#                works without root (also: -n)
#   -h, --help   show this help
#
# Environment:
#   HV_BACKUPS   backup directory (default: /root/hatarvedelem-backups)
#
set -euo pipefail

STATE_VOLUME="/var/lib/docker/volumes/dropjak-state/_data"
STATE_DIR="/var/lib/hatarvedelem"
SYSTEMD_DROPIN="/etc/systemd/system/dropjak.service.d"

ASSUME_YES=0
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

usage() {
  cat <<'EOF'
Usage: sudo ./update.sh [--yes] [--dry-run]

  --yes        do not ask for confirmation
  --dry-run    print the commands and the backup paths, change nothing
               (also: -n); works without root
  -h, --help   this help

The script backs up the configuration and the runtime state to
/root/hatarvedelem-backups (mode 0700, archives 0600) and then runs
`git pull --ff-only` in the checkout it runs from. The backup never goes
into the repository. After a successful pull it only prints the commands
needed for the deployment to take effect.

HV_BACKUPS overrides the backup directory. The script itself never runs
the rebuild or reinstall step.
EOF
}

# ---------------------------------------------------------------- arguments

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes)        ASSUME_YES=1; shift ;;
    --dry-run|-n) DRY_RUN=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *)            die "unknown option: $1 (see: --help)" ;;
  esac
done

# The dry run is read-only and must work without root.
if [[ $DRY_RUN -eq 0 && "$(id -u)" -ne 0 ]]; then
  die "this script must be run as root: sudo ./update.sh"
fi

SCRIPT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)" \
  || die "cannot determine the script's directory"

BACKUP_DIR="${HV_BACKUPS:-/root/hatarvedelem-backups}"

# Realpath that also accepts a path that does not exist yet.
resolve_path() {
  local path="$1" parent base
  if command -v realpath >/dev/null 2>&1; then
    realpath -m -- "$path"
    return 0
  fi
  if [[ -d "$path" ]]; then
    ( cd -P -- "$path" >/dev/null 2>&1 && pwd )
    return 0
  fi
  parent="$(dirname -- "$path")"
  base="$(basename -- "$path")"
  parent="$(cd -P -- "$parent" >/dev/null 2>&1 && pwd)" \
    || die "cannot resolve the backup directory: $path"
  printf '%s/%s\n' "${parent%/}" "$base"
}

RESOLVED_BACKUP_DIR="$(resolve_path "$BACKUP_DIR")" \
  || die "cannot resolve the backup directory: $BACKUP_DIR"

# Hard requirement: the backup must never dirty the checkout.
if [[ "$RESOLVED_BACKUP_DIR" == "$SCRIPT_DIR" \
      || "$RESOLVED_BACKUP_DIR" == "$SCRIPT_DIR"/* ]]; then
  die "the backup directory must stay outside the repository: $RESOLVED_BACKUP_DIR is inside $SCRIPT_DIR (set HV_BACKUPS to a directory outside the checkout)"
fi

umask 077

# In a dry run the directory is only printed, never created.
run mkdir -p -- "$BACKUP_DIR" \
  || die "cannot create the backup directory: $BACKUP_DIR"
run chmod 700 -- "$BACKUP_DIR" \
  || die "cannot set mode 0700 on the backup directory: $BACKUP_DIR"

# ---------------------------------------------------------------- survey

TS="$(date +%Y%m%d-%H%M%S)"
CONFIG_BACKUP="$BACKUP_DIR/hatarvedelem-$TS.tar.gz"
DOCKER_STATE_BACKUP="$BACKUP_DIR/dropjak-state-$TS.tar.gz"
NATIVE_STATE_BACKUP="$BACKUP_DIR/dropjak-state-native-$TS.tar.gz"

HAS_ENV=0
[[ -f "$SCRIPT_DIR/.env" ]] && HAS_ENV=1
HAS_SECRETS=0
[[ -d "$SCRIPT_DIR/secrets" ]] && HAS_SECRETS=1
HAS_SYSTEMD=0
[[ -d "$SYSTEMD_DROPIN" ]] && HAS_SYSTEMD=1

IS_GIT=0
if git -c "safe.directory=$SCRIPT_DIR" -C "$SCRIPT_DIR" rev-parse --git-dir \
    >/dev/null 2>&1; then
  IS_GIT=1
fi

# ---------------------------------------------------------------- summary

printf '\n'
info "Dropjak update plan"
cat <<EOF
  Repository:              $SCRIPT_DIR
  Backup directory:        $BACKUP_DIR  (mode 0700)
    Configuration backup:  $CONFIG_BACKUP
    Docker state backup:   $DOCKER_STATE_BACKUP  (if $STATE_VOLUME exists)
    Native state backup:   $NATIVE_STATE_BACKUP  (if $STATE_DIR exists)
  Git update:              git -C "$SCRIPT_DIR" pull --ff-only
EOF
if [[ $IS_GIT -eq 0 ]]; then
  cat <<EOF
  Note:                    $SCRIPT_DIR is not a git repository; a real run
                           stops after the backup
EOF
fi

if [[ $DRY_RUN -eq 1 ]]; then
  info "dry run: nothing will be changed"
elif [[ $ASSUME_YES -eq 0 ]]; then
  printf '\n'
  printf 'Continue with the backup and the fast-forward pull? [y/N] '
  answer=""
  read -r answer || true
  case "$answer" in
    y|Y|yes|YES) ;;
    *) die "aborted: no changes were made" ;;
  esac
fi

# ---------------------------------------------------------------- backup

STAGE_DIR=""
cleanup() {
  if [[ -n "$STAGE_DIR" && -d "$STAGE_DIR" ]]; then
    rm -rf -- "$STAGE_DIR"
  fi
}
trap cleanup EXIT

backup_config() {
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '[dry-run] mktemp -d\n'
    if [[ $HAS_ENV -eq 1 ]]; then
      printf '[dry-run] cp -a -- %q <staging>/env\n' "$SCRIPT_DIR/.env"
    fi
    if [[ $HAS_SECRETS -eq 1 ]]; then
      printf '[dry-run] cp -a -- %q <staging>/secrets\n' "$SCRIPT_DIR/secrets"
    fi
    if [[ $HAS_SYSTEMD -eq 1 ]]; then
      printf '[dry-run] cp -a -- %q <staging>/systemd\n' "$SYSTEMD_DROPIN"
    fi
    printf '[dry-run] tar -czf %q -C <staging> .\n' "$CONFIG_BACKUP"
    printf '[dry-run] chmod 600 %q\n' "$CONFIG_BACKUP"
    info "configuration backup would be: $CONFIG_BACKUP"
    return 0
  fi

  STAGE_DIR="$(mktemp -d)" || die "cannot create a staging directory"
  if [[ $HAS_ENV -eq 1 ]]; then
    cp -a -- "$SCRIPT_DIR/.env" "$STAGE_DIR/env" \
      || die "cannot copy .env into the backup"
  fi
  if [[ $HAS_SECRETS -eq 1 ]]; then
    cp -a -- "$SCRIPT_DIR/secrets" "$STAGE_DIR/secrets" \
      || die "cannot copy secrets/ into the backup"
  fi
  if [[ $HAS_SYSTEMD -eq 1 ]]; then
    cp -a -- "$SYSTEMD_DROPIN" "$STAGE_DIR/systemd" \
      || die "cannot copy the systemd drop-in into the backup"
  fi

  tar -czf "$CONFIG_BACKUP" -C "$STAGE_DIR" . \
    || die "backup failed: $CONFIG_BACKUP"
  chmod 600 -- "$CONFIG_BACKUP" \
    || die "cannot set mode 0600 on $CONFIG_BACKUP"
  info "configuration backup: $CONFIG_BACKUP"
}

backup_state() {
  local source="$1" destination="$2" label="$3"

  if [[ $DRY_RUN -eq 1 ]]; then
    printf '[dry-run] tar -czf %q -C %q .\n' "$destination" "$source"
    printf '[dry-run] chmod 600 %q\n' "$destination"
    info "$label state backup would be: $destination"
    return 0
  fi

  tar -czf "$destination" -C "$source" . \
    || die "backup failed: $destination"
  chmod 600 -- "$destination" \
    || die "cannot set mode 0600 on $destination"
  info "$label state backup: $destination"
}

backup_config

if [[ $DRY_RUN -eq 1 ]]; then
  # Print both candidate paths without needing root to inspect them.
  backup_state "$STATE_VOLUME" "$DOCKER_STATE_BACKUP" "Docker"
  backup_state "$STATE_DIR" "$NATIVE_STATE_BACKUP" "native"
else
  found_state=0
  if [[ -d "$STATE_VOLUME" ]]; then
    backup_state "$STATE_VOLUME" "$DOCKER_STATE_BACKUP" "Docker"
    found_state=1
  fi
  if [[ -d "$STATE_DIR" ]]; then
    backup_state "$STATE_DIR" "$NATIVE_STATE_BACKUP" "native"
    found_state=1
  fi
  if [[ $found_state -eq 0 ]]; then
    warn "no state directory was found ($STATE_VOLUME, $STATE_DIR); only the configuration backup was made"
  fi
fi

# ---------------------------------------------------------------- git update

if [[ $IS_GIT -eq 0 ]]; then
  if [[ $DRY_RUN -eq 1 ]]; then
    warn "$SCRIPT_DIR is not a git repository; a real run would stop after the backup"
    info "dry run: nothing was changed"
    exit 0
  fi
  die "not a git repository: $SCRIPT_DIR (the backup was created successfully; the pull was not run)"
fi

branch="$(git -c "safe.directory=$SCRIPT_DIR" -C "$SCRIPT_DIR" \
  rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
before="$(git -c "safe.directory=$SCRIPT_DIR" -C "$SCRIPT_DIR" \
  rev-parse --short HEAD 2>/dev/null || true)"
info "branch: ${branch:-unknown}, commit before pull: ${before:-unknown}"

if ! run git -c "safe.directory=$SCRIPT_DIR" -C "$SCRIPT_DIR" pull --ff-only; then
  warn "git pull --ff-only failed; the backup is intact and the pull was not applied"
  warn "archive: $CONFIG_BACKUP"
  exit 1
fi

if [[ $DRY_RUN -eq 1 ]]; then
  printf '[dry-run] git -c safe.directory=%q -C %q rev-parse --short HEAD\n' \
    "$SCRIPT_DIR" "$SCRIPT_DIR"
  info "dry run: nothing was changed"
  exit 0
fi

after="$(git -c "safe.directory=$SCRIPT_DIR" -C "$SCRIPT_DIR" \
  rev-parse --short HEAD 2>/dev/null || true)"
info "commit after pull: ${after:-unknown}"

# ---------------------------------------------------------------- follow-up

info "the update is in the checkout; the script did not apply it"
if [[ -f "$SCRIPT_DIR/docker-compose.yml" ]]; then
  info "Docker deployment — rebuild and recreate:"
  if [[ -x "$SCRIPT_DIR/deploy/hv" ]]; then
    printf '  sudo %s rebuild\n' "$SCRIPT_DIR/deploy/hv"
  else
    printf '  DOCKER_BUILDKIT=0 docker build --network host -t dropjak:2 .\n'
    printf '  docker compose up -d --force-recreate\n'
  fi
fi
if [[ -f "$SCRIPT_DIR/install.sh" ]]; then
  info "native deployment — re-run the installer with the same arguments as before:"
  printf '  sudo ./install.sh <the original arguments>\n'
fi
