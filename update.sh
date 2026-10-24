#!/usr/bin/env bash
#
# Dropjak — updater
#
# Makes a backup of the configuration and the runtime state, writes an update
# manifest (previous commit, branch, deployment style, compose image and the
# archive names; restore.sh reads it), tags the current Compose image as
# dropjak:pre-update-<timestamp>, then performs a fast-forward-only git pull
# in the installation directory (the checkout the script runs from). The
# backup is always written outside the repository, by default to
# /root/dropjak-backups, so the working tree stays clean.
#
# Usage:
#   sudo ./update.sh [--yes] [--dry-run] [--backup-only]
#
#   --yes          do not ask for confirmation
#   --dry-run      print the commands and the backup paths, change nothing;
#                  works without root (also: -n)
#   --backup-only  back up, write the manifest and tag the image, but do not
#                  pull (restore.sh uses it for its safety backup)
#   -h, --help     show this help
#
# Environment:
#   HV_BACKUPS          backup directory (default: /root/dropjak-backups)
#   HV_PRE_UPDATE_KEEP  how many dropjak:pre-update-* image tags an update
#                       keeps (default: 3)
#
set -euo pipefail

STATE_VOLUME="/var/lib/docker/volumes/dropjak-state/_data"
STATE_DIR="/var/lib/hatarvedelem"
SYSTEMD_DROPIN="/etc/systemd/system/dropjak.service.d"
SYSTEMD_HELPER_DROPIN="/etc/systemd/system/dropjak-helper.service.d"
PORTAL_UNIT_FILE="/etc/systemd/system/dropjak.service"
PRE_UPDATE_REPO="dropjak"
PRE_UPDATE_KEEP="${HV_PRE_UPDATE_KEEP:-3}"

ASSUME_YES=0
DRY_RUN=0
BACKUP_ONLY=0

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
Usage: sudo ./update.sh [--yes] [--dry-run] [--backup-only]

  --yes          do not ask for confirmation
  --dry-run      print the commands and the backup paths, change nothing
                 (also: -n); works without root
  --backup-only  back up, write the manifest and tag the image, but do not
                 pull (restore.sh uses this for its safety backup)
  -h, --help     this help

The script backs up the configuration and the runtime state to
/root/dropjak-backups (mode 0700, archives 0600), writes the update manifest
dropjak-<timestamp>.manifest next to the archives (previous commit, branch,
timestamp, deployment style, compose image and image ID, archive names),
tags the current Compose image as dropjak:pre-update-<timestamp> (an update
keeps the newest 3 pre-update tags; HV_PRE_UPDATE_KEEP changes that) and
then runs `git pull --ff-only` in the checkout it runs from. The backup never
goes into the repository. After a successful pull it only prints the commands
needed for the deployment to take effect. ./restore.sh returns to the state
recorded in a manifest.

HV_BACKUPS overrides the backup directory. The script itself never runs
the rebuild or reinstall step.
EOF
}

# ---------------------------------------------------------------- arguments

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes)        ASSUME_YES=1; shift ;;
    --dry-run|-n) DRY_RUN=1; shift ;;
    --backup-only) BACKUP_ONLY=1; shift ;;
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

BACKUP_DIR="${HV_BACKUPS:-/root/dropjak-backups}"

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
CONFIG_BACKUP="$BACKUP_DIR/dropjak-$TS.tar.gz"
DOCKER_STATE_BACKUP="$BACKUP_DIR/dropjak-state-$TS.tar.gz"
NATIVE_STATE_BACKUP="$BACKUP_DIR/dropjak-state-native-$TS.tar.gz"

HAS_ENV=0
[[ -f "$SCRIPT_DIR/.env" ]] && HAS_ENV=1
HAS_SECRETS=0
[[ -d "$SCRIPT_DIR/secrets" ]] && HAS_SECRETS=1
HAS_SYSTEMD=0
[[ -d "$SYSTEMD_DROPIN" ]] && HAS_SYSTEMD=1
HAS_SYSTEMD_HELPER=0
[[ -d "$SYSTEMD_HELPER_DROPIN" ]] && HAS_SYSTEMD_HELPER=1

IS_GIT=0
if git -c "safe.directory=$SCRIPT_DIR" -C "$SCRIPT_DIR" rev-parse --git-dir \
    >/dev/null 2>&1; then
  IS_GIT=1
fi

MANIFEST="$BACKUP_DIR/dropjak-$TS.manifest"
if [[ -e "$MANIFEST" || -e "$CONFIG_BACKUP" ]]; then
  die "a backup with the timestamp $TS already exists in $BACKUP_DIR; run again in a second"
fi

# The deployment style, detected like uninstall.sh and start.sh: a checkout
# with docker-compose.yml and .env is Compose, an installed dropjak.service
# is native.
STYLE="unknown"
if [[ -f "$SCRIPT_DIR/docker-compose.yml" && $HAS_ENV -eq 1 ]]; then
  STYLE="compose"
elif [[ -e "$PORTAL_UNIT_FILE" ]]; then
  STYLE="native"
elif [[ -f "$SCRIPT_DIR/docker-compose.yml" ]]; then
  STYLE="compose"
fi

# Compose: the image the compose file runs, and its current ID. The image is
# tagged as dropjak:pre-update-<timestamp> so restore.sh can bring it back.
COMPOSE_IMAGE=""
COMPOSE_IMAGE_ID=""
PRE_UPDATE_TAG=""
DOCKER_OK=0
if [[ "$STYLE" == "compose" ]]; then
  COMPOSE_IMAGE="$(sed -n 's/^[[:space:]]*image:[[:space:]]*\(dropjak[^[:space:]]*\).*/\1/p' \
    "$SCRIPT_DIR/docker-compose.yml" | head -n 1 || true)"
  [[ -n "$COMPOSE_IMAGE" ]] || COMPOSE_IMAGE="dropjak:2"
  if command -v docker >/dev/null 2>&1 \
      && docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
    DOCKER_OK=1
    COMPOSE_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$COMPOSE_IMAGE" \
      2>/dev/null || true)"
  fi
  if [[ -n "$COMPOSE_IMAGE_ID" || ( $DRY_RUN -eq 1 && $DOCKER_OK -eq 0 ) ]]; then
    PRE_UPDATE_TAG="$PRE_UPDATE_REPO:pre-update-$TS"
  fi
fi
[[ "$PRE_UPDATE_KEEP" =~ ^[0-9]+$ && "$PRE_UPDATE_KEEP" -ge 1 ]] \
  || die "HV_PRE_UPDATE_KEEP must be a positive number: $PRE_UPDATE_KEEP"

GIT_COMMIT=""
GIT_BRANCH=""
if [[ $IS_GIT -eq 1 ]]; then
  GIT_COMMIT="$(git -c "safe.directory=$SCRIPT_DIR" -C "$SCRIPT_DIR" \
    rev-parse HEAD 2>/dev/null || true)"
  GIT_BRANCH="$(git -c "safe.directory=$SCRIPT_DIR" -C "$SCRIPT_DIR" \
    symbolic-ref --short -q HEAD 2>/dev/null || true)"
fi
VERSION=""
if [[ -r "$SCRIPT_DIR/VERSION" ]]; then
  VERSION="$(head -n 1 "$SCRIPT_DIR/VERSION" | tr -cd 'A-Za-z0-9.+-' || true)"
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
    Update manifest:       $MANIFEST
  Deployment style:        $STYLE
EOF
if [[ "$STYLE" == "compose" ]]; then
  cat <<EOF
  Compose image:           $COMPOSE_IMAGE${COMPOSE_IMAGE_ID:+  ($COMPOSE_IMAGE_ID)}
  Pre-update tag:          ${PRE_UPDATE_TAG:-none (the image does not exist locally)}
EOF
fi
if [[ $BACKUP_ONLY -eq 1 ]]; then
  cat <<EOF
  Git update:              skipped (--backup-only)
EOF
else
  cat <<EOF
  Git update:              git -C "$SCRIPT_DIR" pull --ff-only
EOF
fi
if [[ $IS_GIT -eq 0 && $BACKUP_ONLY -eq 0 ]]; then
  cat <<EOF
  Note:                    $SCRIPT_DIR is not a git repository; a real run
                           stops after the backup
EOF
fi

if [[ $DRY_RUN -eq 1 ]]; then
  info "dry run: nothing will be changed"
elif [[ $ASSUME_YES -eq 0 ]]; then
  printf '\n'
  if [[ $BACKUP_ONLY -eq 1 ]]; then
    printf 'Continue with the backup? [y/N] '
  else
    printf 'Continue with the backup and the fast-forward pull? [y/N] '
  fi
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
    if [[ $HAS_SYSTEMD_HELPER -eq 1 ]]; then
      printf '[dry-run] cp -a -- %q <staging>/systemd-helper\n' "$SYSTEMD_HELPER_DROPIN"
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
  if [[ $HAS_SYSTEMD_HELPER -eq 1 ]]; then
    cp -a -- "$SYSTEMD_HELPER_DROPIN" "$STAGE_DIR/systemd-helper" \
      || die "cannot copy the helper's systemd drop-in into the backup"
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

# The archive names that go into the manifest (relative to BACKUP_DIR).
DOCKER_STATE_NAME=""
NATIVE_STATE_NAME=""
if [[ $DRY_RUN -eq 1 ]]; then
  # Print both candidate paths without needing root to inspect them.
  backup_state "$STATE_VOLUME" "$DOCKER_STATE_BACKUP" "Docker"
  backup_state "$STATE_DIR" "$NATIVE_STATE_BACKUP" "native"
  DOCKER_STATE_NAME="$(basename -- "$DOCKER_STATE_BACKUP")"
  NATIVE_STATE_NAME="$(basename -- "$NATIVE_STATE_BACKUP")"
else
  found_state=0
  if [[ -d "$STATE_VOLUME" ]]; then
    backup_state "$STATE_VOLUME" "$DOCKER_STATE_BACKUP" "Docker"
    DOCKER_STATE_NAME="$(basename -- "$DOCKER_STATE_BACKUP")"
    found_state=1
  fi
  if [[ -d "$STATE_DIR" ]]; then
    backup_state "$STATE_DIR" "$NATIVE_STATE_BACKUP" "native"
    NATIVE_STATE_NAME="$(basename -- "$NATIVE_STATE_BACKUP")"
    found_state=1
  fi
  if [[ $found_state -eq 0 ]]; then
    warn "no state directory was found ($STATE_VOLUME, $STATE_DIR); only the configuration backup was made"
  fi
fi

# ---------------------------------------------------------------- image tag

# Compose: keep the running image reachable as dropjak:pre-update-<ts>; a
# rebuild after the pull would otherwise leave it dangling.
if [[ -n "$PRE_UPDATE_TAG" ]]; then
  info "tagging $COMPOSE_IMAGE as $PRE_UPDATE_TAG"
  if ! run docker tag "$COMPOSE_IMAGE" "$PRE_UPDATE_TAG"; then
    warn "could not tag $COMPOSE_IMAGE as $PRE_UPDATE_TAG; restore.sh will rebuild the image instead"
    PRE_UPDATE_TAG=""
  fi
elif [[ "$STYLE" == "compose" ]]; then
  warn "the image $COMPOSE_IMAGE was not found locally; no pre-update tag was made"
fi

# ---------------------------------------------------------------- manifest

# Plain key=value lines; restore.sh parses them and never sources the file.
manifest_content() {
  local kind="update"
  [[ $BACKUP_ONLY -eq 0 ]] || kind="backup"
  cat <<EOF
# Dropjak update manifest (read by restore.sh)
format=1
kind=$kind
timestamp=$TS
created=$(date '+%Y-%m-%dT%H:%M:%S%z')
style=$STYLE
checkout=$SCRIPT_DIR
commit=$GIT_COMMIT
branch=$GIT_BRANCH
version=$VERSION
compose_image=$COMPOSE_IMAGE
compose_image_id=$COMPOSE_IMAGE_ID
pre_update_tag=$PRE_UPDATE_TAG
config_backup=$(basename -- "$CONFIG_BACKUP")
docker_state_backup=$DOCKER_STATE_NAME
native_state_backup=$NATIVE_STATE_NAME
EOF
}

if [[ $DRY_RUN -eq 1 ]]; then
  printf '[dry-run] write %q (mode 0600):\n' "$MANIFEST"
  manifest_content | sed 's/^/[dry-run]   /'
else
  manifest_content > "$MANIFEST.tmp" \
    || die "cannot write the manifest: $MANIFEST"
  chmod 600 -- "$MANIFEST.tmp" \
    || die "cannot set mode 0600 on $MANIFEST.tmp"
  mv -f -- "$MANIFEST.tmp" "$MANIFEST" \
    || die "cannot write the manifest: $MANIFEST"
  info "update manifest: $MANIFEST"
fi

# Keep the newest PRE_UPDATE_KEEP pre-update tags; only those tags are ever
# removed, and only by an update (a --backup-only run never prunes, so a
# restore cannot drop the image it is about to restore).
if [[ "$STYLE" == "compose" && $BACKUP_ONLY -eq 0 && $DOCKER_OK -eq 1 ]]; then
  pre_update_tags=()
  while IFS= read -r tag; do
    [[ -n "$tag" ]] && pre_update_tags+=("$tag")
  done < <(docker images --format '{{.Repository}}:{{.Tag}}' "$PRE_UPDATE_REPO" 2>/dev/null \
             | grep -E "^${PRE_UPDATE_REPO}:pre-update-[0-9]{8}-[0-9]{6}\$" \
             | sort -r || true)
  if [[ -n "$PRE_UPDATE_TAG" && $DRY_RUN -eq 1 ]]; then
    # The dry run did not create the new tag; count it anyway.
    pre_update_tags=("$PRE_UPDATE_TAG" ${pre_update_tags[@]+"${pre_update_tags[@]}"})
  fi
  index=0
  for tag in ${pre_update_tags[@]+"${pre_update_tags[@]}"}; do
    index=$((index + 1))
    (( index > PRE_UPDATE_KEEP )) || continue
    info "removing the old pre-update tag $tag"
    run docker rmi "$tag" || warn "could not remove $tag"
  done
fi

if [[ $BACKUP_ONLY -eq 1 ]]; then
  if [[ $DRY_RUN -eq 1 ]]; then
    info "dry run: nothing was changed (--backup-only: no pull)"
  else
    info "backup complete (--backup-only: the pull was not run)"
  fi
  exit 0
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
info "to go back to the state before this update: sudo $SCRIPT_DIR/restore.sh"
info "  (manifest: $MANIFEST)"
