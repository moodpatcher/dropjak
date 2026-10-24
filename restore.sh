#!/usr/bin/env bash
#
# Dropjak — restore the state from before an update
#
# Reads an update manifest written by update.sh (dropjak-<timestamp>.manifest
# in the backup directory) and returns the checkout, the configuration, the
# runtime state and, for Docker Compose, the image to what they were before
# that update. Backups are never deleted.
#
# Usage:
#   sudo ./restore.sh [--list] [--backup TIMESTAMP] [--yes] [--dry-run]
#                     [--timeout SEC] [--detach] [--skip-caddy-validate]
#
# The whole script runs from main() at the very end: bash has parsed all of it
# before `git reset`/`git checkout` can replace this file in the checkout.
#
set -euo pipefail

STATE_VOLUME_NAME="dropjak-state"
STATE_VOLUME_PATH="/var/lib/docker/volumes/dropjak-state/_data"
STATE_DIR="/var/lib/hatarvedelem"
SERVICE_USER="hatarvedelem"
SYSTEMD_DIR="${HV_SYSTEMD_DIR:-/etc/systemd/system}"
PRE_UPDATE_REPO="dropjak"

ASSUME_YES=0
DRY_RUN=0
LIST=0
SELECTED=""
TIMEOUT=120
FORCE_DETACH=0
SKIP_CADDY_VALIDATE=0

# Output never aborts the script: a dropped SSH terminal must not stop a
# restore half-way.
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
Usage: sudo ./restore.sh [--list] [--backup TIMESTAMP] [--yes] [--dry-run]
                         [--timeout SEC] [--detach] [--skip-caddy-validate]

  --list                 list the update backups (manifests) and exit;
                         needs read access to the backup directory only
  --backup TIMESTAMP     restore this backup (e.g. 20261024-153000); default:
                         the newest backup written by an update
  --yes                  do not ask for confirmation (otherwise type RESTORE)
  --dry-run              preview every step, change nothing (also: -n); works
                         without root
  --timeout SEC          how long start.sh waits for a healthy portal
                         (default: 120)
  --detach               check the recorded commit out as a detached HEAD
                         even when the recorded branch is checked out
  --skip-caddy-validate  passed to start.sh
  -h, --help             this help

Steps:
  1. Checks: a git checkout with a clean working tree (no reset over local
     changes: commit or stash them first), the recorded commit exists, the
     archives named in the manifest exist.
  2. Confirmation (type RESTORE, or --yes).
  3. A safety backup of the current state: ./update.sh --backup-only (the
     same archives and manifest; restore it later with --backup to undo).
  4. ./stop.sh (the nftables table stays loaded, fail-closed).
  5. Git: on the recorded branch, `git reset --keep <commit>` moves the
     branch back, so the next ./update.sh fast-forwards to the latest code
     again. It is used only when the commit is an ancestor of HEAD and HEAD
     has no commit missing from the branch's upstream, so no local commit
     drops off the branch. Otherwise (another branch, no upstream, local
     commits, or --detach) it runs `git checkout --detach <commit>`, which
     leaves every branch untouched; `git checkout <branch>` returns later.
  6. .env, secrets/ and the systemd drop-ins from the configuration archive;
     the state: the Docker volume dropjak-state (Compose) or
     /var/lib/hatarvedelem with owner hatarvedelem:hatarvedelem (native).
  7. Compose: dropjak:pre-update-<timestamp> is retagged as the compose
     image (fallback: the recorded image ID, then a host-network rebuild).
     Native: install.sh has no unattended upgrade mode, so the script prints
     the install.sh command that puts the restored code in place.
  8. ./start.sh with its preflight and health wait.

Restoring a commit from before start.sh/stop.sh/restore.sh existed removes
them from the checkout; the next update brings them back.

Environment:
  HV_BACKUPS       backup directory (default: /root/dropjak-backups)
  HV_SYSTEMD_DIR   the systemd unit directory (default: /etc/systemd/system)
EOF
}

# ---------------------------------------------------------------- helpers

g() {
  git -c "safe.directory=$SCRIPT_DIR" -C "$SCRIPT_DIR" "$@"
}

# A value from a manifest (plain key=value; the file is never sourced).
manifest_get() {
  sed -n "s/^$2=//p" "$1" 2>/dev/null | tail -n 1 || true
}

# The manifests in the backup directory, oldest first.
list_manifests() {
  local path name
  for path in "$BACKUP_DIR"/dropjak-*.manifest; do
    [[ -f "$path" ]] || continue
    name="$(basename -- "$path")"
    [[ "$name" =~ ^dropjak-[0-9]{8}-[0-9]{6}\.manifest$ ]] || continue
    printf '%s\n' "$path"
  done | sort
}

docker_ok() {
  command -v docker >/dev/null 2>&1 \
    && docker version --format '{{.Server.Version}}' >/dev/null 2>&1
}

image_exists() {
  [[ -n "$1" ]] && docker image inspect "$1" >/dev/null 2>&1
}

# ---------------------------------------------------------------- --list

show_list() {
  local manifests=() path ts kind style commit branch version tag archives \
    name missing have_docker=0
  while IFS= read -r path; do
    manifests+=("$path")
  done < <(list_manifests)
  if [[ ${#manifests[@]} -eq 0 ]]; then
    info "no update manifests in $BACKUP_DIR"
    return 0
  fi
  docker_ok && have_docker=1
  printf '%-16s %-7s %-8s %-8s %-12s %-9s %-10s %s\n' \
    TIMESTAMP KIND STYLE COMMIT BRANCH VERSION IMAGE ARCHIVES
  for path in "${manifests[@]}"; do
    ts="$(manifest_get "$path" timestamp)"
    kind="$(manifest_get "$path" kind)"
    style="$(manifest_get "$path" style)"
    commit="$(manifest_get "$path" commit)"
    branch="$(manifest_get "$path" branch)"
    version="$(manifest_get "$path" version)"
    tag="$(manifest_get "$path" pre_update_tag)"
    if [[ -z "$tag" ]]; then
      tag="-"
    elif [[ $have_docker -eq 1 ]]; then
      if image_exists "$tag"; then tag="present"; else tag="missing"; fi
    else
      tag="?"
    fi
    missing=""
    for name in "$(manifest_get "$path" config_backup)" \
                "$(manifest_get "$path" docker_state_backup)" \
                "$(manifest_get "$path" native_state_backup)"; do
      [[ -n "$name" ]] || continue
      [[ -f "$BACKUP_DIR/$name" ]] || missing+=" $name"
    done
    if [[ -n "$missing" ]]; then archives="missing:$missing"; else archives="ok"; fi
    printf '%-16s %-7s %-8s %-8s %-12s %-9s %-10s %s\n' \
      "${ts:--}" "${kind:--}" "${style:--}" "${commit:0:7}" "${branch:-(detached)}" \
      "${version:--}" "$tag" "$archives"
  done
  printf '\n'
  info "default: the newest KIND=update entry; pick another with --backup TIMESTAMP"
}

# ---------------------------------------------------------------- selection

select_manifest() {
  local path kind
  if [[ -n "$SELECTED" ]]; then
    [[ "$SELECTED" =~ ^[0-9]{8}-[0-9]{6}$ ]] \
      || die "invalid --backup value (expected YYYYmmdd-HHMMSS): $SELECTED"
    MANIFEST="$BACKUP_DIR/dropjak-$SELECTED.manifest"
    [[ -f "$MANIFEST" ]] \
      || die "no manifest for $SELECTED in $BACKUP_DIR (see: ./restore.sh --list)"
    return 0
  fi
  MANIFEST=""
  while IFS= read -r path; do
    kind="$(manifest_get "$path" kind)"
    [[ "$kind" == "update" ]] && MANIFEST="$path"
  done < <(list_manifests)
  [[ -n "$MANIFEST" ]] \
    || die "no update manifest in $BACKUP_DIR (see: ./restore.sh --list; a backup of another kind can be picked with --backup)"
}

read_manifest() {
  local name
  M_TS="$(manifest_get "$MANIFEST" timestamp)"
  M_KIND="$(manifest_get "$MANIFEST" kind)"
  M_STYLE="$(manifest_get "$MANIFEST" style)"
  M_CHECKOUT="$(manifest_get "$MANIFEST" checkout)"
  M_COMMIT="$(manifest_get "$MANIFEST" commit)"
  M_BRANCH="$(manifest_get "$MANIFEST" branch)"
  M_VERSION="$(manifest_get "$MANIFEST" version)"
  M_IMAGE="$(manifest_get "$MANIFEST" compose_image)"
  M_IMAGE_ID="$(manifest_get "$MANIFEST" compose_image_id)"
  M_TAG="$(manifest_get "$MANIFEST" pre_update_tag)"
  M_CONFIG="$(manifest_get "$MANIFEST" config_backup)"
  M_DOCKER_STATE="$(manifest_get "$MANIFEST" docker_state_backup)"
  M_NATIVE_STATE="$(manifest_get "$MANIFEST" native_state_backup)"

  [[ "$(manifest_get "$MANIFEST" format)" == "1" ]] \
    || die "unsupported manifest format: $MANIFEST"
  [[ "$M_TS" =~ ^[0-9]{8}-[0-9]{6}$ ]] || die "invalid timestamp in $MANIFEST"
  [[ "$M_STYLE" == "compose" || "$M_STYLE" == "native" ]] \
    || die "the manifest does not record a known deployment style (style=$M_STYLE): $MANIFEST"
  [[ "$M_COMMIT" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] \
    || die "the manifest records no git commit (was update.sh run outside a git checkout?): $MANIFEST"
  if [[ -n "$M_BRANCH" ]]; then
    git check-ref-format --branch "$M_BRANCH" >/dev/null 2>&1 \
      || die "invalid branch name in $MANIFEST: $M_BRANCH"
  fi
  for name in "$M_CONFIG" "$M_DOCKER_STATE" "$M_NATIVE_STATE"; do
    [[ -z "$name" || "$name" =~ ^dropjak-[A-Za-z0-9.-]+\.tar\.gz$ ]] \
      || die "invalid archive name in $MANIFEST: $name"
  done
  [[ -n "$M_CONFIG" ]] || die "the manifest names no configuration archive: $MANIFEST"
  if [[ "$M_STYLE" == "compose" ]]; then
    [[ "$M_IMAGE" =~ ^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?$ ]] \
      || die "invalid compose image in $MANIFEST: $M_IMAGE"
    [[ -z "$M_IMAGE_ID" || "$M_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
      || die "invalid image ID in $MANIFEST: $M_IMAGE_ID"
    [[ -z "$M_TAG" || "$M_TAG" =~ ^${PRE_UPDATE_REPO}:pre-update-[0-9]{8}-[0-9]{6}$ ]] \
      || die "invalid pre-update tag in $MANIFEST: $M_TAG"
  fi
}

# ---------------------------------------------------------------- checks

check_git() {
  local status upstream local_only
  g rev-parse --git-dir >/dev/null 2>&1 \
    || die "$SCRIPT_DIR is not a git repository; run restore.sh from the checkout recorded in the manifest: ${M_CHECKOUT:-unknown}"

  status="$(g status --porcelain --untracked-files=no 2>/dev/null)" \
    || die "git status failed in $SCRIPT_DIR"
  if [[ -n "$status" ]]; then
    printf '%s\n' "$status" | sed 's/^/  /' >&2 || true
    die "the working tree has local changes; commit or stash them first (git stash), restore.sh never resets over them"
  fi

  g cat-file -e "${M_COMMIT}^{commit}" 2>/dev/null \
    || die "the recorded commit $M_COMMIT is not in this repository (git fetch may bring it back)"

  CURRENT_COMMIT="$(g rev-parse HEAD)"
  CURRENT_BRANCH="$(g symbolic-ref --short -q HEAD || true)"
  GIT_MODE="detach"
  GIT_REASON=""
  if [[ "$CURRENT_COMMIT" == "$M_COMMIT" ]]; then
    GIT_MODE="none"
    GIT_REASON="HEAD is already at the recorded commit"
  elif [[ $FORCE_DETACH -eq 1 ]]; then
    GIT_REASON="--detach"
  elif [[ -z "$M_BRANCH" ]]; then
    GIT_REASON="the update ran on a detached HEAD"
  elif [[ "$CURRENT_BRANCH" != "$M_BRANCH" ]]; then
    GIT_REASON="the checkout is on ${CURRENT_BRANCH:-a detached HEAD}, not on $M_BRANCH"
  elif ! g merge-base --is-ancestor "$M_COMMIT" HEAD 2>/dev/null; then
    GIT_REASON="the recorded commit is not an ancestor of HEAD"
  else
    upstream="$(g rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
    if [[ -z "$upstream" ]]; then
      GIT_REASON="$M_BRANCH has no upstream, local commits cannot be told apart"
    else
      local_only="$(g rev-list --count "$upstream..HEAD" 2>/dev/null || echo 1)"
      if [[ "$local_only" == "0" ]]; then
        GIT_MODE="reset"
        GIT_REASON="$M_BRANCH has no commit missing from $upstream"
      else
        GIT_REASON="$M_BRANCH has $local_only commit(s) not on $upstream"
      fi
    fi
  fi
}

check_archives() {
  [[ -f "$BACKUP_DIR/$M_CONFIG" ]] || die "configuration archive not found: $BACKUP_DIR/$M_CONFIG"
  STATE_ARCHIVE=""
  if [[ "$M_STYLE" == "compose" ]]; then
    [[ -z "$M_DOCKER_STATE" ]] || STATE_ARCHIVE="$M_DOCKER_STATE"
  else
    [[ -z "$M_NATIVE_STATE" ]] || STATE_ARCHIVE="$M_NATIVE_STATE"
  fi
  if [[ -n "$STATE_ARCHIVE" ]]; then
    [[ -f "$BACKUP_DIR/$STATE_ARCHIVE" ]] \
      || die "state archive not found: $BACKUP_DIR/$STATE_ARCHIVE"
  else
    warn "the manifest names no $M_STYLE state archive; the state is left as it is"
  fi
}

# How the compose image comes back: tag, id or build.
plan_image() {
  IMAGE_PLAN="build"
  [[ "$M_STYLE" == "compose" ]] || { IMAGE_PLAN="none"; return 0; }
  if docker_ok; then
    if [[ -n "$M_TAG" ]] && image_exists "$M_TAG"; then
      IMAGE_PLAN="tag"
    elif [[ -n "$M_IMAGE_ID" ]] && image_exists "$M_IMAGE_ID"; then
      IMAGE_PLAN="id"
    fi
  elif [[ $DRY_RUN -eq 1 && -n "$M_TAG" ]]; then
    IMAGE_PLAN="tag"
  fi
}

# ---------------------------------------------------------------- steps

safety_backup() {
  local before after path args=(--backup-only --yes)
  [[ -f "$SCRIPT_DIR/update.sh" ]] || die "update.sh not found in $SCRIPT_DIR; cannot take the safety backup"
  [[ $DRY_RUN -eq 0 ]] || args+=(--dry-run)
  before="$(list_manifests || true)"
  info "step 1/6: safety backup of the current state (update.sh --backup-only)"
  HV_BACKUPS="$BACKUP_DIR" bash "$SCRIPT_DIR/update.sh" "${args[@]}" \
    || die "the safety backup failed; nothing was changed"
  SAFETY_TS=""
  if [[ $DRY_RUN -eq 0 ]]; then
    after="$(list_manifests || true)"
    while IFS= read -r path; do
      [[ -n "$path" ]] || continue
      grep -qxF -- "$path" <<<"$before" && continue
      SAFETY_TS="$(manifest_get "$path" timestamp)"
    done <<<"$after"
    [[ -n "$SAFETY_TS" ]] && info "safety backup: $SAFETY_TS (undo this restore with: ./restore.sh --backup $SAFETY_TS)"
  fi
  return 0
}

stop_portal() {
  local args=(--yes "--$M_STYLE")
  [[ $DRY_RUN -eq 0 ]] || args+=(--dry-run)
  info "step 2/6: stopping the portal (stop.sh)"
  [[ -f "$SCRIPT_DIR/stop.sh" ]] || die "stop.sh not found in $SCRIPT_DIR"
  bash "$SCRIPT_DIR/stop.sh" "${args[@]}" || die "stop.sh failed; the checkout and the state were not changed"
}

restore_git() {
  info "step 3/6: git ($GIT_REASON)"
  case "$GIT_MODE" in
    none)   info "the checkout is already at ${M_COMMIT:0:12}" ;;
    reset)
      run git -c "safe.directory=$SCRIPT_DIR" -C "$SCRIPT_DIR" reset --keep "$M_COMMIT" \
        || die "git reset --keep $M_COMMIT failed" ;;
    detach)
      run git -c "safe.directory=$SCRIPT_DIR" -C "$SCRIPT_DIR" checkout --detach "$M_COMMIT" \
        || die "git checkout --detach $M_COMMIT failed" ;;
  esac
}

# Replace a file or directory with the copy from the staging directory.
replace_path() {
  local source="$1" target="$2"
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '[dry-run] rm -rf -- %q && cp -a -- <staging>/%s %q\n' "$target" "$(basename -- "$source")" "$target"
    return 0
  fi
  rm -rf -- "$target.restore-tmp"
  cp -a -- "$source" "$target.restore-tmp" || die "cannot copy $source"
  rm -rf -- "$target"
  mv -f -- "$target.restore-tmp" "$target" || die "cannot put $target in place"
}

# Whether the configuration archive holds a top-level entry. In a dry run the
# archive listing decides; an unreadable archive counts every entry as present.
ARCHIVE_MEMBERS=""
in_config() {
  local stage="$1" name="$2"
  if [[ $DRY_RUN -eq 0 ]]; then
    [[ -e "$stage/$name" ]]
  elif [[ -z "$ARCHIVE_MEMBERS" ]]; then
    return 0
  else
    grep -qxF -- "$name" <<<"$ARCHIVE_MEMBERS"
  fi
}

restore_config() {
  local archive="$BACKUP_DIR/$M_CONFIG" stage dropins=0 pair source target
  info "step 4/6: configuration from $M_CONFIG"
  if [[ $DRY_RUN -eq 1 ]]; then
    ARCHIVE_MEMBERS="$(tar -tzf "$archive" 2>/dev/null \
      | sed 's|^\./||; s|/.*||' | grep -v '^$' | sort -u || true)"
    info "archive entries: $(printf '%s' "${ARCHIVE_MEMBERS:-(not readable for this user)}" | tr '\n' ' ')"
    printf '[dry-run] tar -xzf %q -C <staging>\n' "$archive"
    stage="<staging>"
  else
    stage="$(mktemp -d)" || die "cannot create a staging directory"
    STAGES+=("$stage")
    tar -xzf "$archive" -C "$stage" || die "cannot unpack $archive"
  fi

  if in_config "$stage" env; then
    info "restoring .env"
    replace_path "$stage/env" "$SCRIPT_DIR/.env"
    run chmod 600 -- "$SCRIPT_DIR/.env"
  else
    info "the archive has no .env; the current one is kept"
  fi
  if in_config "$stage" secrets; then
    info "restoring secrets/"
    replace_path "$stage/secrets" "$SCRIPT_DIR/secrets"
  else
    info "the archive has no secrets/; the current one is kept"
  fi
  for pair in "systemd:dropjak.service.d" "systemd-helper:dropjak-helper.service.d"; do
    source="$stage/${pair%%:*}"
    target="$SYSTEMD_DIR/${pair#*:}"
    if in_config "$stage" "${pair%%:*}"; then
      info "restoring the systemd drop-in $target"
      replace_path "$source" "$target"
      dropins=1
    fi
  done
  if [[ $dropins -eq 1 ]] && command -v systemctl >/dev/null 2>&1; then
    run systemctl daemon-reload || warn "systemctl daemon-reload failed"
  fi
}

# Unpack into a staging directory first, so a broken archive never leaves a
# half-restored state behind; then replace the contents of the target.
restore_state_into() {
  local archive="$1" target="$2" stage
  [[ "$target" == /?* && "$target" != "/" ]] || die "refusing to restore into: $target"
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '[dry-run] tar -xzf %q -C <staging> --numeric-owner\n' "$archive"
    printf '[dry-run] find %q -mindepth 1 -delete\n' "$target"
    printf '[dry-run] cp -a -- <staging>/. %q/\n' "$target"
    return 0
  fi
  stage="$(mktemp -d)" || die "cannot create a staging directory"
  STAGES+=("$stage")
  tar -xzf "$archive" -C "$stage" --numeric-owner || die "cannot unpack $archive"
  mkdir -p -- "$target"
  find "$target" -mindepth 1 -delete || die "cannot empty $target"
  cp -a -- "$stage/." "$target/" || die "cannot copy the state into $target"
}

restore_state() {
  local archive target
  info "step 5/6: state"
  if [[ -z "$STATE_ARCHIVE" ]]; then
    info "no state archive; the state is left as it is"
    return 0
  fi
  archive="$BACKUP_DIR/$STATE_ARCHIVE"
  if [[ "$M_STYLE" == "compose" ]]; then
    target=""
    if [[ $DRY_RUN -eq 0 ]]; then
      if ! docker volume inspect "$STATE_VOLUME_NAME" >/dev/null 2>&1; then
        info "creating the Docker volume $STATE_VOLUME_NAME"
        docker volume create "$STATE_VOLUME_NAME" >/dev/null \
          || die "cannot create the Docker volume $STATE_VOLUME_NAME"
      fi
      target="$(docker volume inspect -f '{{.Mountpoint}}' "$STATE_VOLUME_NAME" 2>/dev/null || true)"
    fi
    [[ -n "$target" ]] || target="$STATE_VOLUME_PATH"
    info "restoring the Docker volume $STATE_VOLUME_NAME ($target) from $STATE_ARCHIVE"
    restore_state_into "$archive" "$target"
  else
    info "restoring $STATE_DIR from $STATE_ARCHIVE"
    restore_state_into "$archive" "$STATE_DIR"
    run chown -R "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR" \
      || die "cannot set the owner of $STATE_DIR"
    run chmod 0750 "$STATE_DIR" || die "cannot set the mode of $STATE_DIR"
  fi
}

restore_image() {
  case "$IMAGE_PLAN" in
    none) return 0 ;;
    tag)
      info "retagging $M_TAG as $M_IMAGE"
      run docker tag "$M_TAG" "$M_IMAGE" || die "docker tag $M_TAG $M_IMAGE failed"
      ;;
    id)
      warn "$M_TAG is gone; the recorded image ID ${M_IMAGE_ID:7:12} still exists"
      run docker tag "$M_IMAGE_ID" "$M_IMAGE" || die "docker tag $M_IMAGE_ID $M_IMAGE failed"
      ;;
    build)
      warn "neither ${M_TAG:-a pre-update tag} nor the recorded image exists; rebuilding $M_IMAGE from the restored checkout (host network)"
      ( cd -- "$SCRIPT_DIR" && run env DOCKER_BUILDKIT=0 docker build --network host -t "$M_IMAGE" . ) \
        || die "the rebuild failed; build it by hand: DOCKER_BUILDKIT=0 docker build --network host -t $M_IMAGE . && ./start.sh"
      ;;
  esac
}

# install.sh has no unattended upgrade mode: print the command, with the
# values taken from the restored drop-in and the installed portal unit.
print_native_install() {
  local dropin="$SYSTEMD_DIR/dropjak.service.d/10-dropjak-env.conf"
  local unit="$SYSTEMD_DIR/dropjak.service" single wan lan lan_net portal_net port url cmd
  conf_value() {
    sed -n "s/^[[:space:]]*Environment=$2=//p" "$1" 2>/dev/null | tail -n 1 || true
  }
  single="$(conf_value "$dropin" HV_SINGLE_NIC)"
  wan="$(conf_value "$dropin" HV_WAN_IF)"
  lan="$(conf_value "$dropin" HV_LAN_IF)"
  lan_net="$(conf_value "$dropin" HV_LAN_NET)"
  portal_net="$(conf_value "$dropin" HV_PORTAL_NET)"
  port="$(conf_value "$unit" PORT)"
  url="$(conf_value "$unit" HV_PORTAL_URL)"
  cmd="sudo $SCRIPT_DIR/install.sh --wan-if ${wan:-<WAN_IF>}"
  if [[ "$single" == "1" ]]; then
    cmd+=" --single-nic"
  else
    cmd+=" --lan-if ${lan:-<LAN_IF>} --lan-net ${lan_net:-<LAN_NET>}"
  fi
  cmd+=" --portal-net ${portal_net:-<PORTAL_NET>} --port ${port:-80} --portal-url ${url:-<PORTAL_URL>} --skip-user"
  info "native: the restored checkout is not installed yet. install.sh has no"
  info "unattended upgrade mode; put the restored code in place with:"
  printf '  %s\n' "$cmd" || true
  info "(values from $dropin and $unit; add --gateway-ip, --no-forward-nets and"
  info "--route-localnet-ifs if the original installation used them, and --yes"
  info "to skip the prompts. install.sh restarts the services itself.)"
}

start_portal() {
  local args=(--dir "$SCRIPT_DIR" --yes "--$M_STYLE" --timeout "$TIMEOUT")
  [[ $SKIP_CADDY_VALIDATE -eq 0 ]] || args+=(--skip-caddy-validate)
  info "step 6/6: starting the portal (start.sh, with preflight and health wait)"
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '[dry-run] bash <copy of start.sh> %s\n' "${args[*]}"
    info "dry run: start.sh runs its preflight against the restored checkout"
    return 0
  fi
  if ! bash "$START_COPY" "${args[@]}"; then
    warn "the restore was applied, but the portal did not start cleanly"
    [[ -z "${SAFETY_TS:-}" ]] || warn "the state before this restore is in the safety backup $SAFETY_TS"
    die "start.sh failed (backups are intact in $BACKUP_DIR)"
  fi
}

# ---------------------------------------------------------------- main

STAGES=()
cleanup() {
  local dir
  for dir in ${STAGES[@]+"${STAGES[@]}"}; do
    [[ -n "$dir" && -d "$dir" ]] && rm -rf -- "$dir"
  done
  return 0
}

main() {
  local answer ssh_src=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --list)       LIST=1; shift ;;
      --backup)
        [[ $# -ge 2 && -n "$2" ]] || die "--backup needs a timestamp (see: --list)"
        SELECTED="$2"; shift 2 ;;
      --yes)        ASSUME_YES=1; shift ;;
      --dry-run|-n) DRY_RUN=1; shift ;;
      --timeout)
        [[ $# -ge 2 && "${2:-}" =~ ^[0-9]+$ && "$2" -ge 1 ]] \
          || die "--timeout needs a positive number of seconds"
        TIMEOUT="$2"; shift 2 ;;
      --detach)     FORCE_DETACH=1; shift ;;
      --skip-caddy-validate) SKIP_CADDY_VALIDATE=1; shift ;;
      -h|--help)    usage; exit 0 ;;
      *)            die "unknown option: $1 (see: --help)" ;;
    esac
  done

  # The listing and the dry run are read-only and work without root.
  if [[ $DRY_RUN -eq 0 && $LIST -eq 0 && "$(id -u)" -ne 0 ]]; then
    die "this script must be run as root: sudo ./restore.sh"
  fi

  SCRIPT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)" \
    || die "cannot determine the script's directory"
  BACKUP_DIR="${HV_BACKUPS:-/root/dropjak-backups}"
  [[ -d "$BACKUP_DIR" ]] || die "backup directory not found: $BACKUP_DIR"
  [[ -r "$BACKUP_DIR" && -x "$BACKUP_DIR" ]] \
    || die "cannot read the backup directory $BACKUP_DIR (run as root, or set HV_BACKUPS)"

  umask 077
  trap cleanup EXIT

  if [[ $LIST -eq 1 ]]; then
    show_list
    exit 0
  fi

  select_manifest
  read_manifest
  check_git
  check_archives
  plan_image

  [[ -z "${SSH_CONNECTION:-}" ]] || ssh_src="${SSH_CONNECTION%% *}"
  if [[ -n "$M_CHECKOUT" && "$M_CHECKOUT" != "$SCRIPT_DIR" ]]; then
    warn "the manifest was written in $M_CHECKOUT, this checkout is $SCRIPT_DIR"
  fi

  # ------------------------------------------------------------ summary

  local git_plan="no change" state_plan="left as it is"
  [[ -z "$STATE_ARCHIVE" ]] || state_plan="$BACKUP_DIR/$STATE_ARCHIVE"
  if [[ "$GIT_MODE" == "reset" ]]; then
    git_plan="git reset --keep ${M_COMMIT:0:12} (on $M_BRANCH)"
  elif [[ "$GIT_MODE" == "detach" ]]; then
    git_plan="git checkout --detach ${M_COMMIT:0:12}"
  fi

  printf '\n'
  info "Dropjak restore plan"
  cat <<EOF
  Backup:                $M_TS ($M_KIND, $MANIFEST)
  Deployment:            $M_STYLE
  Checkout:              $SCRIPT_DIR
  Git:                   $git_plan
                         ($GIT_REASON)
  Version:               ${M_VERSION:-unknown}
  Configuration:         $BACKUP_DIR/$M_CONFIG (.env, secrets/, systemd drop-ins)
  State:                 $state_plan
EOF
  if [[ "$M_STYLE" == "compose" ]]; then
    case "$IMAGE_PLAN" in
      tag)   printf '  Image:                 docker tag %s %s\n' "$M_TAG" "$M_IMAGE" ;;
      id)    printf '  Image:                 docker tag %s %s (the tag is gone)\n' "$M_IMAGE_ID" "$M_IMAGE" ;;
      build) printf '  Image:                 host-network rebuild of %s (no pre-update image left)\n' "$M_IMAGE" ;;
    esac
  else
    printf '  Code:                  install.sh from the restored checkout (printed, not run)\n'
  fi
  cat <<EOF
  First:                 a safety backup of the current state (update.sh --backup-only)
  Then:                  stop.sh, restore, start.sh (preflight, health wait)
  Backups:               never deleted
EOF

  if [[ -n "$ssh_src" ]]; then
    warn "you are connected over SSH from $ssh_src. The restart flushes every"
    warn "grant, including this session's; re-authorize TCP 22 in the portal"
    warn "afterwards. Prefer running detached:"
    warn "  nohup $SCRIPT_DIR/restore.sh --yes ${SELECTED:+--backup $SELECTED }> /root/dropjak-restore.log 2>&1 &"
  fi

  if [[ $DRY_RUN -eq 1 ]]; then
    info "dry run: nothing will be changed"
  elif [[ $ASSUME_YES -eq 0 ]]; then
    printf '\n'
    printf 'Type RESTORE to continue: '
    answer=""
    read -r answer || true
    [[ "$answer" == "RESTORE" ]] || die "aborted: the confirmation did not match RESTORE"
  fi

  # A lost SSH terminal must not kill the restore half-way.
  trap '' HUP

  # start.sh may not exist in the restored commit: keep a copy of this one.
  START_COPY=""
  if [[ $DRY_RUN -eq 0 ]]; then
    [[ -f "$SCRIPT_DIR/start.sh" ]] || die "start.sh not found in $SCRIPT_DIR"
    local copy_dir
    copy_dir="$(mktemp -d)" || die "cannot create a temporary directory"
    STAGES+=("$copy_dir")
    cp -- "$SCRIPT_DIR/start.sh" "$copy_dir/start.sh" || die "cannot copy start.sh"
    START_COPY="$copy_dir/start.sh"
  fi

  safety_backup
  stop_portal
  restore_git
  restore_config
  restore_state
  restore_image
  [[ "$M_STYLE" != "native" ]] || print_native_install
  start_portal

  if [[ $DRY_RUN -eq 1 ]]; then
    info "dry run: nothing was changed"
    exit 0
  fi
  info "restored the state of $M_TS (commit ${M_COMMIT:0:12})"
  if [[ "$GIT_MODE" == "detach" ]]; then
    info "the checkout is on a detached HEAD; before the next update run:"
    info "  git -C $SCRIPT_DIR checkout ${M_BRANCH:-<branch>}"
  fi
  info "log in to the portal again and re-authorize host SSH (TCP 22) if needed"
}

main "$@"; exit $?
