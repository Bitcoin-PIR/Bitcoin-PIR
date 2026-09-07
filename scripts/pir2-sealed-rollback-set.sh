#!/usr/bin/env bash
# Explicit rollback set for the pir2 sealed data directory (pain point 13).
#
# Runs on the VPSBG stock rootfs inside a Flow F window (as root), or anywhere
# with --root pointing at a copy. A rollback set is the four files a previous
# measured image needs to serve again: credentials.envelope.bin, release.bin,
# identity.cert, and that image's Ready startup.env. `preserve` copies them
# before a new image's Observe startup is placed, `detach-envelope` removes the
# canonical envelope only when the set still matches it (so Enroll on the new
# image mints a fresh one), and `restore` puts the set back for a rollback.
set -euo pipefail

usage() { cat <<'USAGE'
usage: scripts/pir2-sealed-rollback-set.sh preserve        --label LABEL [--root DIR] [--startup-from FILE]
       scripts/pir2-sealed-rollback-set.sh verify          --label LABEL [--root DIR]
       scripts/pir2-sealed-rollback-set.sh detach-envelope --label LABEL [--root DIR] (--dry-run | --apply)
       scripts/pir2-sealed-rollback-set.sh restore         --label LABEL [--root DIR] (--dry-run | --apply)

--root defaults to /home/pir/data/pir2-sealed. The set lives in ROOT/rollback/LABEL/
(directory 0700, files 0600) with MANIFEST.sha256 covering all four files.
preserve requires the current startup.env to be a Ready file (phase=ready) unless
--startup-from names the previous image's Ready startup explicitly; it never
overwrites an existing label. detach-envelope and restore mutate ROOT and need
--apply; --dry-run prints the plan. Every action ends with PASS and NEXT_STEP.
USAGE
}

FILES=(credentials.envelope.bin release.bin identity.cert startup.env)
if command -v sha256sum >/dev/null 2>&1; then
  hash_one() { sha256sum "$1" | awk '{print $1}'; }
else
  hash_one() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

action=${1:-}
case "$action" in
  -h|--help|'') usage; [[ -n "$action" ]] && exit 0 || exit 2 ;;
  preserve|verify|detach-envelope|restore) shift ;;
  *) echo "unknown action: $action" >&2; usage >&2; exit 2 ;;
esac
root=/home/pir/data/pir2-sealed; label=; startup_from=; apply=0; dry_run=0
while (($#)); do
  case "$1" in
    --root) root=${2:?--root requires a directory}; shift 2 ;;
    --label) label=${2:?--label requires a value}; shift 2 ;;
    --startup-from) startup_from=${2:?--startup-from requires a file}; shift 2 ;;
    --apply) apply=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ "$label" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$ ]] || { echo "--label must be 1-80 characters of [A-Za-z0-9._-]" >&2; exit 2; }
[[ -d "$root" ]] || { echo "root is not a directory: $root" >&2; exit 2; }
set_dir=$root/rollback/$label
manifest=$set_dir/MANIFEST.sha256

verify_set() {
  [[ -d "$set_dir" ]] || { echo "rollback set missing: $set_dir" >&2; return 1; }
  [[ -f "$manifest" ]] || { echo "rollback set has no MANIFEST.sha256: $set_dir" >&2; return 1; }
  local f want have
  for f in "${FILES[@]}"; do
    [[ -f "$set_dir/$f" ]] || { echo "rollback set lacks $f" >&2; return 1; }
    want=$(awk -v n="$f" '$2==n{print $1}' "$manifest")
    [[ "$want" =~ ^[0-9a-f]{64}$ ]] || { echo "MANIFEST.sha256 has no entry for $f" >&2; return 1; }
    have=$(hash_one "$set_dir/$f")
    [[ "$have" == "$want" ]] || { echo "rollback set file changed: $f" >&2; return 1; }
    echo "verified $f sha256=$have"
  done
}

startup_phase() { awk -F= '$1=="phase"{print $2; exit}' "$1"; }

case "$action" in
  preserve)
    echo "[stage] preserve rollback set $label from $root"
    [[ ! -e "$set_dir" ]] || { echo "rollback set already exists: $set_dir" >&2; exit 1; }
    for f in credentials.envelope.bin release.bin identity.cert; do
      [[ -f "$root/$f" ]] || { echo "missing $root/$f" >&2; exit 1; }
    done
    if [[ -n "$startup_from" ]]; then
      [[ -f "$startup_from" ]] || { echo "missing --startup-from file: $startup_from" >&2; exit 1; }
    else
      startup_from=$root/startup.env
      [[ -f "$startup_from" ]] || { echo "missing $startup_from (pass --startup-from for the previous Ready startup)" >&2; exit 1; }
    fi
    phase=$(startup_phase "$startup_from")
    [[ "$phase" == ready ]] || { echo "startup file is phase=${phase:-unknown}, not ready: $startup_from (preserve before placing the next Observe, or pass --startup-from)" >&2; exit 1; }
    umask 077
    mkdir -p "$root/rollback"; mkdir "$set_dir"; chmod 700 "$set_dir"
    for f in credentials.envelope.bin release.bin identity.cert; do cp -p "$root/$f" "$set_dir/$f"; done
    cp -p "$startup_from" "$set_dir/startup.env"
    : > "$manifest"
    for f in "${FILES[@]}"; do chmod 600 "$set_dir/$f"; printf '%s  %s\n' "$(hash_one "$set_dir/$f")" "$f" >> "$manifest"; done
    chmod 600 "$manifest"
    for f in credentials.envelope.bin release.bin identity.cert; do
      [[ "$(hash_one "$root/$f")" == "$(awk -v n="$f" '$2==n{print $1}' "$manifest")" ]] || { echo "copy mismatch for $f" >&2; exit 1; }
    done
    verify_set
    echo "rollback_set=$set_dir"
    echo "PASS action=preserve label=$label"
    echo "NEXT_STEP=place the next Observe startup.env; run detach-envelope --apply in the Enroll window"
    ;;
  verify)
    echo "[stage] verify rollback set $label"
    verify_set
    echo "PASS action=verify label=$label"
    echo "NEXT_STEP=the set is intact; restore --apply reinstates it for a rollback to its image"
    ;;
  detach-envelope)
    echo "[stage] detach the canonical envelope (rollback set $label must match it)"
    verify_set
    canon=$root/credentials.envelope.bin
    if [[ -f "$canon" ]]; then
      [[ "$(hash_one "$canon")" == "$(awk '$2=="credentials.envelope.bin"{print $1}' "$manifest")" ]] \
        || { echo "canonical envelope differs from the rollback set; refusing to remove it" >&2; exit 1; }
      state=present
    else
      state=absent
    fi
    echo "canonical_envelope=$state"
    if ((dry_run)) || ((!apply)); then
      echo "planned_remove=$canon"
      echo "PASS action=detach-envelope label=$label dry_run=true"
      echo "NEXT_STEP=run with --apply inside the Enroll window, then place the new release and Enroll startup"
      exit 0
    fi
    [[ "$state" == present ]] && rm -f "$canon"
    [[ ! -e "$canon" ]] || { echo "failed to remove $canon" >&2; exit 1; }
    echo "envelope_removed=true"
    echo "PASS action=detach-envelope label=$label"
    echo "NEXT_STEP=place the new release.bin and the Enroll startup.env, then close onto the new image"
    ;;
  restore)
    echo "[stage] restore rollback set $label into $root"
    verify_set
    if ((dry_run)) || ((!apply)); then
      for f in "${FILES[@]}"; do echo "planned_copy=$set_dir/$f -> $root/$f"; done
      echo "PASS action=restore label=$label dry_run=true"
      echo "NEXT_STEP=run with --apply inside a Flow F window, then close onto the set's image"
      exit 0
    fi
    umask 077
    for f in "${FILES[@]}"; do
      cp -p "$set_dir/$f" "$root/.$f.rollback.tmp"
      mv -f "$root/.$f.rollback.tmp" "$root/$f"
      [[ "$(hash_one "$root/$f")" == "$(awk -v n="$f" '$2==n{print $1}' "$manifest")" ]] || { echo "restore mismatch for $f" >&2; exit 1; }
      echo "restored $f"
    done
    echo "PASS action=restore label=$label"
    echo "NEXT_STEP=close the window onto the image this set belongs to, then run scripts/pir2-post-switch-check.sh"
    ;;
esac
