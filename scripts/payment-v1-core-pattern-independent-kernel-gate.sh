#!/bin/sh
set -eu

expected_ack='I_UNDERSTAND_THIS_MUTATES_ONLY_A_DISPOSABLE_INDEPENDENT_KERNEL_VM'
run_id=${BITCOINPIR_CORE_PATTERN_VM_RUN_ID-}
matrix_sha256=${BITCOINPIR_CORE_PATTERN_MATRIX_SHA256-}
marker_root=/run/bitcoinpir-core-pattern-independent-kernel

usage() {
  cat >&2 <<'EOF'
usage: payment-v1-core-pattern-independent-kernel-gate.sh -- /absolute/reviewed-matrix [args...]

The caller must provision a disposable VM with its own kernel and boot it with
bitcoinpir.core_pattern_vm_run_id=<UUID>. Set the matching
BITCOINPIR_CORE_PATTERN_VM_RUN_ID and the explicit guest acknowledgement.
Bind the reviewed matrix bytes with BITCOINPIR_CORE_PATTERN_MATRIX_SHA256.
This gate never creates a VM and is never run automatically by CI.
EOF
  exit 64
}

[ "${1-}" = -- ] || usage
shift
[ "$#" -ge 1 ] || usage
command_path=$1

[ "$(id -u)" -eq 0 ] || { echo 'independent-kernel gate requires guest EUID 0' >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo 'independent-kernel gate requires Linux' >&2; exit 1; }
[ "$(cat /proc/1/comm)" = systemd ] || { echo 'guest PID 1 is not systemd' >&2; exit 1; }

container_kind=$(systemd-detect-virt --container 2>/dev/null || true)
case "$container_kind" in
  ''|none) ;;
  *) echo "refusing shared-kernel container virtualization: $container_kind" >&2; exit 1 ;;
esac

vm_kind=$(systemd-detect-virt --vm 2>/dev/null || true)
case "$vm_kind" in
  kvm|qemu|amazon|apple|bhyve|google|microsoft|oracle|parallels|vmware|xen) ;;
  *) echo "independent VM virtualization is not proven: ${vm_kind:-none}" >&2; exit 1 ;;
esac

[ "${BITCOINPIR_CORE_PATTERN_VM_ACK-}" = "$expected_ack" ] || {
  echo 'independent-kernel guest acknowledgement is absent' >&2
  exit 1
}
case "$run_id" in
  ????????-????-????-????-????????????) ;;
  *) echo 'BITCOINPIR_CORE_PATTERN_VM_RUN_ID must be a UUID' >&2; exit 1 ;;
esac
case "$run_id" in
  *[!0-9a-f-]*) echo 'VM run ID must use lowercase hex UUID text' >&2; exit 1 ;;
esac

grep -Fqx "bitcoinpir.core_pattern_vm_run_id=$run_id" /proc/cmdline.tokens 2>/dev/null || {
  tr ' ' '\n' </proc/cmdline | grep -Fqx "bitcoinpir.core_pattern_vm_run_id=$run_id" || {
    echo 'VM run ID is not bound by the guest kernel command line' >&2
    exit 1
  }
}

boot_id=$(tr -d '\n' </proc/sys/kernel/random/boot_id)
marker=$marker_root/$run_id

case "$command_path" in
  /*) ;;
  *) echo 'reviewed matrix path must be absolute' >&2; exit 1 ;;
esac
[ ! -L "$command_path" ] || { echo 'reviewed matrix must not be a symlink' >&2; exit 1; }
[ "$(stat -c '%U:%G:%a:%F' "$command_path")" = 'root:root:500:regular file' ] || {
  echo 'reviewed matrix must be exact root:root mode 0500 regular file' >&2
  exit 1
}
case "$matrix_sha256" in
  *[!0-9a-f]*|'') echo 'reviewed matrix SHA-256 must use lowercase hex' >&2; exit 1 ;;
esac
[ "${#matrix_sha256}" -eq 64 ] || { echo 'reviewed matrix SHA-256 must be 64 hex characters' >&2; exit 1; }
actual_matrix_sha256=$(sha256sum "$command_path" | cut -d ' ' -f 1)
[ "$actual_matrix_sha256" = "$matrix_sha256" ] || {
  echo 'reviewed matrix bytes differ from the approved SHA-256' >&2
  exit 1
}

[ "$(stat -c '%U:%G:%a:%F' "$marker_root")" = 'root:root:700:directory' ] || {
  echo 'independent-kernel marker root metadata is not exact' >&2
  exit 1
}
[ "$(stat -c '%U:%G:%a:%F' "$marker")" = 'root:root:400:regular file' ] || {
  echo 'independent-kernel marker metadata is not exact' >&2
  exit 1
}
expected_marker=$(printf 'kind=bitcoinpir-core-pattern-independent-kernel-v1\nrun_id=%s\nboot_id=%s\nvirtualization=%s\nmatrix_sha256=%s\n' "$run_id" "$boot_id" "$vm_kind" "$matrix_sha256")
[ "$(cat "$marker")" = "$expected_marker" ] || {
  echo 'independent-kernel marker bytes do not bind this VM boot' >&2
  exit 1
}

exec env -i LANG=C LC_ALL=C PATH=/usr/sbin:/usr/bin TZ=UTC \
  BITCOINPIR_CORE_PATTERN_VM_RUN_ID="$run_id" \
  BITCOINPIR_CORE_PATTERN_MATRIX_SHA256="$matrix_sha256" "$@"
