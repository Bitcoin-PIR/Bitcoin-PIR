#!/usr/bin/env bash
# One pir2 sealed-release campaign as five reviewed windows (pain point 9):
#
#   plan    validate the env file and evidence directory, print the sequence
#   build   W1: build runtime + UKI on the stock rootfs, preserve the rollback
#           set, place the Observe startup, upload the UKI, boot Observe,
#           fetch its receipt, sign the release
#   enroll  W2: detach the old envelope, place release + Enroll startup, boot,
#           accept the Enroll receipt, sign the runtime identity cert
#   probe   W3/W4 (--ordinal N [--with-cert]): place (cert +) Probe startup,
#           boot, accept the Probe receipt, require the enrolled identity
#   ready   W5: place the Ready startup, boot, wait for the live attestation,
#           post-switch check (candidate pin), channel test, fetch + accept
#           both Ready receipts over the WebSocket, draft the release record
#
# Every action takes --dry-run, which prints each external command as a PLAN:
# line and touches nothing. Live runs are Flow E/F/G operations and need the
# authorization those flows require. All identity values come from files
# (env, evidence, sidecars, receipts); none is retyped here.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
exec 3>&1  # PLAN lines from captured commands still reach the operator
usage() { sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

action=${1:-}
case "$action" in
  -h|--help) usage; exit 0 ;;
  plan|build|enroll|probe|ready) shift ;;
  '') usage >&2; exit 2 ;;
  *) echo "unknown action: $action" >&2; usage >&2; exit 2 ;;
esac
env_file= dry_run=0 ordinal_arg= with_cert=0
while (($#)); do
  case "$1" in
    --env) env_file=${2:?--env requires a file}; shift 2 ;;
    --ordinal) ordinal_arg=${2:?}; shift 2 ;;
    --with-cert) with_cert=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ -n "$env_file" && -f "$env_file" ]] || { echo "--env FILE is required" >&2; exit 2; }

# ── env file: KEY=VALUE, allowlisted keys, conservative values (data, not code) ──
ALLOWED_KEYS=" REV TAG GEN ROLLBACK_IMAGE IMAGE SERVER_ID WS_URL EVIDENCE_DIR BPIR_ADMIN \
 ORD_OBSERVE ORD_ENROLL ORD_PROBE1 ORD_PROBE2 ORD_READY \
 BUILD_ROOT INPUTS_FROM ORAMCTL_SHA256 BHTM_SHA256 KERNEL UKI_LOCAL_DIR HETZNER_ARCHIVE ROLLBACK_LABEL \
 OVMF AMD_CERT_DIR OPERATOR_KEY OPERATOR_PUBKEY_HEX ARK_SHA256 PROVIDER_ID_HEX STABLE_SERVER_ID \
 VCPUS VCPU_SIG_HEX VMM_TYPE GUEST_FEATURES_HEX GUEST_POLICY_HEX MIN_TCB_FMC MIN_TCB_BOOTLOADER MIN_TCB_TEE MIN_TCB_SNP MIN_TCB_MICROCODE \
 SSH_PACE_SECONDS READY_WAIT_SECONDS "
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -z "$line" || "$line" == \#* ]] && continue
  key=${line%%=*}; value=${line#*=}
  [[ "$key" =~ ^[A-Z_][A-Z0-9_]*$ && "$ALLOWED_KEYS" == *" $key "* ]] || { echo "env: unknown key '$key'" >&2; exit 2; }
  [[ "$value" =~ ^[A-Za-z0-9_./:@+=-]*$ ]] || { echo "env: value of $key contains unsupported characters" >&2; exit 2; }
  printf -v "$key" '%s' "$value"
done < "$env_file"

# Defaults for the pir2 production topology; every one can be overridden in the env file.
: "${SERVER_ID:=25285}"; : "${WS_URL:=wss://weikeng2.bitcoinpir.org}"
: "${BUILD_ROOT:=/home/pir/data/production-builds}"; : "${KERNEL:=/boot/vmlinuz-7.0.0-29-generic}"
: "${OVMF:=$REPO/web/public/ovmf/OVMF_SEV_MEASUREDBOOT_4M.fd}"; : "${AMD_CERT_DIR:=$REPO/.keys/pir2-ceremony}"
: "${OPERATOR_KEY:=$REPO/.keys/pir2-operator.key}"; : "${STABLE_SERVER_ID:=pir2-vpsbg-dpf-v1}"
: "${VCPUS:=4}"; : "${VCPU_SIG_HEX:=00b10f10}"; : "${VMM_TYPE:=qemu}"; : "${GUEST_FEATURES_HEX:=1}"; : "${GUEST_POLICY_HEX:=30000}"
: "${MIN_TCB_FMC:=1}"; : "${MIN_TCB_BOOTLOADER:=1}"; : "${MIN_TCB_TEE:=1}"; : "${MIN_TCB_SNP:=4}"; : "${MIN_TCB_MICROCODE:=88}"
: "${SSH_PACE_SECONDS:=2}"; : "${READY_WAIT_SECONDS:=2400}"  # ssh/scp share one ControlMaster connection per window
: "${TAG:=}"; : "${UKI_LOCAL_DIR:=$REPO/deploy/uki/$TAG}"; : "${HETZNER_ARCHIVE:=}"; : "${IMAGE:=}"; : "${ROLLBACK_LABEL:=}"

need() { local k; for k in "$@"; do [[ -n "${!k:-}" ]] || { echo "env: $k is required for $action" >&2; exit 2; }; done; }
hexlen() { [[ "${!1}" =~ ^[0-9a-f]{$2}$ ]] || { echo "env: $1 must be $2 lowercase hex characters" >&2; exit 2; }; }
intval() { [[ "${!1}" =~ ^[1-9][0-9]*$ ]] || { echo "env: $1 must be a positive integer" >&2; exit 2; }; }
need SERVER_ID EVIDENCE_DIR TAG BPIR_ADMIN
intval SERVER_ID
[[ "$TAG" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || { echo "env: TAG must be [A-Za-z0-9._-]" >&2; exit 2; }
[[ -d "$EVIDENCE_DIR" ]] || { echo "env: EVIDENCE_DIR is not a directory: $EVIDENCE_DIR" >&2; exit 2; }
[[ -x "$BPIR_ADMIN" && -f "$BPIR_ADMIN" ]] || { echo "env: BPIR_ADMIN is not an executable file: $BPIR_ADMIN" >&2; exit 2; }
export BPIR_ADMIN
if command -v sha256sum >/dev/null 2>&1; then hash_one() { sha256sum "$1" | awk '{print $1}'; }; else hash_one() { shasum -a 256 "$1" | awk '{print $1}'; }; fi

V=$REPO/scripts/vpsbg-data-disk.sh; MB=$REPO/scripts/vpsbg-measured-boot.sh; CER=$REPO/scripts/pir2-sealed-ceremony.sh
P=/home/pir/data/pir2-sealed; D=$BUILD_ROOT/$TAG; REMOTE=$REPO/scripts/pir2-sealed-remote
stage() { echo; echo "[stage] $(date -u +%H:%M:%SZ) $*"; }
plan_line() { printf 'PLAN:'; printf ' %q' "$@"; echo; }
run() { if ((dry_run)); then plan_line "$@"; else "$@"; fi; }
pace() { ((dry_run)) || sleep "$SSH_PACE_SECONDS"; }
# capture <placeholder> <command...>: stdout of the command, or the placeholder in a dry run.
capture() { local ph=$1; shift; if ((dry_run)); then plan_line "$@" >&3; printf '%s' "$ph"; else "$@"; fi; }
startup_file() { echo "$EVIDENCE_DIR/$1-ordinal$2.startup.env"; }
check_startup() {
  local f; f=$(startup_file "$1" "$2")
  [[ -f "$f" ]] || { echo "missing startup file for $1 ordinal $2: $f" >&2; return 1; }
  [[ "$(awk -F= '$1=="phase"{print $2}' "$f")" == "$1" ]] || { echo "$f is not phase=$1" >&2; return 1; }
  [[ "$(awk -F= '$1=="ordinal"{print $2}' "$f")" == "$2" ]] || { echo "$f is not ordinal=$2" >&2; return 1; }
  [[ "$(awk -F= '$1=="verifier_nonce_hex"{print $2}' "$f")" =~ ^[0-9a-f]{64}$ ]] || { echo "$f has no 64-hex verifier nonce" >&2; return 1; }
}
put() { run "$V" put --local "$1" --remote "$2" --server-id "$SERVER_ID" --apply; pace; }
rssh() { run "$V" ssh --server-id "$SERVER_ID" -- "$@"; pace; }
open_window() { stage "open window on image $1"; run "$V" open --server-id "$SERVER_ID" --image-id "$1" --apply; pace; }
close_window() { stage "close onto image $1 ($2)"; run "$V" close --server-id "$SERVER_ID" --image-id "$1" --apply; }
recovery_receipt() {  # phase ordinal
  stage "recovery receipt $1/$2"
  run "$REPO/scripts/pir2-sealed-recovery-receipt.sh" --phase "$1" --ordinal "$2" --out-dir "$EVIDENCE_DIR" --label "$1-ordinal$2"
}
accept_receipt() {  # phase ordinal -> prints the strict-verify log path
  local phase=$1 ord=$2 f status log
  f=$(startup_file "$phase" "$ord"); status=$EVIDENCE_DIR/$phase-ordinal$ord.status.json; log=$EVIDENCE_DIR/$phase-ordinal$ord.strict-verify.log
  need OPERATOR_PUBKEY_HEX ARK_SHA256; hexlen OPERATOR_PUBKEY_HEX 64; hexlen ARK_SHA256 64
  local nonce boot rhash
  nonce=$(awk -F= '$1=="verifier_nonce_hex"{print $2}' "$f")
  if ((dry_run)); then boot='<boot_id>'; rhash='<receipt_sha256>'; else boot=$(jq -r .boot_id "$status"); rhash=$(jq -r .receipt_sha256 "$status"); fi
  stage "offline acceptance of $phase/$ord"
  if ((dry_run)); then
    plan_line "$CER" receipt --receipt "$EVIDENCE_DIR/$phase-ordinal$ord.receipt.bin" --release "$EVIDENCE_DIR/release-generation$GEN.bin" \
      --operator-pubkey-hex "$OPERATOR_PUBKEY_HEX" --expected-phase "$phase" --expected-ordinal "$ord" \
      --expected-verifier-nonce-hex "$nonce" --expected-boot-id-hex "$boot" --expected-receipt-sha256-hex "$rhash" \
      --ark "$AMD_CERT_DIR/ark.pem" --ask "$AMD_CERT_DIR/ask.pem" --vcek "$AMD_CERT_DIR/vcek.pem" --expected-ark-sha256-hex "$ARK_SHA256"
    return 0
  fi
  "$CER" receipt --receipt "$EVIDENCE_DIR/$phase-ordinal$ord.receipt.bin" --release "$EVIDENCE_DIR/release-generation$GEN.bin" \
    --operator-pubkey-hex "$OPERATOR_PUBKEY_HEX" --expected-phase "$phase" --expected-ordinal "$ord" \
    --expected-verifier-nonce-hex "$nonce" --expected-boot-id-hex "$boot" --expected-receipt-sha256-hex "$rhash" \
    --ark "$AMD_CERT_DIR/ark.pem" --ask "$AMD_CERT_DIR/ask.pem" --vcek "$AMD_CERT_DIR/vcek.pem" --expected-ark-sha256-hex "$ARK_SHA256" \
    2>&1 | tee "$log"
  grep -q '^PASS pir2_sealed_receipt_verify' "$log" || { echo "receipt acceptance failed for $phase/$ord" >&2; return 1; }
}
identity_of() { grep -oE 'service_identity_pubkey_hex=[0-9a-f]{64}' "$1" | head -1 | cut -d= -f2; }
uki_file() { ls "$UKI_LOCAL_DIR"/*.efi 2>/dev/null | head -1; }

case "$action" in
plan)
  need REV GEN ROLLBACK_IMAGE ORD_OBSERVE ORD_ENROLL ORD_PROBE1 ORD_PROBE2 ORD_READY INPUTS_FROM ORAMCTL_SHA256 BHTM_SHA256 ROLLBACK_LABEL OPERATOR_PUBKEY_HEX ARK_SHA256 PROVIDER_ID_HEX
  hexlen REV 40; hexlen ORAMCTL_SHA256 64; hexlen BHTM_SHA256 64; hexlen OPERATOR_PUBKEY_HEX 64; hexlen ARK_SHA256 64; hexlen PROVIDER_ID_HEX 64
  intval GEN; intval ROLLBACK_IMAGE; for k in ORD_OBSERVE ORD_ENROLL ORD_PROBE1 ORD_PROBE2 ORD_READY; do intval "$k"; done
  (( ORD_OBSERVE < ORD_ENROLL && ORD_ENROLL < ORD_PROBE1 && ORD_PROBE1 < ORD_PROBE2 && ORD_PROBE2 < ORD_READY )) || { echo "ordinals must increase: observe < enroll < probe1 < probe2 < ready" >&2; exit 2; }
  ok=1
  for pair in "observe:$ORD_OBSERVE" "enroll:$ORD_ENROLL" "probe:$ORD_PROBE1" "probe:$ORD_PROBE2" "ready:$ORD_READY"; do check_startup "${pair%%:*}" "${pair#*:}" || ok=0; done
  for f in "$OPERATOR_KEY" "$AMD_CERT_DIR/ark.pem" "$AMD_CERT_DIR/ask.pem" "$AMD_CERT_DIR/vcek.pem" "$OVMF"; do [[ -f "$f" ]] || { echo "missing $f" >&2; ok=0; }; done
  pin=$(awk '/PIR2_PROVIDER: ProductionProviderPin/{f=1} f && /operatorPubkey: hexToBytes\(/{getline; gsub(/[^0-9a-f]/,""); print; exit}' "$REPO/web/src/production-providers.ts")
  [[ "$pin" == "$OPERATOR_PUBKEY_HEX" ]] || { echo "OPERATOR_PUBKEY_HEX differs from the pin in web/src/production-providers.ts" >&2; ok=0; }
  [[ -z "$IMAGE" ]] || echo "note: IMAGE=$IMAGE is already set (build appends it; leave it unset before a build)"
  ((ok)) || { echo "FAIL plan"; exit 1; }
  echo "release_commit=$REV tag=$TAG generation=$GEN rollback_image=$ROLLBACK_IMAGE rollback_label=$ROLLBACK_LABEL"
  echo "ordinals: observe=$ORD_OBSERVE enroll=$ORD_ENROLL probe=$ORD_PROBE1,$ORD_PROBE2 ready=$ORD_READY"
  echo "windows: build (open $ROLLBACK_IMAGE, close NEW) -> enroll -> probe $ORD_PROBE1 --with-cert -> probe $ORD_PROBE2 -> ready"
  echo "PASS pir2_sealed_campaign action=plan"
  echo "NEXT_STEP=run build --dry-run, then build --env $env_file"
  ;;
build)
  need REV GEN ROLLBACK_IMAGE ORD_OBSERVE INPUTS_FROM ORAMCTL_SHA256 BHTM_SHA256 ROLLBACK_LABEL ARK_SHA256 PROVIDER_ID_HEX
  hexlen REV 40; check_startup observe "$ORD_OBSERVE"
  [[ -z "$IMAGE" ]] || { echo "IMAGE is already set in $env_file; build appends it" >&2; exit 2; }
  ((dry_run)) || mkdir -p "$UKI_LOCAL_DIR"
  bundle=$EVIDENCE_DIR/source-$TAG.bundle
  stage "source bundle for $REV"
  run git -C "$REPO" bundle create "$bundle" "$REV"
  open_window "$ROLLBACK_IMAGE"
  stage "preserve the rollback set $ROLLBACK_LABEL (previous image's credentials + Ready startup)"
  put "$REPO/scripts/pir2-sealed-rollback-set.sh" "$BUILD_ROOT/pir2-sealed-rollback-set.sh"
  rssh bash "$BUILD_ROOT/pir2-sealed-rollback-set.sh" preserve --label "$ROLLBACK_LABEL"
  stage "prepare inputs on the build host"
  put "$REMOTE/prep-inputs.sh" "$BUILD_ROOT/prep-inputs.sh"
  rssh env D="$D" INPUTS_FROM="$INPUTS_FROM" ORAMCTL_SHA256="$ORAMCTL_SHA256" BHTM_SHA256="$BHTM_SHA256" bash "$BUILD_ROOT/prep-inputs.sh"
  put "$bundle" "$D/source.bundle"
  put "$REMOTE/build-runtime.sh" "$D/build-runtime.sh"
  put "$REMOTE/build-uki.sh" "$D/build-uki.sh"
  stage "runtime build as pir"
  rssh "su -s /bin/bash pir -c 'env SHA=$REV D=$D bash $D/build-runtime.sh'"
  stage "UKI build as root (pinned cloudflared placed first)"
  rssh env D="$D" TAG="$TAG" KERNEL="$KERNEL" bash "$D/build-uki.sh"
  stage "fetch the archived trio"
  name=$(capture '<archive>.efi' "$V" ssh --server-id "$SERVER_ID" -- ls "$D/archive/tier3" | grep -E '^tier3-.*\.efi$|^<archive>\.efi$' | head -1); pace
  [[ -n "$name" ]] || { echo "no archived UKI under $D/archive/tier3" >&2; exit 1; }
  for ext in efi efi.meta efi.sha256; do run "$V" get --remote "$D/archive/tier3/${name%.efi}.$ext" --local "$UKI_LOCAL_DIR/${name%.efi}.$ext" --server-id "$SERVER_ID"; pace; done
  ((dry_run)) || (cd "$UKI_LOCAL_DIR" && shasum -a 256 -c "$name.sha256")
  stage "place the Observe startup"
  put "$(startup_file observe "$ORD_OBSERVE")" "$P/startup.env"
  if [[ -n "$HETZNER_ARCHIVE" ]]; then
    stage "mirror the trio to $HETZNER_ARCHIVE"
    run scp -q "$UKI_LOCAL_DIR/$name" "$UKI_LOCAL_DIR/$name.meta" "$UKI_LOCAL_DIR/$name.sha256" "$HETZNER_ARCHIVE/"
  fi
  stage "Flow E.4 upload"
  up=$(capture 'PASS action=upload image_id=<image>' "$MB" upload --uki "$UKI_LOCAL_DIR/$name" --apply)
  echo "$up" | grep -E '^PASS|image_id=' || true
  new=$(grep -oE 'image_id=[0-9<>a-z]+' <<<"$up" | tail -1 | cut -d= -f2)
  [[ -n "$new" ]] || { echo "upload did not return an image id" >&2; exit 1; }
  ((dry_run)) || printf 'IMAGE=%s\n' "$new" >> "$env_file"
  close_window "$new" "boots Observe $ORD_OBSERVE"
  recovery_receipt observe "$ORD_OBSERVE"
  stage "sign the generation-$GEN release"
  obs=$EVIDENCE_DIR/observe-ordinal$ORD_OBSERVE.receipt.bin
  if ((dry_run)); then chan='<channel_pubkey>'; boot='<boot_id>'; else
    fields=$("$BPIR_ADMIN" pir2-sealed-observe-fields --receipt "$obs")
    chan=$(awk -F= '$1=="current_channel_pubkey_hex"{print $2}' <<<"$fields"); boot=$(awk -F= '$1=="boot_id_hex"{print $2}' <<<"$fields")
  fi
  nonce=$(awk -F= '$1=="verifier_nonce_hex"{print $2}' "$(startup_file observe "$ORD_OBSERVE")")
  uki=$UKI_LOCAL_DIR/$name
  run "$CER" release --uki "$uki" --expected-uki-sha256-hex "$( ((dry_run)) && echo '<uki_sha256>' || awk '{print $1}' "$uki.sha256")" \
    --ovmf "$OVMF" --expected-ovmf-sha256-hex "$(hash_one "$OVMF")" \
    --observation-receipt "$obs" --observation-ordinal "$ORD_OBSERVE" --observation-verifier-nonce-hex "$nonce" \
    --observation-current-channel-pubkey-hex "$chan" --observation-boot-id-hex "$boot" \
    --ark "$AMD_CERT_DIR/ark.pem" --ask "$AMD_CERT_DIR/ask.pem" --vcek "$AMD_CERT_DIR/vcek.pem" --expected-ark-sha256-hex "$ARK_SHA256" \
    --vcpus "$VCPUS" --vcpu-sig-hex "$VCPU_SIG_HEX" --vmm-type "$VMM_TYPE" --guest-features-hex "$GUEST_FEATURES_HEX" \
    --expected-guest-policy-hex "$GUEST_POLICY_HEX" --provider-id-hex "$PROVIDER_ID_HEX" --stable-server-id "$STABLE_SERVER_ID" \
    --minimum-tcb-fmc "$MIN_TCB_FMC" --minimum-tcb-bootloader "$MIN_TCB_BOOTLOADER" --minimum-tcb-tee "$MIN_TCB_TEE" \
    --minimum-tcb-snp "$MIN_TCB_SNP" --minimum-tcb-microcode "$MIN_TCB_MICROCODE" \
    --identity-generation "$GEN" --operator-signing-key "$OPERATOR_KEY" --out "$EVIDENCE_DIR/release-generation$GEN.bin"
  echo "PASS pir2_sealed_campaign action=build image=$new$( ((dry_run)) && echo ' dry_run=true')"
  echo "NEXT_STEP=run enroll --env $env_file (IMAGE is recorded there)"
  ;;
enroll)
  need IMAGE GEN ORD_ENROLL ROLLBACK_LABEL; intval IMAGE; check_startup enroll "$ORD_ENROLL"
  open_window "$IMAGE"
  stage "detach the old envelope (rollback set $ROLLBACK_LABEL must match it)"
  put "$REPO/scripts/pir2-sealed-rollback-set.sh" "$BUILD_ROOT/pir2-sealed-rollback-set.sh"
  rssh bash "$BUILD_ROOT/pir2-sealed-rollback-set.sh" detach-envelope --label "$ROLLBACK_LABEL" --apply
  stage "place release + Enroll startup"
  put "$EVIDENCE_DIR/release-generation$GEN.bin" "$P/release.bin"
  put "$(startup_file enroll "$ORD_ENROLL")" "$P/startup.env"
  rssh sha256sum "$P/release.bin" "$P/startup.env"
  close_window "$IMAGE" "boots Enroll $ORD_ENROLL"
  recovery_receipt enroll "$ORD_ENROLL"
  accept_receipt enroll "$ORD_ENROLL"
  cert=$EVIDENCE_DIR/identity-generation$GEN-image$IMAGE-runtime-v1.cert
  pk=$( ((dry_run)) && echo '<service_identity_pubkey>' || identity_of "$EVIDENCE_DIR/enroll-ordinal$ORD_ENROLL.strict-verify.log")
  [[ -n "$pk" ]] || { echo "no service identity in the Enroll acceptance log" >&2; exit 1; }
  stage "sign the runtime identity cert (valid 0/0, as the previous generations)"
  run "$BPIR_ADMIN" sign-identity --operator-key-path "$OPERATOR_KEY" --server-id "$STABLE_SERVER_ID" --identity-pubkey-hex "$pk" --valid-from 0 --valid-until 0 --out "$cert"
  ((dry_run)) || chmod 600 "$cert"
  echo "PASS pir2_sealed_campaign action=enroll$( ((dry_run)) && echo ' dry_run=true')"
  echo "NEXT_STEP=run probe --ordinal $ORD_PROBE1 --with-cert --env $env_file"
  ;;
probe)
  need IMAGE GEN ORD_ENROLL; intval IMAGE
  ord=${ordinal_arg:-}; [[ "$ord" =~ ^[1-9][0-9]*$ ]] || { echo "probe requires --ordinal N" >&2; exit 2; }
  check_startup probe "$ord"
  cert=$EVIDENCE_DIR/identity-generation$GEN-image$IMAGE-runtime-v1.cert
  ((with_cert == 0)) || ((dry_run)) || [[ -f "$cert" ]] || { echo "missing $cert" >&2; exit 1; }
  open_window "$IMAGE"
  if ((with_cert)); then stage "place the runtime identity cert"; put "$cert" "$P/identity.cert"; fi
  stage "place the Probe startup"
  put "$(startup_file probe "$ord")" "$P/startup.env"
  rssh sha256sum "$P/identity.cert" "$P/startup.env"
  close_window "$IMAGE" "boots Probe $ord"
  recovery_receipt probe "$ord"
  accept_receipt probe "$ord"
  if ((!dry_run)); then
    a=$(identity_of "$EVIDENCE_DIR/probe-ordinal$ord.strict-verify.log"); b=$(identity_of "$EVIDENCE_DIR/enroll-ordinal$ORD_ENROLL.strict-verify.log")
    [[ -n "$a" && "$a" == "$b" ]] || { echo "Probe $ord identity differs from Enroll $ORD_ENROLL" >&2; exit 1; }
    echo "identity_matches_enroll=true"
  fi
  echo "PASS pir2_sealed_campaign action=probe ordinal=$ord$( ((dry_run)) && echo ' dry_run=true')"
  echo "NEXT_STEP=run the second probe, or ready --env $env_file once two Probe receipts are accepted"
  ;;
ready)
  need IMAGE GEN ORD_READY ORD_OBSERVE ARK_SHA256; intval IMAGE; check_startup ready "$ORD_READY"; hexlen ARK_SHA256 64
  open_window "$IMAGE"
  stage "place the Ready startup"
  put "$(startup_file ready "$ORD_READY")" "$P/startup.env"
  rssh sha256sum "$P/startup.env" "$P/identity.cert" "$P/release.bin"
  close_window "$IMAGE" "boots Ready $ORD_READY"
  stage "wait for the Ready boot to serve, then attest against the Observe measurement and the sidecar binary"
  uki=$(uki_file); meta="$uki.meta"
  if ((dry_run)); then meas='<measurement>'; bin='<binary_sha256>'; else
    meas=$("$BPIR_ADMIN" pir2-sealed-observe-fields --receipt "$EVIDENCE_DIR/observe-ordinal$ORD_OBSERVE.receipt.bin" | awk -F= '$1=="report_measurement_hex"{print $2}')
    bin=$(awk -F= '$1=="binary_sha256"{print $2}' "$meta")
  fi
  attest_log=$EVIDENCE_DIR/ready-ordinal$ORD_READY-live-attest.log
  if ((dry_run)); then
    plan_line "$REPO/scripts/vpsbg-production-status.sh" --server-id "$SERVER_ID"
    plan_line "$BPIR_ADMIN" attest "$WS_URL" --expect-measurement "$meas" --expect-binary "$bin" --expect-ark-fingerprint "$ARK_SHA256"
  else
    started=$(date +%s); attested=0
    while :; do
      now=$(date +%s); (( now - started < READY_WAIT_SECONDS )) || { echo "HARD_STOP ready not serving within ${READY_WAIT_SECONDS}s"; exit 1; }
      snap=$("$REPO/scripts/vpsbg-production-status.sh" --server-id "$SERVER_ID" 2>/dev/null || true)
      bm=$(awk -F= '$1=="boot_mode"{print $2}' <<<"$snap"); rn=$(awk -F= '$1=="control_plane_running"{print $2}' <<<"$snap"); st=$(awk -F= '$1=="oram_stage"{print $2}' <<<"$snap")
      echo "elapsed=$((now - started)) boot_mode=$bm running=$rn oram_stage=$st"
      [[ "$st" != failed ]] || { echo "ORAM_FAILED"; exit 1; }
      if [[ "$bm" == measured && "$rn" == true ]] && "$BPIR_ADMIN" attest "$WS_URL" --expect-measurement "$meas" --expect-binary "$bin" --expect-ark-fingerprint "$ARK_SHA256" > "$attest_log" 2>&1; then attested=1; break; fi
      sleep 30
    done
    ((attested)) && echo "READY_ATTEST_PASS"
  fi
  stage "post-switch check against a candidate pin built from the evidence"
  cand=$EVIDENCE_DIR/attest-pin.candidate-image$IMAGE.ts
  if ((dry_run)); then echo "PLAN: write $cand from measurement + sidecar binary"; else
    printf "export const PIR2_TIER3_PIN: ServerAttestPin = {\n  measurementHex:\n    '%s',\n  binarySha256Hex:\n    '%s',\n};\n" "$meas" "$bin" > "$cand"
  fi
  run "$REPO/scripts/pir2-post-switch-check.sh" --server-id "$SERVER_ID" --pin-file "$cand"
  stage "encrypted-channel test"
  run "$BPIR_ADMIN" channel-test "$WS_URL" --expect-ark-fingerprint "$ARK_SHA256"
  stage "fetch both Ready receipts + marker over the WebSocket"
  fetch_dir=$EVIDENCE_DIR/ready-ordinal$ORD_READY; ((dry_run)) || { mkdir -p "$fetch_dir"; chmod 700 "$fetch_dir"; }
  fetch_log=$EVIDENCE_DIR/ready-ordinal$ORD_READY-fetch.log
  if ((dry_run)); then plan_line "$CER" fetch "$WS_URL" --out-dir "$fetch_dir"; boot='<boot_id>'; else
    "$CER" fetch "$WS_URL" --out-dir "$fetch_dir" 2>&1 | tee "$fetch_log"
    boot=$(grep -oE 'PASS pir2_sealed_receipt_fetch boot_id_hex=[0-9a-f]{32}' "$fetch_log" | head -1 | sed 's/.*=//')
    [[ -n "$boot" ]] || { echo "receipt fetch failed" >&2; exit 1; }
    for kind in preflight runtime; do
      cp -p "$fetch_dir/ready-$kind-$boot.bin" "$EVIDENCE_DIR/ready-ordinal$ORD_READY-$kind.receipt.bin"
      printf '{"schema_version":1,"phase":"ready","ordinal":%s,"boot_id":"%s","receipt_sha256":"%s","source":"websocket-fetch"}\n' \
        "$ORD_READY" "$boot" "$(hash_one "$EVIDENCE_DIR/ready-ordinal$ORD_READY-$kind.receipt.bin")" > "$EVIDENCE_DIR/ready-ordinal$ORD_READY-$kind.status.json"
    done
  fi
  for kind in preflight runtime; do
    if ((dry_run)); then
      plan_line "$CER" receipt --receipt "$EVIDENCE_DIR/ready-ordinal$ORD_READY-$kind.receipt.bin" --expected-phase ready --expected-ordinal "$ORD_READY" --expected-boot-id-hex "$boot" '...'
    else
      log=$EVIDENCE_DIR/ready-ordinal$ORD_READY-$kind.strict-verify.log
      nonce=$(awk -F= '$1=="verifier_nonce_hex"{print $2}' "$(startup_file ready "$ORD_READY")")
      "$CER" receipt --receipt "$EVIDENCE_DIR/ready-ordinal$ORD_READY-$kind.receipt.bin" --release "$EVIDENCE_DIR/release-generation$GEN.bin" \
        --operator-pubkey-hex "$OPERATOR_PUBKEY_HEX" --expected-phase ready --expected-ordinal "$ORD_READY" \
        --expected-verifier-nonce-hex "$nonce" --expected-boot-id-hex "$boot" \
        --expected-receipt-sha256-hex "$(jq -r .receipt_sha256 "$EVIDENCE_DIR/ready-ordinal$ORD_READY-$kind.status.json")" \
        --ark "$AMD_CERT_DIR/ark.pem" --ask "$AMD_CERT_DIR/ask.pem" --vcek "$AMD_CERT_DIR/vcek.pem" --expected-ark-sha256-hex "$ARK_SHA256" 2>&1 | tee "$log"
      grep -q '^PASS pir2_sealed_receipt_verify' "$log" || { echo "Ready $kind receipt rejected" >&2; exit 1; }
    fi
  done
  stage "draft the release record from the live attestation"
  run "$REPO/scripts/generate-release-record.sh" --uki "$uki" --image-id "$IMAGE" --server-id "$SERVER_ID" --runtime-rev "${REV:-TODO}" --web-pin-rev TODO \
    --attest-log "$attest_log" --acceptance "pir2_attest_channel_oram_smoke_passed_ready${ORD_READY}_receipts_accepted" --out "$EVIDENCE_DIR/release-record-image$IMAGE.env"
  echo "pin_measurement_hex=$meas"; echo "pin_binary_sha256=$bin"
  echo "PASS pir2_sealed_campaign action=ready image=$IMAGE$( ((dry_run)) && echo ' dry_run=true')"
  echo "NEXT_STEP=update web/src/attest-pin.ts PIR2_TIER3_PIN from the two pin_* values above (pin PR, Flow C), then regenerate the record with --web-pin-rev <merge commit> into docs/data-retention/"
  ;;
esac
