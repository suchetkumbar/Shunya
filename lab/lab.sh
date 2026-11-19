#!/usr/bin/env bash
# Shunya lab controller. Runs inside WSL (or any Linux host with KVM).
#
#   lab.sh images   download/verify base image, create boot overlay + sparse target images
#   lab.sh up       boot the disposable lab VM (daemonized) and wait for SSH
#   lab.sh shell    interactive SSH into the VM
#   lab.sh run CMD  run a command in the VM as root
#   lab.sh runf F   run local script file F in the VM as root
#   lab.sh push SRC DST / pull SRC DST   copy files in/out (scp)
#   lab.sh test     push binaries + probe, run them, pull results to lab/results/
#   lab.sh demo     push the lab builds and run the Milestone 9 demo (TUI) in the VM
#   lab.sh image    build the live image (ISO) in the VM; outputs in lab/images/live/
#   lab.sh down     stop the VM
#   lab.sh reset    down + delete boot overlay and targets (base image kept)
#
# SAFETY (design/SAFETY.md): every disk handed to QEMU must be a regular file under
# lab/images/. Block/char devices are refused. This script never needs root.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$LAB_DIR")"
# shellcheck source=lab.env
. "$LAB_DIR/lab.env"

IMG_DIR="$LAB_DIR/images"
SECRETS_DIR="$LAB_DIR/secrets"
RUN_DIR="$LAB_DIR/run"
RESULTS_DIR="$LAB_DIR/results"
BASE_IMG="$IMG_DIR/alpine-base.qcow2"
BOOT_IMG="$IMG_DIR/boot.qcow2"
SEED_ISO="$IMG_DIR/seed.iso"
PIDFILE="$RUN_DIR/qemu.pid"
SERIAL_LOG="$RUN_DIR/serial.log"

# name|bus|size|qemu-device-args   (targets the tool MAY wipe inside the VM)
TARGETS=(
  "t-virtio|virtio|$TARGET_SIZE|"
  "t-sata-ssd|ahci-ssd|$TARGET_SIZE|"
  "t-sata-hdd|ahci-hdd|$TARGET_SIZE|"
  "t-nvme|nvme|$TARGET_SIZE|"
  "t-usb|usb|$USB_SIZE|"
)

die() { echo "lab: $*" >&2; exit 1; }
log() { echo "lab: $*" >&2; }

require_linux() {
  [ "$(uname -s)" = Linux ] || die "lab must run on Linux/WSL, not $(uname -s)"
  [ -r /dev/kvm ] && [ -w /dev/kvm ] || die "/dev/kvm not accessible (is the user in group kvm? nested virt on?)"
  [ "$(id -u)" -ne 0 ] || die "do not run the lab as root"
}

# Defence in depth: refuse anything that is not a regular file inside lab/images.
assert_image_file() {
  local f="$1" real
  [ -e "$f" ] || die "missing image $f"
  [ -f "$f" ] && [ ! -b "$f" ] && [ ! -c "$f" ] || die "REFUSING non-regular file $f"
  real="$(readlink -f "$f")"
  case "$real" in
    "$(readlink -f "$IMG_DIR")"/*) ;;
    *) die "REFUSING image outside lab/images: $real" ;;
  esac
}

ssh_key() {
  # ssh refuses keys with loose permissions, and /mnt/d (drvfs) cannot store 0600,
  # so use a per-user copy in $XDG_RUNTIME_DIR or /tmp.
  local tmpkey="${TMPDIR:-/tmp}/shunya-lab-$(id -u).key"
  install -m 600 "$SECRETS_DIR/id_ed25519" "$tmpkey"
  echo "$tmpkey"
}

ssh_opts() {
  echo "-i $(ssh_key) -p $SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5"
}

cmd_images() {
  require_linux
  mkdir -p "$IMG_DIR" "$SECRETS_DIR" "$RUN_DIR"

  if [ ! -f "$BASE_IMG" ]; then
    log "downloading $ALPINE_URL"
    curl -fL --progress-bar -o "$BASE_IMG.part" "$ALPINE_URL"
    echo "$ALPINE_SHA512  $BASE_IMG.part" | sha512sum -c - >/dev/null || { rm -f "$BASE_IMG.part"; die "sha512 mismatch"; }
    mv "$BASE_IMG.part" "$BASE_IMG"
  fi
  echo "$ALPINE_SHA512  $BASE_IMG" | sha512sum -c - >/dev/null || die "base image checksum mismatch"

  [ -f "$SECRETS_DIR/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C shunya-lab -f "$SECRETS_DIR/id_ed25519"
  [ -f "$SECRETS_DIR/lab-token" ] || openssl rand -hex 32 > "$SECRETS_DIR/lab-token"  # getrandom(2); opens no device node

  if [ ! -f "$BOOT_IMG" ]; then
    qemu-img create -q -f qcow2 -F qcow2 -b "$(basename "$BASE_IMG")" "$BOOT_IMG" "$BOOT_SIZE"
  fi
  for t in "${TARGETS[@]}"; do
    IFS='|' read -r name _ size _ <<<"$t"
    [ -f "$IMG_DIR/$name.raw" ] || truncate -s "$size" "$IMG_DIR/$name.raw"
  done
  make_seed
  log "images ready in $IMG_DIR"
  ls -ls "$IMG_DIR" >&2
}

make_seed() {
  local d pub token
  d="$(mktemp -d)"
  pub="$(cat "$SECRETS_DIR/id_ed25519.pub")"
  token="$(cat "$SECRETS_DIR/lab-token")"
  cat >"$d/meta-data" <<EOF
instance-id: shunya-lab-1
local-hostname: shunya-lab
EOF
  cat >"$d/user-data" <<EOF
#cloud-config
ssh_authorized_keys:
  - $pub
write_files:
  - path: /etc/shunya-lab
    permissions: '0644'
    content: |
      $token
runcmd:
  # Retry: the WSL->internet path occasionally drops TLS connections.
  - |
    for i in 1 2 3 4 5; do
      apk add --quiet $VM_PACKAGES && { touch /etc/shunya-lab-ready; break; }
      sleep 5
    done
EOF
  xorriso -as mkisofs -quiet -volid cidata -joliet -rock -o "$SEED_ISO.tmp" "$d/user-data" "$d/meta-data" 2>/dev/null
  mv "$SEED_ISO.tmp" "$SEED_ISO"
  rm -rf "$d"
}

is_running() { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

cmd_up() {
  require_linux
  is_running && { log "already running (pid $(cat "$PIDFILE"))"; return 0; }
  [ -f "$BOOT_IMG" ] || cmd_images
  mkdir -p "$RUN_DIR"
  assert_image_file "$BOOT_IMG"; assert_image_file "$SEED_ISO"

  local args=(
    -name shunya-lab
    -machine q35,accel=kvm -cpu host -m "$VM_MEM_MB" -smp "$VM_CPUS"
    -display none -serial "file:$SERIAL_LOG" -daemonize -pidfile "$PIDFILE"
    -nodefaults -no-user-config
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" -device virtio-net-pci,netdev=n0
    # Boot disk: the tool must refuse this one.
    -drive "if=none,id=boot,file=$BOOT_IMG,format=qcow2,cache=writeback"
    -device virtio-blk-pci,drive=boot,serial=SHUNYA-BOOT-0,bootindex=0
    -drive "if=none,id=seed,file=$SEED_ISO,format=raw,media=cdrom,readonly=on"
    -device ide-cd,drive=seed,bus=ide.5
    -device qemu-xhci,id=xhci
  )
  local t name bus f
  for t in "${TARGETS[@]}"; do
    IFS='|' read -r name bus _ _ <<<"$t"
    f="$IMG_DIR/$name.raw"; assert_image_file "$f"
    args+=(-drive "if=none,id=$name,file=$f,format=raw,cache=none,aio=threads")
    case "$bus" in
      virtio)   args+=(-device "virtio-blk-pci,drive=$name,serial=SHUNYA-VIRTIO-01") ;;
      ahci-ssd) args+=(-device "ide-hd,drive=$name,bus=ide.0,serial=SHUNYA-SATA-SSD-01,model=SHUNYA LAB SATA SSD,rotation_rate=1,wwn=0x5000c500a1b2c301") ;;
      ahci-hdd) args+=(-device "ide-hd,drive=$name,bus=ide.1,serial=SHUNYA-SATA-HDD-01,model=SHUNYA LAB SATA HDD,rotation_rate=7200,wwn=0x5000c500a1b2c302") ;;
      nvme)     args+=(-device "nvme,id=nvme0,serial=SHUNYA-NVME-01" -device "nvme-ns,drive=$name,bus=nvme0,nsid=1,eui64=0x5348554e59410001") ;;
      usb)      args+=(-device "usb-storage,bus=xhci.0,drive=$name,serial=SHUNYA-USB-01,removable=on") ;;
      *) die "unknown bus $bus" ;;
    esac
  done

  : >"$SERIAL_LOG"
  qemu-system-x86_64 "${args[@]}"
  log "VM started (pid $(cat "$PIDFILE")); waiting for SSH on 127.0.0.1:$SSH_PORT"
  local i
  for i in $(seq 1 120); do
    # shellcheck disable=SC2046
    if ssh $(ssh_opts) "$VM_USER@127.0.0.1" 'test -f /etc/shunya-lab && test -f /etc/shunya-lab-ready' 2>/dev/null; then
      log "VM ready after ~$((i*2))s"; return 0
    fi
    is_running || { tail -n 40 "$SERIAL_LOG" >&2; die "QEMU exited during boot"; }
    sleep 2
  done
  tail -n 40 "$SERIAL_LOG" >&2
  die "timed out waiting for VM"
}

# Alpine locks the root account, so we log in as the default user and use doas.
# The script is sent on stdin so no quoting survives two shells (bash -> ash).
cmd_run()   { is_running || die "VM not running"
              # shellcheck disable=SC2046
              printf '%s
' "$*" | ssh $(ssh_opts) "$VM_USER@127.0.0.1" 'doas sh -s'; }
cmd_runf()  { is_running || die "VM not running"; [ -f "$1" ] || die "no such script $1"
              # shellcheck disable=SC2046
              ssh $(ssh_opts) "$VM_USER@127.0.0.1" 'doas sh -s' <"$1"; }
cmd_shell() { is_running || die "VM not running"; # shellcheck disable=SC2046
              ssh -t $(ssh_opts) "$VM_USER@127.0.0.1"; }
cmd_push()  { # shellcheck disable=SC2046
              scp -q $(ssh_opts | sed 's/-p /-P /') "$1" "$VM_USER@127.0.0.1:$2"; }
cmd_pull()  { # shellcheck disable=SC2046
              scp -q -r $(ssh_opts | sed 's/-p /-P /') "$VM_USER@127.0.0.1:$1" "$2"; }

cmd_demo() {
  is_running || die "VM not running (make lab-up)"
  local bin="$REPO_DIR/bin/lab" w=/home/$VM_USER/demo
  [ -x "$bin/shunya" ] && [ -x "$bin/shunya-verify" ] || die "missing $bin/{shunya,shunya-verify} (make build-lab)"
  cmd_run "rm -rf $w && mkdir -p $w && chown -R $VM_USER $w"
  cmd_push "$bin/shunya" "$w/shunya"
  cmd_push "$bin/shunya-verify" "$w/shunya-verify"
  cmd_push "$LAB_DIR/demo.sh" "$w/demo.sh"
  if [ -n "${DEMO_WIPE:-}" ]; then # non-interactive variant (checks the script itself)
    cmd_run "DEMO_WIPE=$DEMO_WIPE sh $w/demo.sh $w"
  else
    # shellcheck disable=SC2046
    ssh -t $(ssh_opts) "$VM_USER@127.0.0.1" "doas sh $w/demo.sh $w"
  fi
}

# Build the live image inside the VM (image/build.sh), as the unprivileged VM user. The
# outputs (ISO files, BUILDINFO.TXT, SHA256SUMS) land in lab/images/live/ (gitignored).
# LOCK=print prints packages.lock lines instead; PROVISION=lab adds the lab-test ISO;
# IMAGE_OUT=DIR (under lab/images/) picks another output directory.
cmd_image() {
  is_running || die "VM not running (make lab-up)"
  local w=/home/$VM_USER/image out="${IMAGE_OUT:-$IMG_DIR/live}" epoch
  local rel="$REPO_DIR/bin/release-linux-amd64" tool="$REPO_DIR/bin/tools/mkinitramfs"
  [ -x "$rel/shunya" ] && [ -x "$rel/shunya-verify" ] && [ -x "$tool" ] || die "missing release binaries or mkinitramfs (make image)"
  case "$(readlink -f "$out")" in "$(readlink -f "$IMG_DIR")"/*) ;; *) die "IMAGE_OUT must be under lab/images" ;; esac
  epoch="${SOURCE_DATE_EPOCH:-$(git -C "$REPO_DIR" log -1 --format=%ct 2>/dev/null || true)}"
  [ -n "$epoch" ] || die "no SOURCE_DATE_EPOCH and no git history to take it from"
  # Build tool in the VM only (the ISO writer); e2fsprogs is already there.
  cmd_run "for i in 1 2 3; do apk add --quiet $IMAGE_BUILD_PACKAGES && break; sleep 3; done" || die "apk add failed in the VM"
  cmd_run "rm -rf $w && mkdir -p $w/image && chown -R $VM_USER $w"
  cmd_push "$rel/shunya" "$w/shunya"
  cmd_push "$rel/shunya-verify" "$w/shunya-verify"
  cmd_push "$tool" "$w/mkinitramfs"
  local f
  for f in build.sh init isolinux.cfg packages.lock modules.list; do cmd_push "$REPO_DIR/image/$f" "$w/image/$f"; done
  # shellcheck disable=SC2046
  printf '%s\n' "SOURCE_DATE_EPOCH=$epoch LOCK=${LOCK:-} PROVISION=${PROVISION:-} sh $w/image/build.sh $w" |
    ssh $(ssh_opts) "$VM_USER@127.0.0.1" 'sh -s' || die "image build failed"
  [ "${LOCK:-}" = print ] && return 0
  rm -rf "$out"; mkdir -p "$out"
  cmd_pull "$w/out/." "$out"
  log "live image in $out"
  (cd "$out" && sha256sum -c SHA256SUMS >&2)
}

cmd_test() {
  is_running || die "VM not running (make lab-up)"
  # bin/lab holds the token-bearing lab builds (make build-lab); they never leave the lab.
  local bin="$REPO_DIR/bin/lab"
  [ -x "$bin/shunya" ] && [ -x "$bin/shunya-broken" ] && [ -x "$bin/shunya-verify" ] && [ -x "$bin/backend.test" ] || die "missing $bin/{shunya,shunya-broken,shunya-verify,backend.test} (make build-lab)"
  local stamp out
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  out="$RESULTS_DIR/$stamp"
  mkdir -p "$out"
  local w=/home/$VM_USER/shunya
  cmd_run "rm -rf $w && mkdir -p $w/results && chown -R $VM_USER $w"
  # Packages added after first boot (cloud-init installs VM_PACKAGES only once). VM only.
  cmd_run "for i in 1 2 3; do apk add --quiet $VM_PACKAGES && break; sleep 3; done" || die "apk add failed in the VM"
  cmd_push "$bin/shunya" "$w/shunya"
  cmd_push "$bin/shunya-broken" "$w/shunya-broken"
  cmd_push "$bin/shunya-verify" "$w/shunya-verify"
  log "running shunya list in VM (read-only)"
  cmd_run "$w/shunya list --all | tee $w/results/list.txt; $w/shunya list --json > $w/results/list.json"
  log "shunya guard (read-only): boot disk and a target"
  cmd_run "$w/shunya guard /dev/vda | tee $w/results/guard-vda.txt; $w/shunya guard /dev/nvme0n1 | tee $w/results/guard-nvme0n1.txt; true"
  cmd_push "$bin/backend.test" "$w/backend.test"
  log "running backend lab tests as root (writes to TARGET disks only)"
  # LAB_RUN (optional) selects tests by name, e.g. to split a long run into parts.
  cmd_run "cd $w && SHUNYA_LAB=1 ./backend.test -test.v -test.count=1 -test.timeout=45m ${LAB_RUN:+-test.run='$LAB_RUN'} > results/backend-lab.txt 2>&1; echo \$? > results/backend-lab.rc"
  if [ "${PROBE:-0}" = 1 ]; then
    cmd_push "$LAB_DIR/probe/probe.sh" "$w/probe.sh"
    log "running capability probe in VM (destructive to TARGET disks only)"
    cmd_run "sh $w/probe.sh $w/results" || log "probe returned non-zero (see results)"
  fi
  cmd_run "chown -R $VM_USER $w/results"
  cmd_pull "$w/results/." "$out"
  ln -sfn "$stamp" "$RESULTS_DIR/latest" 2>/dev/null || cp -r "$out/." "$RESULTS_DIR/latest/"
  log "results in $out"
  log "backend lab tests:"
  grep -E '^(=== RUN|--- |    backend_lab_test|PASS|FAIL|ok)' "$out/backend-lab.txt" | grep -v '^=== RUN' || true
  [ -f "$out/canary-report.txt" ] && { log "canary harness report:"; cat "$out/canary-report.txt"; }
  local rc; rc="$(cat "$out/backend-lab.rc" 2>/dev/null || echo missing)"
  log "checking results against lab expectations"
  (cd "$REPO_DIR" && go run ./lab/check "$out/list.json") || return 1
  [ "$rc" = 0 ] || { log "backend lab tests FAILED (exit $rc); see $out/backend-lab.txt"; return 1; }
  log "backend lab tests PASSED"
}

cmd_down() {
  if is_running; then
    local pid; pid="$(cat "$PIDFILE")"
    cmd_run 'poweroff' 2>/dev/null || true
    for _ in $(seq 1 30); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    kill -0 "$pid" 2>/dev/null && { log "forcing stop"; kill "$pid"; }
    log "VM stopped"
  else
    log "VM not running"
  fi
  rm -f "$PIDFILE"
}

cmd_reset() {
  cmd_down
  rm -f "$BOOT_IMG" "$SEED_ISO" "$IMG_DIR"/t-*.raw
  log "reset done (base image kept)"
}

case "${1:-}" in
  images) cmd_images ;;
  up)     cmd_up ;;
  shell)  cmd_shell ;;
  run)    shift; cmd_run "$@" ;;
  runf)   shift; cmd_runf "$1" ;;
  push)   shift; cmd_push "$@" ;;
  pull)   shift; cmd_pull "$@" ;;
  test)   cmd_test ;;
  demo)   cmd_demo ;;
  image)  cmd_image ;;
  down)   cmd_down ;;
  reset)  cmd_reset ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
