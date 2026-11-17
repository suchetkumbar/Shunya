#!/bin/sh
# Lab capability probe — RUNS ONLY INSIDE THE LAB VM, as root.
# Uses standard tools (nvme-cli, hdparm, sg3_utils) purely to discover what QEMU's
# emulated devices support. Shelling out is allowed here because this is a lab
# harness, not the core engine (brief §4).
#
# It is destructive to the TARGET disks only (serials SHUNYA-{VIRTIO,SATA,NVME,USB}-*)
# and refuses the boot disk and any disk without a lab serial.
set -u
OUT="${1:-/root/results}"
mkdir -p "$OUT"
S="$OUT/capabilities.txt"
: >"$S"

say() { echo "$*" | tee -a "$S"; }
sect() { say ""; say "=== $* ==="; }

# ---- Guard 1: must be the lab VM ----
vendor="$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)"
product="$(cat /sys/class/dmi/id/product_name 2>/dev/null)"
case "$vendor $product" in
  *QEMU*|*KVM*) ;;
  *) echo "probe: REFUSING — not a QEMU/KVM system ($vendor / $product)" >&2; exit 3 ;;
esac
[ -s /etc/shunya-lab ] || { echo "probe: REFUSING — /etc/shunya-lab missing" >&2; exit 3; }

# ---- Guard 2: identify the root disk and never touch it ----
rootsrc="$(findmnt -no SOURCE /)"
rootdisk="$(lsblk -no PKNAME "$rootsrc" 2>/dev/null | head -n1)"
[ -n "$rootdisk" ] || rootdisk="$(basename "$rootsrc")"

serial_of() {  # serial_of NAME — sysfs only (Alpine has no udev, so lsblk shows no serials)
  b="/sys/block/$1"
  if [ -s "$b/serial" ]; then tr -d ' \n' <"$b/serial"; return; fi                 # virtio-blk
  if [ -s "$b/device/serial" ]; then tr -d ' \n' <"$b/device/serial"; return; fi   # nvme
  if [ -r "$b/device/vpd_pg80" ]; then tail -c +5 "$b/device/vpd_pg80" | tr -d ' \0\n'; return; fi  # SCSI/SAT unit serial
  p="$(readlink -f "$b/device")"                                                    # USB: walk up to the usb device
  while [ "$p" != / ] && [ -n "$p" ]; do
    if [ -f "$p/serial" ] && [ -f "$p/idVendor" ]; then tr -d ' \n' <"$p/serial"; return; fi
    p="$(dirname "$p")"
  done
}
devof() {  # devof SERIAL -> /dev/NAME (whole disk) or empty
  for b in /sys/block/*; do
    n="$(basename "$b")"
    [ "$(serial_of "$n")" = "$1" ] && { echo "/dev/$n"; return; }
  done
}
safe_target() {  # refuse root disk / mounted / non-lab serial
  d="$1"; n="$(basename "$d")"
  [ -b "$d" ] || return 1
  [ "$n" != "$rootdisk" ] || { say "REFUSED $d: root disk"; return 1; }
  if lsblk -nr -o MOUNTPOINTS "$d" | grep -q .; then say "REFUSED $d: mounted"; return 1; fi
  return 0
}
t() { timeout 30 "$@" 2>&1; }   # run a probe step, capture output

sect "system"
say "dmi: $vendor / $product"
say "kernel: $(uname -r)"
say "root fs source: $rootsrc  root disk: $rootdisk"
say "lab marker present: yes ($(wc -c </etc/shunya-lab) bytes)"
lsblk -o NAME,SIZE,TYPE,TRAN,ROTA,RM,MODEL,MOUNTPOINTS | tee -a "$S"
for b in /sys/block/*; do say "serial($(basename "$b")): $(serial_of "$(basename "$b")")"; done
for m in nvme ahci usb_storage uas virtio_blk sg; do
  if [ -d "/sys/module/$m" ]; then say "module $m: loaded/builtin"; else say "module $m: ABSENT"; fi
done

# ---- virtio-blk ----
sect "virtio-blk (SHUNYA-VIRTIO-01)"
d="$(devof SHUNYA-VIRTIO-01)"
if [ -n "$d" ] && safe_target "$d"; then
  n="$(basename "$d")"
  say "device: $d"
  say "discard_max_bytes: $(cat /sys/block/$n/queue/discard_max_bytes)"
  say "write_zeroes_max_bytes: $(cat /sys/block/$n/queue/write_zeroes_max_bytes)"
  say "rotational: $(cat /sys/block/$n/queue/rotational)"
  say "blkdiscard test: $(t blkdiscard -f "$d" && echo OK || echo FAILED)"
  say "ATA passthrough (SG_IO): $(t hdparm -I "$d" | head -n3 | tr '\n' ' ')"
else say "not found"; fi

# ---- SATA via AHCI ----
for ser in SHUNYA-SATA-SSD-01 SHUNYA-SATA-HDD-01; do
  sect "AHCI SATA ($ser)"
  d="$(devof "$ser")"
  if [ -z "$d" ] || ! safe_target "$d"; then say "not found / refused"; continue; fi
  n="$(basename "$d")"
  say "device: $d  rotational=$(cat /sys/block/$n/queue/rotational) discard_max=$(cat /sys/block/$n/queue/discard_max_bytes)"
  t hdparm -I "$d" >"$OUT/hdparm-I-$ser.txt"
  say "IDENTIFY via SG_IO ATA PT: $(grep -q 'Model Number' "$OUT/hdparm-I-$ser.txt" && echo OK || echo FAILED)"
  grep -E 'Model Number|Serial Number|Firmware|LBA48|sectors|TRIM|Security|supported|frozen|enabled|ERASE|HPA|Host Protected|Device Configuration' \
    "$OUT/hdparm-I-$ser.txt" | sed 's/^/    /' | head -n 60 | tee -a "$S" >/dev/null
  t sg_inq "$d" >"$OUT/sg_inq-$ser.txt"
  say "HPA (READ NATIVE MAX via hdparm -N): $(t hdparm -N "$d" | tail -n1)"
  say "DCO IDENTIFY: $(t hdparm --dco-identify "$d" | head -n4 | tr '\n' ' ')"
  # Volatile HPA set: shrink by 2048 sectors, read back, then restore (volatile, no 'p').
  max="$(hdparm -N "$d" 2>/dev/null | sed -n 's#.*= *\([0-9]*\)/\([0-9]*\).*#\2#p')"
  if [ -n "$max" ]; then
    new=$((max - 2048))
    say "SET MAX ADDRESS (volatile) to $new: $(t hdparm --yes-i-know-what-i-am-doing -N "$new" "$d" | tail -n1)"
    say "  after: $(t hdparm -N "$d" | tail -n1)"
    say "  restore: $(t hdparm --yes-i-know-what-i-am-doing -N "$max" "$d" | tail -n1)"
  fi
  say "SECURITY SET PASSWORD: $(t hdparm --user-master u --security-set-pass shunya "$d" | tail -n2 | tr '\n' ' ')"
  say "  security state after: $(t hdparm -I "$d" | sed -n '/^Security:/,/^Logical/p' | tr -s ' \t\n' ' ')"
  say "SECURITY ERASE: $(t hdparm --user-master u --security-erase shunya "$d" | tail -n2 | tr '\n' ' ')"
  say "TRIM via blkdiscard: $(t blkdiscard -f "$d" && echo OK || echo FAILED)"
done

# ---- NVMe ----
sect "NVMe (SHUNYA-NVME-01)"
ctrl=""
for c in /sys/class/nvme/nvme*; do
  [ -e "$c/serial" ] || continue
  [ "$(tr -d ' ' <"$c/serial")" = SHUNYA-NVME-01 ] && ctrl="/dev/$(basename "$c")"
done
ns="${ctrl:+${ctrl}n1}"
if [ -n "$ctrl" ] && [ -b "$ns" ] && safe_target "$ns"; then
  say "controller: $ctrl  namespace: $ns"
  t nvme id-ctrl "$ctrl" >"$OUT/nvme-id-ctrl.txt"
  t nvme id-ctrl -H "$ctrl" >"$OUT/nvme-id-ctrl-H.txt"
  t nvme id-ns -H "$ns" >"$OUT/nvme-id-ns-H.txt"
  for f in mn fr oacs oncs fna sanicap vwc ver; do
    say "  $f: $(awk -v k="$f" '$1==k{ $1=$2=""; print }' "$OUT/nvme-id-ctrl.txt" | sed 's/^ *//')"
  done
  say "  LBA formats: $(grep -c '^LBA Format' "$OUT/nvme-id-ns-H.txt")"
  # Don't trust status codes: plant a pattern, format, and check the data is really gone.
  for ses in 0 1 2; do
    dd if=/dev/urandom of=/tmp/pat bs=1M count=4 2>/dev/null
    dd if=/tmp/pat of="$ns" bs=1M count=4 oflag=direct conv=fsync 2>/dev/null
    dd if=/tmp/pat of="$ns" bs=1M seek=1000 count=4 oflag=direct conv=fsync 2>/dev/null
    r="$(t nvme format "$ns" --ses=$ses --force | tail -n1)"
    a="$(dd if="$ns" bs=1M count=4 iflag=direct 2>/dev/null | od -An -v -tx1 | tr -d ' \n' | tr -d 0 | wc -c)"
    b="$(dd if="$ns" bs=1M skip=1000 count=4 iflag=direct 2>/dev/null | od -An -v -tx1 | tr -d ' \n' | tr -d 0 | wc -c)"
    say "FORMAT NVM ses=$ses: $r ; nonzero hex digits after: head=$a tail=$b ($( [ "$a$b" = 00 ] && echo 'DATA ERASED' || echo 'DATA REMAINS'))"
  done
  for a in 2:block 3:overwrite 4:crypto; do
    say "SANITIZE ${a#*:} (sanact=${a%%:*}): $(t nvme sanitize "$ctrl" --sanact="${a%%:*}" | tail -n1)"
    sleep 1
    say "  sanitize-log: $(t nvme sanitize-log "$ctrl" | tr -s ' \n' ' ' | cut -c1-200)"
  done
  say "DSM deallocate (discard): $(t blkdiscard -f "$ns" && echo OK || echo FAILED)"
  say "write-zeroes: $(t nvme write-zeroes "$ns" --start-block=0 --block-count=7 | tail -n1)"
else say "not found / refused"; fi

# ---- USB mass storage ----
sect "USB mass storage (SHUNYA-USB-01)"
d="$(devof SHUNYA-USB-01)"
if [ -n "$d" ] && safe_target "$d"; then
  n="$(basename "$d")"
  say "device: $d  tran=$(lsblk -dno TRAN "$d") removable=$(cat /sys/block/$n/removable)"
  say "SCSI INQUIRY: $(t sg_inq "$d" | grep -E 'Vendor|Product' | tr -s ' \n' ' ')"
  say "ATA passthrough (SAT) via hdparm -I: $(t hdparm -I "$d" | head -n4 | tr '\n' ' ')"
  say "discard_max_bytes: $(cat /sys/block/$n/queue/discard_max_bytes)"
else say "not found"; fi

# ---- Boot disk must be refused ----
sect "boot disk guard"
b="$(devof SHUNYA-BOOT-0)"
say "boot disk: ${b:-?} ; safe_target says: $(safe_target "${b:-/nonexistent}" && echo ALLOWED-BUG || echo refused)"

say ""
say "probe complete"
