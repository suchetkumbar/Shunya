#!/bin/sh
# Shunya Milestone 9 demo. Runs INSIDE the lab VM as root (lab.sh demo pushes and starts
# it); it touches only the VM's target disks, which are image files on the host.
#
#   1. an offline organisation root, a certified station, a transparency log on 127.0.0.1
#   2. the TUI on three disks of different kinds: you pick them, confirm each by typing
#      the end of its serial, and watch them wipe in parallel
#   3. every certificate and the batch manifest verified (logged), and a log audit
#
# DEMO_WIPE=fleet runs step 2 without a terminal ("shunya fleet", the same code path),
# for checking this script itself.
set -eu
W=${1:?usage: demo.sh WORKDIR}
cd "$W"
S=./shunya
V=./shunya-verify
D=$W/run-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$D/batch"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

say "1/3  keys and the transparency log"
printf 'demo root passphrase, keep offline\n' > "$D/pass"
$S keys init-root --passphrase-file "$D/pass" "$D/root" | grep 'root key id'
$S keys gen-station "$D/station.key" | grep 'key id'
$S keys issue-station --root "$D/root/root.key" --station-key "$D/station.key" --name demo-bay \
  --out "$D/station.cert.json" --passphrase-file "$D/pass" | grep certified
$V log-key --origin 127.0.0.1:8080/log --out "$D" >/dev/null
$V serve --init --dir "$D/log" --log-key "$D/log.key" --root "$D/root/root.pub" \
  --revocations "$D/root/revocations.json" --listen 127.0.0.1:8080 >"$D/serve.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
for _ in 1 2 3 4 5 6 7 8 9 10; do wget -q -O /dev/null http://127.0.0.1:8080/checkpoint 2>/dev/null && break; sleep 0.5; done
echo "log serving on 127.0.0.1:8080 (pid $SRV)"

# The three demo disks, found by serial (device names can change between boots), and
# their fingerprints as an approved list (used by the fleet variant).
$S list --fingerprints | grep -E ' (SHUNYA-VIRTIO-01|SHUNYA-SATA-HDD-01|SHUNYA-NVME-01) ' > "$D/approved.txt"
DISKS=$(awk '{printf "%s ", $3}' "$D/approved.txt")
echo "demo disks: $DISKS"
COMMON="--journal-dir $D/batch --key $D/station.key --station-cert $D/station.cert.json --log http://127.0.0.1:8080 --log-key $D/log.vkey"

say "2/3  wipe three disks in parallel"
if [ "${DEMO_WIPE:-tui}" = fleet ]; then
  # shellcheck disable=SC2086
  $S fleet --execute --approved "$D/approved.txt" --yes-really $COMMON $DISKS || true
else
  echo "In the TUI: Space selects a disk, Enter continues; type the last 4 characters of each serial."
  printf 'Press Enter to start the TUI. '
  read -r _
  # shellcheck disable=SC2086
  $S tui $COMMON $DISKS || true
fi

say "3/3  verify the certificates, the batch manifest and the log"
for c in "$D"/batch/*.cert.json; do
  $V --root "$D/root/root.pub" --revocations "$D/root/revocations.json" --log-key "$D/log.vkey" --require-log "$c" | head -3
done
$V manifest --root "$D/root/root.pub" --revocations "$D/root/revocations.json" --log-key "$D/log.vkey" --require-log \
  --certs "$D/batch" "$D"/batch/batch-*.manifest.json
$V audit --log http://127.0.0.1:8080 --log-key "$D/log.vkey" --state "$D/audit.state"
echo
echo "Everything is in $D (certificates and PDFs in $D/batch)."
echo "Open a certificate's QR target inside the VM, e.g.: wget -qO- http://127.0.0.1:8080/c/<ID> | grep -o '>VALID<'"
