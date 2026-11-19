#!/bin/sh
# Build the Shunya live image. Runs INSIDE the lab VM as an ordinary user (lab.sh image
# pushes the inputs and starts it); it writes only under WORKDIR and never touches a
# block device: the ISO and its partitions are image files.
#
#   build.sh WORKDIR            WORKDIR holds shunya, shunya-verify, mkinitramfs and image/
#   LOCK=print build.sh WORKDIR fetch the newest versions and print packages.lock lines
#   PROVISION=lab build.sh ...  also build shunya-live-labtest.iso: the same ISO with a
#                               lab-only root, station key and certificate on SHUNYA-KEYS
#
# Inputs that decide the bytes: the binaries, image/*, the pinned packages, xorriso and
# e2fsprogs versions (recorded in build-info), SOURCE_DATE_EPOCH.
set -eu
W=${1:?usage: build.sh WORKDIR}
cd "$W"
: "${SOURCE_DATE_EPOCH:?set SOURCE_DATE_EPOCH (lab.sh uses the last commit time)}"
export SOURCE_DATE_EPOCH
B=$W/build
rm -rf "$B"
mkdir -p "$B/pkgs" "$B/x" "$B/rootfs/bin" "$B/rootfs/etc/shunya" "$B/iso/boot" "$B/iso/isolinux" "$B/keys" "$B/data" "$W/out"

PKGS="linux-virt busybox-static syslinux"
REPO=$(grep '^# Repository: ' image/packages.lock | awk '{print $3}')
case "$REPO" in https://*) ;; *) echo "build: no https repository in packages.lock" >&2; exit 1 ;; esac
log() { printf 'build: %s\n' "$*" >&2; }
die() { printf 'build: %s\n' "$*" >&2; exit 1; }

if [ "${LOCK:-}" = print ]; then
  for p in $PKGS; do
    apk fetch --quiet -o "$B/pkgs" "$p" >/dev/null
    f=$(ls "$B/pkgs/$p"-[0-9]*.apk)
    v=${f##*/"$p"-}; v=${v%.apk}
    printf '%-16s %-16s %s\n' "$p" "$v" "$(sha256sum "$f" | cut -d' ' -f1)"
  done
  exit 0
fi

# 1. Pinned packages: fetch, check, unpack (not installed: tar only).
grep -v '^#' image/packages.lock | grep -q . || die "image/packages.lock has no packages: run make image-lock first"
grep -v '^#' image/packages.lock | while read -r name ver sum; do
  [ -n "$name" ] || continue
  # The exact file by URL (apk 3 cannot fetch a pinned version); the SHA-256 in the lock
  # was recorded from an apk fetch, which checks Alpine's package signature.
  f="$B/pkgs/$name-$ver.apk"
  wget -q -O "$f" "$REPO/x86_64/$name-$ver.apk" || die "cannot fetch $name-$ver.apk (gone from the mirror? run make image-lock)"
  got=$(sha256sum "$f" | cut -d' ' -f1)
  [ "$got" = "$sum" ] || die "$name-$ver.apk: sha256 $got, packages.lock says $sum"
  mkdir -p "$B/x/$name"
  tar -xzf "$f" -C "$B/x/$name" 2>/dev/null || die "cannot unpack $f"
  log "package $name $ver ok"
done
for p in $PKGS; do [ -d "$B/x/$p" ] || die "package $p is not in packages.lock"; done

K=$B/x/linux-virt
KVER=$(ls "$K/lib/modules")
[ "$(echo "$KVER" | wc -w)" = 1 ] || die "expected one kernel in linux-virt, found: $KVER"
S=$B/x/syslinux/usr/share/syslinux

# 2. The initramfs: init, busybox, shunya, shunya-verify, storage drivers.
install -m 0755 image/init "$B/rootfs/init"
install -m 0755 "$B/x/busybox-static/bin/busybox.static" "$B/rootfs/bin/busybox"
install -m 0755 shunya "$B/rootfs/bin/shunya"
install -m 0755 shunya-verify "$B/rootfs/bin/shunya-verify"
./shunya version 2>/dev/null | head -1 | sed 's/^shunya //' >"$B/rootfs/etc/shunya/version"
MODULES=$(grep -v '^#' image/modules.list | tr '\n' ',' | tr -s ', ' ',')
./mkinitramfs -root "$B/rootfs" -modules "$K/lib/modules/$KVER" -want "$MODULES" \
  -epoch "$SOURCE_DATE_EPOCH" -o "$B/iso/boot/initramfs.gz" -list "$B/initramfs.sha256"
install -m 0644 "$K/boot/vmlinuz-virt" "$B/iso/boot/vmlinuz"
install -m 0644 "$S/isolinux.bin" "$S/ldlinux.c32" "$B/iso/isolinux/"
install -m 0644 image/isolinux.cfg "$B/iso/isolinux/isolinux.cfg"

{
  echo "Shunya live image"
  echo "shunya $(cat "$B/rootfs/etc/shunya/version")"
  echo "kernel linux-virt $KVER"
  grep -v '^#' image/packages.lock | awk 'NF==3 {print "package " $1 " " $2 " sha256:" $3}'
  echo "xorriso $(xorriso -version 2>/dev/null | head -1)"
  echo "mke2fs $(mke2fs -V 2>&1 | head -1)"
  echo "SOURCE_DATE_EPOCH $SOURCE_DATE_EPOCH"
  echo
  echo "sha256 of every file in the initramfs:"
  cat "$B/initramfs.sha256"
} >"$B/iso/BUILDINFO.TXT"

# 3. The writable partitions: ext4 images built from directories, with fixed UUIDs,
# hash seeds and times. Nothing secret is in them: the key partition ships empty.
cat >"$B/keys/README.txt" <<'EOF'
SHUNYA-KEYS: put station.key and station.cert.json here (see design/IMAGE.md,
"Provisioning"). The live system mounts this partition read-only.
EOF
cat >"$B/data/README.txt" <<'EOF'
SHUNYA-DATA: the live system keeps its wipe journals, certificates (JSON and PDF) and
batch manifests here, one directory per session under sessions/.
EOF
mkdir -p "$B/data/sessions"

mkext4() { # DIR LABEL UUID SIZE OUT
  rm -f "$5"
  E2FSPROGS_FAKE_TIME=$SOURCE_DATE_EPOCH mke2fs -q -F -t ext4 -d "$1" -L "$2" -U "$3" \
    -E "hash_seed=$3,root_owner=0:0,lazy_itable_init=0,lazy_journal_init=0,nodiscard" \
    -m 0 -N 128 "$5" "$4" || die "mke2fs $2 failed"
}
find "$B/keys" "$B/data" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

mkiso() { # KEYSDIR OUT
  mkext4 "$1" SHUNYA-KEYS 5348554e-5941-4b45-5953-000000000002 8M "$B/keys.img"
  mkext4 "$B/data" SHUNYA-DATA 5348554e-5941-4441-5441-000000000003 64M "$B/data.img"
  find "$B/iso" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  rm -f "$2"
  xorriso -as mkisofs -quiet -o "$2" -V SHUNYA-LIVE -r \
    -isohybrid-mbr "$S/isohdpfx.bin" \
    -c isolinux/boot.cat -b isolinux/isolinux.bin -no-emul-boot -boot-load-size 4 -boot-info-table \
    -append_partition 2 0x83 "$B/keys.img" \
    -append_partition 3 0x83 "$B/data.img" \
    "$B/iso" || die "xorriso failed"
}

mkiso "$B/keys" "$W/out/shunya-live.iso"
cp "$B/iso/BUILDINFO.TXT" "$W/out/BUILDINFO.TXT"
log "shunya-live.iso: $(du -h "$W/out/shunya-live.iso" | cut -f1)"

# 4. Lab-test variant (lab only, never published): a throwaway root certifies a station
# key, both put on SHUNYA-KEYS. The ISO filesystem itself is the same as the release one.
if [ "${PROVISION:-}" = lab ]; then
  P=$B/provision
  mkdir -p "$P/keys"
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$P/pass"
  ./shunya keys init-root --passphrase-file "$P/pass" "$P/root" >/dev/null
  ./shunya keys gen-station "$P/keys/station.key" >/dev/null
  ./shunya keys issue-station --root "$P/root/root.key" --station-key "$P/keys/station.key" --name lab-iso-bay \
    --out "$P/keys/station.cert.json" --passphrase-file "$P/pass" >/dev/null
  cp "$B/keys/README.txt" "$P/keys/"
  chmod 0600 "$P/keys/station.key"
  find "$P/keys" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  mkiso "$P/keys" "$W/out/shunya-live-labtest.iso"
  cp "$P/root/root.pub" "$W/out/labtest-root.pub"
  cp "$P/root/revocations.json" "$W/out/labtest-revocations.json"
  rm -rf "$P/root" "$P/pass" # the throwaway root key never leaves the VM
  log "shunya-live-labtest.iso: lab-only, carries a test station key"
fi
(cd "$W/out" && sha256sum ./*.iso >SHA256SUMS && cat SHA256SUMS)
