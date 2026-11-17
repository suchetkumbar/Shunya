#!/usr/bin/env bash
# Prints URL and size of the newest Alpine (virt kernel) cloud-init qcow2 image. Read-only.
set -euo pipefail
dir="https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/cloud/"
img="$(curl -fsSL "$dir" | grep -o 'alpine-[0-9.]*-x86_64-cloudinit-r[0-9]*\.qcow2' | sort -uV | tail -n1)"
[ -n "$img" ] || { echo "no image found in $dir" >&2; exit 1; }
size="$(curl -fsSIL "$dir$img" | tr -d '\r' | awk 'tolower($1)=="content-length:"{print $2}' | tail -n1)"
echo "URL=$dir$img"
echo "SIZE_BYTES=$size"
echo "METADATA_URL=$dir${img%.qcow2}.yaml   (sha512 under outputs.qcow2)"
