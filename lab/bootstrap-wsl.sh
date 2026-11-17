#!/usr/bin/env bash
# Installs the user-level toolchain for the Shunya lab inside the WSL "lab" user.
# Non-destructive: touches only $HOME. System packages (qemu etc.) are installed
# separately by root — see design/SAFETY.md and lab/README.md.
set -euo pipefail

GO_VERSION="${GO_VERSION:-go1.27.4}"
GO_SHA256="${GO_SHA256:-7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840}"
ARCHIVE="${GO_VERSION}.linux-amd64.tar.gz"
SDK="$HOME/go-sdk"

if [ ! -x "$SDK/bin/go" ] || [ "$("$SDK/bin/go" env GOVERSION)" != "$GO_VERSION" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  curl -fsSL -o "$tmp/$ARCHIVE" "https://dl.google.com/go/$ARCHIVE"
  echo "$GO_SHA256  $tmp/$ARCHIVE" | sha256sum -c -
  rm -rf "$SDK"
  mkdir -p "$SDK"
  tar -C "$SDK" --strip-components=1 -xzf "$tmp/$ARCHIVE"
fi

grep -q 'go-sdk/bin' "$HOME/.profile" 2>/dev/null ||
  echo 'export PATH="$HOME/go-sdk/bin:$HOME/go/bin:$PATH"' >> "$HOME/.profile"
export PATH="$SDK/bin:$HOME/go/bin:$PATH"

go version
go install honnef.co/go/tools/cmd/staticcheck@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
staticcheck -version
govulncheck -version | head -n 2
