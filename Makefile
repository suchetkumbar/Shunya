# Shunya build entry point. Run from Linux/WSL (see scripts/wsl.ps1 on Windows).
SHELL := /bin/bash
GO    ?= go
PKGS  := ./...
BIN   := bin

# Reproducible, static builds: no cgo, trimmed paths, no VCS stamping, fixed build id.
export CGO_ENABLED := 0
GOFLAGS_REPRO := -trimpath -buildvcs=false
LDFLAGS       := -s -w -buildid=

LAB_TOKEN_FILE := lab/secrets/lab-token
CMDS := shunya shunya-verify

# Every build kind is linted and tested: dev (default), release, and the lab-only tests.
TAGSETS := "" release labtest
# Lint also covers the test-only brokenwipe build (bin/lab/shunya-broken); its tests run
# separately (make test-broken) because that build is wrong on purpose.
LINTTAGS := $(TAGSETS) brokenwipe

.PHONY: all build build-linux build-release build-windows windows-check build-lab repro test test-big test-broken bench race fuzz vet \
        staticcheck vulncheck lint fmt-check ci clean lab-images lab-up lab-shell lab-test lab-demo lab-down lab-reset \
        build-image-tools image image-lock image-repro lab-iso-test

all: lint test build

# windows-check compiles the Windows binaries without writing an .exe (on the dev host,
# Windows Defender deletes freshly written .exe files from the repo; see DECISIONS).
build: build-linux build-release windows-check

windows-check:
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS_REPRO) -o /dev/null ./...
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS_REPRO) -tags release -o /dev/null ./...

# Dev build: lab lock active, no lab token -> refuses every block device.
build-linux:
	@mkdir -p $(BIN)/linux-amd64
	@for c in $(CMDS); do GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS_REPRO) -ldflags '$(LDFLAGS)' -o $(BIN)/linux-amd64/$$c ./cmd/$$c || exit 1; done
	@sha256sum $(BIN)/linux-amd64/*

# Release build: no lab lock, typed confirmation required; all other guards kept.
build-release:
	@mkdir -p $(BIN)/release-linux-amd64
	@for c in $(CMDS); do GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS_REPRO) -tags release -ldflags '$(LDFLAGS)' -o $(BIN)/release-linux-amd64/$$c ./cmd/$$c || exit 1; done
	@sha256sum $(BIN)/release-linux-amd64/*

build-windows:
	@mkdir -p $(BIN)/windows-amd64
	@for c in $(CMDS); do GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS_REPRO) -ldflags '$(LDFLAGS)' -o $(BIN)/windows-amd64/$$c.exe ./cmd/$$c || exit 1; done

# Lab build: dev build + the lab token, plus the lab test binary and shunya-broken (the
# test-only brokenwipe build that skips the last 1%, for the canary harness's negative test). Not reproducible by
# design (the token differs per lab) and never shipped; bin/ is gitignored.
build-lab:
	@test -s $(LAB_TOKEN_FILE) || { echo "no lab token: run make lab-images first"; exit 1; }
	@mkdir -p $(BIN)/lab
	@tok="$$(cat $(LAB_TOKEN_FILE))"; \
	  GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS_REPRO) -ldflags "$(LDFLAGS) -X shunya/internal/backend.labToken=$$tok" -o $(BIN)/lab/shunya ./cmd/shunya && \
	  GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS_REPRO) -ldflags '$(LDFLAGS)' -o $(BIN)/lab/shunya-verify ./cmd/shunya-verify && \
	  GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS_REPRO) -tags brokenwipe -ldflags "$(LDFLAGS) -X shunya/internal/backend.labToken=$$tok" -o $(BIN)/lab/shunya-broken ./cmd/shunya && \
	  GOOS=linux GOARCH=amd64 $(GO) test -c -tags labtest $(GOFLAGS_REPRO) -ldflags "-X shunya/internal/backend.labToken=$$tok" -o $(BIN)/lab/backend.test ./lab/tests

# Reproducibility demo: two builds of each kind from empty build caches must be identical.
repro:
	@for cmd in $(CMDS); do for kind in dev release; do \
	  tags=$$([ $$kind = release ] && echo release); \
	  for i in 1 2; do \
	    c=$$(mktemp -d); GOCACHE=$$c GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS_REPRO) -tags "$$tags" -ldflags '$(LDFLAGS)' -o $(BIN)/repro-$$cmd-$$kind-$$i ./cmd/$$cmd || exit 1; \
	    chmod -R u+w $$c; rm -r $$c; \
	  done; \
	  sha256sum $(BIN)/repro-$$cmd-$$kind-1 $(BIN)/repro-$$cmd-$$kind-2; \
	  cmp $(BIN)/repro-$$cmd-$$kind-1 $(BIN)/repro-$$cmd-$$kind-2 && echo "$$cmd $$kind: byte-identical" || exit 1; \
	done; done

test:
	@for tags in $(TAGSETS); do echo "== go test -tags '$$tags'"; $(GO) test -count=1 -tags "$$tags" $(PKGS) || exit 1; done

# Milestone 3 acceptance: wipe + byte-check a 1 GiB + 4095-sector image. Needs ~1.1 GiB in
# the repo's tmp/ (gitignored); the image is deleted afterwards.
BIG_DIR := $(CURDIR)/tmp
test-big:
	@mkdir -p $(BIG_DIR)
	SHUNYA_BIG_DIR=$(BIG_DIR) $(GO) test -count=1 -v -run '^TestBigOddImage$$' ./internal/engine

# The deliberately broken wipe (skips the last 1%) and the harness test that catches it.
test-broken:
	$(GO) test -count=1 -tags brokenwipe -run 'Broken' -v ./internal/engine ./internal/canary

# Throughput benchmarks: pattern generators, and full wipes of a 256 MiB image in the
# test temp directory.
bench:
	$(GO) test -run '^$$' -bench . -benchtime 5x ./internal/engine

race:
	@for tags in $(TAGSETS); do echo "== go test -race -tags '$$tags'"; CGO_ENABLED=1 $(GO) test -race -count=1 -tags "$$tags" $(PKGS) || exit 1; done

# Short fuzzing pass over every Fuzz* target, FUZZTIME each.
FUZZTIME ?= 10s
fuzz:
	@for pkg in $$($(GO) list ./...); do \
	  for t in $$($(GO) test -list '^Fuzz' $$pkg | grep '^Fuzz'); do \
	    echo "== $$pkg $$t"; \
	    $(GO) test -run='^$$' -fuzz="^$$t$$" -fuzztime=$(FUZZTIME) $$pkg || exit 1; \
	  done; \
	done

vet:
	@for tags in $(LINTTAGS); do for os in linux windows; do echo "== vet $$os '$$tags'"; GOOS=$$os $(GO) vet -tags "$$tags" $(PKGS) || exit 1; done; done

staticcheck:
	@for tags in $(LINTTAGS); do for os in linux windows; do echo "== staticcheck $$os '$$tags'"; GOOS=$$os staticcheck -tags "$$tags" $(PKGS) || exit 1; done; done

vulncheck:
	govulncheck $(PKGS)

fmt-check:
	@out="$$(gofmt -l .)"; \
	  if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint: fmt-check vet staticcheck

ci: lint race vulncheck build

clean:
	rm -rf $(BIN)

# ---- Lab (Linux + KVM only; never destructive on the host) ----
lab-images:
	@bash lab/lab.sh images
lab-up:
	@bash lab/lab.sh up
lab-shell:
	@bash lab/lab.sh shell
lab-test: build-linux build-lab
	@bash lab/lab.sh test
# The Milestone 9 demo in the VM (design/DEMO.md): keys, log, TUI on three disks, verification.
lab-demo: build-lab
	@bash lab/lab.sh demo
lab-down:
	@bash lab/lab.sh down
lab-reset:
	@bash lab/lab.sh reset

# ---- Live image (Milestone 10, design/IMAGE.md). Built inside the lab VM, never on the host ----
# mkinitramfs is a build tool (it runs in the VM), not part of the image.
build-image-tools:
	@mkdir -p $(BIN)/tools
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS_REPRO) -ldflags '$(LDFLAGS)' -o $(BIN)/tools/mkinitramfs ./image/mkinitramfs
# The release ISO in lab/images/live/ (needs make lab-up).
image: build-release build-image-tools
	@bash lab/lab.sh image
# Print packages.lock lines for the newest Alpine packages (review, then paste).
image-lock: build-release build-image-tools
	@LOCK=print bash lab/lab.sh image
# Two image builds from scratch (each with freshly built binaries and empty Go caches)
# must give identical binaries and identical ISO files.
image-repro: build-image-tools
	@for i in 1 2; do \
	  c=$$(mktemp -d); \
	  for cmd in $(CMDS); do GOCACHE=$$c GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS_REPRO) -tags release -ldflags '$(LDFLAGS)' -o $(BIN)/release-linux-amd64/$$cmd ./cmd/$$cmd || exit 1; done; \
	  chmod -R u+w $$c; rm -r $$c; \
	  IMAGE_OUT=lab/images/repro-$$i bash lab/lab.sh image || exit 1; \
	  sha256sum $(BIN)/release-linux-amd64/* > lab/images/repro-$$i/BINARIES.SHA256; \
	done
	@cat lab/images/repro-1/BINARIES.SHA256 lab/images/repro-1/SHA256SUMS
	@cmp lab/images/repro-1/BINARIES.SHA256 lab/images/repro-2/BINARIES.SHA256 && echo "binaries: identical in both builds"
	@cmp lab/images/repro-1/shunya-live.iso lab/images/repro-2/shunya-live.iso && echo "shunya-live.iso: byte-identical in both builds"
# Boot the ISO in QEMU (from WSL, image files only) and wipe disks from its TUI.
lab-iso-test: build-release build-image-tools build-linux
	@PROVISION=lab bash lab/lab.sh image
	@bash lab/lab.sh down
	$(GO) test -count=1 -tags labiso -timeout 30m -v ./lab/iso
