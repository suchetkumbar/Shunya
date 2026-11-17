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
CMDS := shunya

# Every build kind is linted and tested: dev (default), release, and the lab-only tests.
TAGSETS := "" release labtest

.PHONY: all build build-linux build-release build-windows windows-check build-lab repro test race fuzz vet \
        staticcheck vulncheck lint fmt-check ci clean lab-images lab-up lab-shell lab-test lab-down lab-reset

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

# Lab build: dev build + the lab token, plus the lab test binary. Not reproducible by
# design (the token differs per lab) and never shipped; bin/ is gitignored.
build-lab:
	@test -s $(LAB_TOKEN_FILE) || { echo "no lab token: run make lab-images first"; exit 1; }
	@mkdir -p $(BIN)/lab
	@tok="$$(cat $(LAB_TOKEN_FILE))"; \
	  GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS_REPRO) -ldflags "$(LDFLAGS) -X shunya/internal/backend.labToken=$$tok" -o $(BIN)/lab/shunya ./cmd/shunya && \
	  GOOS=linux GOARCH=amd64 $(GO) test -c -tags labtest $(GOFLAGS_REPRO) -ldflags "-X shunya/internal/backend.labToken=$$tok" -o $(BIN)/lab/backend.test ./lab/tests

# Reproducibility demo: two builds of each kind from empty build caches must be identical.
repro:
	@for kind in dev release; do \
	  tags=$$([ $$kind = release ] && echo release); \
	  for i in 1 2; do \
	    c=$$(mktemp -d); GOCACHE=$$c GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS_REPRO) -tags "$$tags" -ldflags '$(LDFLAGS)' -o $(BIN)/repro-$$kind-$$i ./cmd/shunya || exit 1; \
	    chmod -R u+w $$c; rm -r $$c; \
	  done; \
	  sha256sum $(BIN)/repro-$$kind-1 $(BIN)/repro-$$kind-2; \
	  cmp $(BIN)/repro-$$kind-1 $(BIN)/repro-$$kind-2 && echo "$$kind: byte-identical" || exit 1; \
	done

test:
	@for tags in $(TAGSETS); do echo "== go test -tags '$$tags'"; $(GO) test -count=1 -tags "$$tags" $(PKGS) || exit 1; done

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
	@for tags in $(TAGSETS); do for os in linux windows; do echo "== vet $$os '$$tags'"; GOOS=$$os $(GO) vet -tags "$$tags" $(PKGS) || exit 1; done; done

staticcheck:
	@for tags in $(TAGSETS); do for os in linux windows; do echo "== staticcheck $$os '$$tags'"; GOOS=$$os staticcheck -tags "$$tags" $(PKGS) || exit 1; done; done

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
lab-down:
	@bash lab/lab.sh down
lab-reset:
	@bash lab/lab.sh reset
