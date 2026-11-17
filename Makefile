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
CMDS := shunya-hello

.PHONY: all build build-linux build-windows test race vet staticcheck vulncheck lint fmt-check ci clean \
        lab-images lab-up lab-shell lab-test lab-down lab-reset

all: lint test build

build: build-linux build-windows

build-linux:
	@mkdir -p $(BIN)/linux-amd64
	@for c in $(CMDS); do GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS_REPRO) -ldflags '$(LDFLAGS)' -o $(BIN)/linux-amd64/$$c ./cmd/$$c || exit 1; done
	@sha256sum $(BIN)/linux-amd64/*

build-windows:
	@mkdir -p $(BIN)/windows-amd64
	@for c in $(CMDS); do GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS_REPRO) -ldflags '$(LDFLAGS)' -o $(BIN)/windows-amd64/$$c.exe ./cmd/$$c || exit 1; done

test:
	$(GO) test -count=1 $(PKGS)

race:
	CGO_ENABLED=1 $(GO) test -race -count=1 $(PKGS)

vet:
	$(GO) vet $(PKGS)
	GOOS=windows $(GO) vet $(PKGS)

staticcheck:
	staticcheck $(PKGS)
	GOOS=windows staticcheck $(PKGS)

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
lab-test: build-linux
	@bash lab/lab.sh test
lab-down:
	@bash lab/lab.sh down
lab-reset:
	@bash lab/lab.sh reset
