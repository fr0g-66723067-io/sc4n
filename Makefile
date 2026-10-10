# sc4n — static scanner for ML model artifacts and the code around them.
#
# Unlike gr4ph, nothing here *requires* an experiment: the SIMD byte-class
# kernel (internal/stringscan/kernel_simd.go) and the encoding/json/v2 header
# decoder (internal/jsonutil/...) live behind build tags with pure-stdlib
# counterparts, so `go build ./cmd/sc4n` works on a stock toolchain.

GO ?= go
BIN ?= sc4n

.PHONY: all build vet test test-simd bench bench-big fixtures fuzz clean fmt diffscan

all: vet test

build:
	$(GO) build -o $(BIN) ./cmd/sc4n

vet:
	$(GO) vet ./...

# `go vet ./...` twice is deliberate: the untagged pass proves the stock
# toolchain still builds every pure-stdlib counterpart.
test:
	$(GO) vet ./...
	$(GO) test ./...
	$(GO) test -race ./...

# The emulated pass (GODEBUG=simd=0) is a distinct code path from the native one
# and is the only pass that runs the pure-Go fallback inside the same binary, so
# both are required. Do not add GODEBUG=simd=256: it bypasses the CPU feature
# check and can SIGILL.
test-simd:
	GOEXPERIMENT=simd $(GO) test ./...
	GODEBUG=simd=0 GOEXPERIMENT=simd $(GO) test ./...

bench:
	$(GO) test -run '^$$' -bench . -benchmem ./...

# Generates a 13 GiB F16 safetensors, scans it and asserts the wall-time and RSS
# budget from docs/architecture.md. Never committed.
#
# Two environment knobs, both of which exist because the defaults are wrong on a
# small machine: SC4N_BIG_DIR picks where the ~13 GiB fixture is written (it
# defaults to $TMPDIR, which on the reference host is a 7.5 GiB tmpfs — point it
# at a real filesystem) and SC4N_BIG_GB scales the fixture down for a smoke run.
# The test skips loudly when the target has no room rather than shrinking itself.
# -timeout is raised because writing 13 GiB on a slow disk takes minutes before
# the scan is even timed.
bench-big:
	$(GO) test -tags=bigfixtures -run TestBigSafetensors -v -timeout 30m ./internal/scan

# Regenerates testdata/fixtures. Deterministic: a second run produces no diff.
fixtures:
	$(GO) run ./tools/sc4nfixtures -out testdata/fixtures

fuzz:
	$(GO) test ./internal/pickle -run '^$$' -fuzz FuzzPickleWalk -fuzztime 30s
	$(GO) test ./internal/artifact -run '^$$' -fuzz FuzzDispatch -fuzztime 30s
	$(GO) test ./internal/gguf -run '^$$' -fuzz FuzzGGUF -fuzztime 30s
	$(GO) test ./internal/safetensors -run '^$$' -fuzz FuzzSafetensors -fuzztime 30s

# Optional differential check against fickling/picklescan/modelscan. Skipped
# loudly when the tools are absent (they are absent on the reference host).
diffscan:
	./tools/diffscan.sh testdata/fixtures

fmt:
	$(GO) fmt ./...

clean:
	$(GO) clean -testcache
	rm -f $(BIN)
