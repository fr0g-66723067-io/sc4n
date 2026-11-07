# sc4n — static scanner for ML model artifacts and the code around them.
#
# Nothing here *requires* an experiment: every file builds on a stock toolchain.
#
# Two experiments were evaluated for the hot paths and neither is shipped, because
# neither earned its place by the plan's own rule (>= 1.5x on its own kernel):
#
#   - a SIMD byte-class histogram (goexperiment.simd, simd/archsimd). Evaluated,
#     dropped and then deleted: no detector reads a byte-class histogram (the entropy
#     pass over the same bytes is bytescan.Entropy, 1.0-1.2 GB/s), the kernel itself
#     measured 0.10 GB/s on tensor-body bytes, and the string engine's real bottleneck
#     is the Aho-Corasick walk's dependent load chain, which a histogram kernel does
#     not touch. Measured numbers are in docs/architecture.md.
#   - encoding/json/v2 (goexperiment.jsonv2) for header decoding. The header
#     decode is microseconds per artifact against a scan that is dominated by I/O
#     and hashing; there was no measurable end-to-end win to show.
#
# `test-simd` remains: it proves the tree still builds and passes under
# GOEXPERIMENT=simd, which is where a future kernel would have to live.

GO ?= go
BIN ?= sc4n
# The version a build stamps. `git describe` is the release form; a tree without
# tags or git stamps its commit; no git at all stamps "dev", which is what the
# binary reported for every build before this.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all build vet test test-simd bench bench-big fixtures fuzz clean fmt diffscan docker lab oracle-image confirm-image confirm

all: vet test

build:
	$(GO) build -trimpath -ldflags "-X main.version=$(VERSION)" -o $(BIN) ./cmd/sc4n

# The image is the documented way to scan an untrusted repository: --network=none
# (the scan path has no dialer), --read-only and a non-root user bound what the
# binary may read and write, which a path check alone cannot.
docker:
	docker build --build-arg VERSION=$(VERSION) -t $(BIN):$(VERSION) .

vet:
	$(GO) vet ./...

# `go vet ./...` twice is deliberate: the untagged pass proves the stock
# toolchain still builds every pure-stdlib counterpart.
test:
	$(GO) vet ./...
	$(GO) test ./...
	$(GO) test -race ./...

# Both passes are required: the emulated one (GODEBUG=simd=0) takes the
# experiment's portable code paths, which is where a future SIMD kernel would
# first break. Do not add GODEBUG=simd=256: it bypasses the CPU feature check and
# can SIGILL.
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

# The validity-oracle lab: mutates real artifacts, keeps the mutants an external
# validator accepts and scans them. It is a separate binary because it shells
# out and runs Python in a container, which the scanner itself never does.
lab:
	$(GO) build -trimpath -o sc4nlab ./tools/sc4nlab

# The graphs profile's oracle: onnx.checker and onnxruntime, pinned. Built once;
# `make lab` does not need it for the containers or native profiles.
oracle-image:
	docker build -t sc4n-oracle:1 ./tools/sc4nlab

# The confirmation sandbox: a disposable container with no network, a read-only
# root and strace, in which an artifact is loaded for real. Executing payloads is
# a tool's job, never the scanner's (internal/ and cmd/ have no os/exec).
confirm-image:
	docker build -t sc4nconfirm:1 ./tools/sc4nconfirm/image

# Attest artifacts, then merge the attestation into a scan:
#   make confirm ARTIFACTS="model.bin other.joblib" ATTESTATION=/tmp/att.json
#   sc4n scan -attestation /tmp/att.json <paths>
confirm:
	$(GO) run ./tools/sc4nconfirm $(foreach a,$(ARTIFACTS),-artifact $(a)) -out $(ATTESTATION)

# The rule catalogue a reader without a binary can browse. Generated from the
# registry, and `go test ./tools/sc4nrules` fails when the committed file is
# stale, so a rule added without running this cannot ship undocumented.
rules-doc:
	$(GO) run ./tools/sc4nrules -out docs/rules.md

# Regenerates testdata/fixtures. Deterministic: a second run produces no diff.
fixtures:
	$(GO) run ./tools/sc4nfixtures -out testdata/fixtures

# Each parser's fuzz target, seeded from the fixture corpus. Invariant for all of
# them: no panic, bounded memory, terminates. FUZZTIME is per target, so the whole
# target costs roughly (number of targets) x FUZZTIME.
FUZZTIME ?= 30s
fuzz:
	$(GO) test ./internal/pickle     -run '^$$' -fuzz FuzzPickleWalk     -fuzztime $(FUZZTIME)
	$(GO) test ./internal/artifact   -run '^$$' -fuzz FuzzSniffNeverPanics -fuzztime $(FUZZTIME)
	$(GO) test ./internal/gguf       -run '^$$' -fuzz FuzzGGUF           -fuzztime $(FUZZTIME)
	$(GO) test ./internal/safetensors -run '^$$' -fuzz FuzzSafetensors   -fuzztime $(FUZZTIME)
	$(GO) test ./internal/onnx       -run '^$$' -fuzz FuzzONNX           -fuzztime $(FUZZTIME)
	$(GO) test ./internal/tfmodel    -run '^$$' -fuzz FuzzKerasDocument  -fuzztime $(FUZZTIME)
	$(GO) test ./internal/tfmodel    -run '^$$' -fuzz FuzzKerasParse     -fuzztime $(FUZZTIME)
	$(GO) test ./internal/tfmodel    -run '^$$' -fuzz FuzzHDF5Parse      -fuzztime $(FUZZTIME)
	$(GO) test ./internal/tfmodel    -run '^$$' -fuzz FuzzSavedModelParse -fuzztime $(FUZZTIME)
	$(GO) test ./internal/tfmodel    -run '^$$' -fuzz FuzzCheckpointParse -fuzztime $(FUZZTIME)
	$(GO) test ./internal/tfmodel    -run '^$$' -fuzz FuzzTFLiteParse    -fuzztime $(FUZZTIME)
	$(GO) test ./internal/torch      -run '^$$' -fuzz FuzzTorch          -fuzztime $(FUZZTIME)
	$(GO) test ./internal/numpy      -run '^$$' -fuzz FuzzParseNPY       -fuzztime $(FUZZTIME)
	$(GO) test ./internal/numpy      -run '^$$' -fuzz FuzzParseJoblib    -fuzztime $(FUZZTIME)
	$(GO) test ./internal/msgpack    -run '^$$' -fuzz FuzzParseMsgpack   -fuzztime $(FUZZTIME)
	$(GO) test ./internal/xgb        -run '^$$' -fuzz FuzzUBJWalk        -fuzztime $(FUZZTIME)
	$(GO) test ./internal/coreml     -run '^$$' -fuzz FuzzCoreMLWalk     -fuzztime $(FUZZTIME)
	$(GO) test ./internal/pte        -run '^$$' -fuzz FuzzPTEHeader      -fuzztime $(FUZZTIME)
	$(GO) test ./internal/content    -run '^$$' -fuzz FuzzContentParse   -fuzztime $(FUZZTIME)
	$(GO) test ./internal/archive    -run '^$$' -fuzz FuzzArchive        -fuzztime $(FUZZTIME)
	$(GO) test ./internal/stringscan -run '^$$' -fuzz FuzzScanIndicators -fuzztime $(FUZZTIME)
	$(GO) test ./internal/pysrc      -run '^$$' -fuzz FuzzPythonLex      -fuzztime $(FUZZTIME)
	$(GO) test ./internal/jinja      -run '^$$' -fuzz FuzzJinjaAnalyze   -fuzztime $(FUZZTIME)
	$(GO) test ./internal/tokenizer  -run '^$$' -fuzz FuzzTokenizerJSON  -fuzztime $(FUZZTIME)
	$(GO) test ./internal/cards      -run '^$$' -fuzz FuzzCardText       -fuzztime $(FUZZTIME)
	$(GO) test ./internal/polyglot   -run '^$$' -fuzz FuzzPolyglot       -fuzztime $(FUZZTIME)
	$(GO) test ./internal/repo       -run '^$$' -fuzz FuzzRepoFile       -fuzztime $(FUZZTIME)

# Optional differential check against fickling/picklescan/modelscan. Skipped
# loudly when the tools are absent (they are absent on the reference host).
diffscan:
	./tools/diffscan.sh testdata/fixtures

fmt:
	$(GO) fmt ./...

clean:
	$(GO) clean -testcache
	rm -f $(BIN) sc4nlab
