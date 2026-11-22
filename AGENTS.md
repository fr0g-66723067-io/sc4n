# AGENTS.md

sc4n is a static scanner for ML model artifacts and the code around them. It
decodes bytes — pickle opcodes, archive directories, format headers, Python
source, chat templates, cards — and reports what would execute, read files or
dial the network on load. It never runs the artifact.

This file is for anyone changing the tree, human or agent. It states what must
stay true, the gates that prove it, and the conventions a diff is judged by.
`README.md` is the user-facing document; `docs/architecture.md` is the design
document and the place for the *why* of a mechanism. Neither is repeated here.

Go 1.27.3 (`go.mod`), module `github.com/fr0g-66723067-io/sc4n`.

## Invariants

A change that breaks one of these is wrong, not a tradeoff.

1. **The scan path executes nothing.** `internal/**` and `cmd/**` import no
   `os/exec` and no `tools/` package. Enforced by
   `tools/sc4nconfirm/boundary_test.go` (`TestScanPathStillDoesNotExec`,
   `TestScannerDoesNotImportTheHarness`) and mirrored in
   `tools/sc4nlab/boundary_test.go`. Loading an artifact for real is
   `tools/sc4nconfirm`'s job, in a disposable container.
2. **The scan path is stdlib-only plus `google.golang.org/protobuf`.** No new
   module without a reason the README's "What sc4n does not do" section can
   carry. The only non-test package that imports `net/http` is
   `internal/hubapi`, because only `sc4n hub` dials; `scan` must stay offline.
3. **Content decides the format, not the extension.** Dispatch is by sniffed
   bytes (`internal/artifact`); an extension that disagrees with the content is
   itself a finding. A sniffer that claims a file it cannot walk is a silent
   miss, and a silent miss reads exactly like a clean file.
4. **Silent truncation is forbidden.** Every cap in `internal/limits` emits an
   `SC4N-LIMIT-*` finding naming the limit and the observed value. A partial
   parse says so (`SC4N-PARSE-FAILED`, `SC4N-PARTIAL-SLICE`), and a cancelled
   scan reports `summary.cancelled` rather than presenting a partial result as
   complete.
5. **Determinism is a property, not a nicety.** Two runs over the same bytes
   produce byte-identical JSON, SARIF and CycloneDX: sorted findings, stable
   rule order, no map iteration in output. Several tests assert exactly this,
   so a non-deterministic encoder fails `make test`.
6. **A rule is declared once, by pointer.** Use `report.DefineRule` from the
   format package's `rules.go` and emit through that pointer. `DefineRule`
   panics on a malformed or duplicate ID on purpose. Never build a `report.Rule`
   literal inline: the catalogue, JSON, and SARIF would then disagree.
7. **Report, never rewrite.** sc4n does not repair, quarantine or sanitise an
   artifact, and it writes no path except `-out` (and unlinked spill files under
   `TMPDIR`).

## Commands

```sh
make build        # ./sc4n, version stamped from `git describe`
make test         # go vet ./... + go test ./... + go test -race ./... (the gate)
make all          # vet + test + docs-links
make docs-links   # every link and anchor in README.md and docs/ resolves
make rules-doc    # regenerate docs/rules.md from the registry
make fixtures     # regenerate testdata/fixtures (deterministic)
make fuzz         # every parser's fuzz target, FUZZTIME=30s per target
make bench        # benchmarks, -benchmem
make bench-big    # 13 GiB safetensors RSS budget; SC4N_BIG_DIR, SC4N_BIG_GB
make sarif-check  # validates emitted SARIF against the 2.1.0 schema
make docker       # the release image
make lab confirm-image   # the out-of-scanner harnesses (tools/ only)
```

Run the narrowest gate that covers the change. A parser change is not verified
until `go test ./internal/<format>` passes and the fixture corpus still matches;
a rule change is not verified until `make rules-doc` leaves no diff.

## Changing a parser or adding a format

`docs/architecture.md` §"Adding a format" is authoritative. The short form:

1. Add the `Format` constant and any diagnostic extension mapping in
   `internal/artifact/format.go`.
2. Create `internal/<format>/` with `parser.go` (registration, sniffer, parser),
   `rules.go` (`DefineRule` calls, references in the description) and the
   parsing files.
3. Add `internal/formats/<format>.go`: `package formats` plus a blank import, so
   the CLI links the parser.
4. Add `tools/sc4nfixtures/<format>_fixtures.go` — fixture bytes and expectation
   maps, generated in Go, never downloaded. Each fixture's doc comment names the
   attack it reproduces.
5. `make fixtures && go test ./internal/... -run TestFixtureExpectations`.
6. Gate informational statistics behind `ctx.Session.DeepStats`.

Parsers take a `source.Source` and recurse with `artifact.ScanMember`, so
naming, depth accounting and the depth budget exist once. Bounds come from
`ctx.Limits`; never allocate from a declared length before checking it.

## Tests

- Table-driven, one behaviour per test, and the test name states the claim:
  `TestSubprocessNonExecFunctionsAreNotSinks`, `TestPthExecutable`,
  `TestJSONOutputIsDeterministicAndComplete`. A comment above a fixture or test
  says what attack or defect it pins.
- No wall-clock assertions. A busy machine is not a regression; assert a ratio,
  an allocation count or an RSS bound, and print timings without asserting them
  (`Makefile` bench-big, `internal/tokenizer` guard).
- Fuzz targets exist for every parser (`make fuzz`). Their invariant is: no
  panic, bounded memory, terminates.
- `testdata/fixtures/expectations.json` is the corpus gate: an on-disk fixture
  with no expectation entry fails the test, so a fixture cannot be added without
  stating what it is for.
- Prefer a failing test that reproduces the report over a re-run of a passing
  suite; a fix without a test that would have caught it is unfinished.

## Generated files

Never hand-edit these; regenerate and commit the result:

| file | generator | gate |
|---|---|---|
| `docs/rules.md` | `make rules-doc` | `go test ./tools/sc4nrules`, CI diff |
| `testdata/fixtures/**` | `make fixtures` | `TestFixtureExpectations`, CI diff |

A new rule also needs a triage path: add its prefix to the bucket table in
`tools/sc4nrules/main.go` and a matching `<a id="..."></a>` section in
`docs/triage.md`, or `TestEveryRuleHasABucket` and `TestTriageAnchorsExist`
fail.

Binaries (`/sc4n`, `/sc4nlab`, `/sc4nfixtures`, `/sc4nconfirm`, `/dist/`) are
gitignored. Fixtures under `testdata/big/` are generated and never committed.

## Documentation

The repo writes prose as assertions with the reason attached ("a probe that
refuses a file it could have walked is indistinguishable from a clean file").
Keep that: state what the code guarantees and what breaks otherwise. Wrap at 80
columns. Never copy a count, limit or measured number into prose if it is
generated or measured — link to `sc4n rules`, `sc4n formats`, or the document
that owns it; prose copies of the rule count drifted twice.

Behaviour changes land with the document that describes them:

| change | document |
|---|---|
| flag, exit code, output shape | `README.md` §Flags/§Exit codes, `docs/quickstart.md` |
| new or retuned rule | `docs/rules.md` (generated), `docs/triage.md` section for the family, `docs/threat-model.md` justification |
| limit or performance claim | `docs/architecture.md` §Limits/§Performance, `docs/measurements.md` |
| attestation or harness | `docs/attestation.md` |
| SARIF or CI integration | `docs/github-code-scanning.md` |
| release assets or workflow | `docs/release.md` |
| disclosure route or reporting scope | `SECURITY.md` |

## Performance rules

- Only the standard library on the hot path. The two evaluated experiments (a
  SIMD byte-class histogram, `encoding/json/v2` header decoding) were dropped
  because neither reached 1.5x on its own kernel; that is the bar a new special
  path has to clear, measured, or it does not ship.
- `make test-simd` must keep passing under `GOEXPERIMENT=simd` and
  `GODEBUG=simd=0`. Never add `GODEBUG=simd=256`: it bypasses the CPU feature
  check and can SIGILL.
- Allocation, copy and decompression are the cost centres (`internal/bytescan`,
  `internal/stringscan`, `internal/source`). A change to a hot kernel is
  reported with `make bench` numbers before and after, not with an adjective.

## Commits

Subject line: `<scope>: <a claim about the new behaviour>`, lowercase, no
`feat:`/`fix:` ceremony. The claim describes what the tree now guarantees, not
the activity.

```text
pickle: a stream found inside other bytes must decode more than a scalar
tests: no wall-clock assertions, because a busy machine is not a regression
archive: a .joblib in xz, lzma or lz4 is a loader escalation, not just an unscanned payload
```

- Commit on the branch you are on (`master` is normal). Push only to the
  operator-designated mirror remote; github.com and every other remote stay
  operator-gated.
- Stage explicit paths, never `-A`: generated corpora and binaries are easy to
  sweep in by accident.
- One logical change per commit; `make test` green before each.
- Commit before any `git checkout --`, `git restore`, `git reset --hard` or
  `git clean`. Uncommitted work has no reflog copy.

## Before claiming done

1. The narrowest test that exercises the change passes.
2. If a rule, format or fixture changed: `make fixtures && make rules-doc`, then
   `git diff --exit-code testdata/fixtures docs/rules.md`.
3. If docs changed: `make docs-links`.
4. If the scan path changed: the boundary tests still pass and no new module,
   `os/exec`, `net/http` or `tools/` import crept into `internal/` or `cmd/`.
5. State what was run. "It builds" is not verification of behaviour.
