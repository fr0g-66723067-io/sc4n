# Quickstart

Ten minutes from nothing to a gated CI check. Every command and every output
block below was run against this repository's fixture corpus, so you can reproduce
all of it offline before pointing the scanner at anything you care about.

## Install

Three ways, in order of convenience. The release assets and the image are public,
so neither needs credentials; `make release` builds and verifies the same
artifacts from the tag if you would rather not download them.

```sh
# 1. released binary (linux/amd64 shown; darwin and windows builds are published too)
curl -LO https://github.com/fr0g-66723067-io/sc4n/releases/download/v1.0.1/sc4n_v1.0.1_linux_amd64
curl -LO https://github.com/fr0g-66723067-io/sc4n/releases/download/v1.0.1/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing && chmod +x sc4n_v1.0.1_linux_amd64

# 2. container, which is the right way to scan bytes you do not trust
docker pull ghcr.io/fr0g-66723067-io/sc4n:v1.0.1

# 3. from source: Go 1.27.3, no code generation, no third-party tooling
git clone https://github.com/fr0g-66723067-io/sc4n && cd sc4n
go build -o sc4n ./cmd/sc4n
```

The binary is statically linked (`CGO_ENABLED=0`) and has one dependency,
`google.golang.org/protobuf`, which is compiled in. It dials nothing: only
`sc4n hub` uses the network.

## Your first scan

Offline, against the fixtures in this repository:

```sh
./sc4n scan testdata/fixtures/benign
```

```text
ARTIFACT	FORMAT	SIZE	FINDINGS
testdata/fixtures/benign/card/README.md                   markdown       193 B    0
testdata/fixtures/benign/model.safetensors                safetensors    694 B    0
… 50 rows omitted: 45 with no finding, 5 with the single info finding listed below
testdata/fixtures/benign/tiny.onnx                        onnx           77 B     0

SEVERITY	CONFIDENCE	RULE	LOCATION	EVIDENCE
INFO  high  SC4N-NATIVE-VALID       testdata/fixtures/benign/native_imports_benign.so  the artifact is a valid ELF executable; sc4n does not disassemble it, and does not run it
INFO  high  SC4N-TORCH-ZIP          testdata/fixtures/benign/torch_clean.pt            new-format torch zip: data.pkl + data/<n> storages
INFO  high  SC4N-ARCHIVE-TRUNCATED  testdata/fixtures/benign/truncated_plain.zip       1 member(s) recovered from local headers; 1 scanned

sc4n: 53 artifact(s), 5 finding(s) [5 info], max severity info
```

Exit code 0: nothing at or above the default `-fail-on high`. The five `info`
findings are statements of what the format is and what was not interpreted — they
are not a risk signal, which is why a benign tree can carry them and still pass
the release gate.

Now one hostile artifact:

```sh
./sc4n scan testdata/fixtures/joblib_object_array.joblib
```

```text
ARTIFACT	FORMAT	SIZE	FINDINGS
testdata/fixtures/joblib_object_array.joblib  joblib  83 B  6

SEVERITY	CONFIDENCE	RULE	LOCATION	EVIDENCE
MEDIUM    low     SC4N-PICKLE-REQUIRES-UNSAFE-LOADER  …:object-array.pkl       the stream uses at least one opcode the weights-only unpickler rejects…
CRITICAL  high    SC4N-PICKLE-GLOBAL-CRITICAL         …:object-array.pkl+0xe   os.system: sink process and filesystem primitives (os.system, os.popen, …)
INFO      medium  SC4N-PICKLE-SAFE-GLOBALS            …:object-array.pkl+0xe   all 1 global(s) in this stream are outside the built-in weights-only allowlist…
CRITICAL  high    SC4N-MALICE-CONSTRUCTED             …:object-array.pkl+0x14  REDUCE calls os.system with a 2-byte command string, so the artifact supplies the code the loader runs
HIGH      high    SC4N-PICKLE-REDUCE                  …:object-array.pkl+0x14  REDUCE calls os.system, which is not in the weights-only allowlist…

sc4n: 1 artifact(s), 6 finding(s) [2 critical, 1 high, 2 medium, 1 info], max severity critical
sc4n: 3 finding(s) at or above high (worst: critical)
```

Exit code 1. Three things in that output are worth reading carefully:

- **`LOCATION` is a member chain.** The finding is inside a joblib payload, so the
  location is `artifact:member`, and `+0xe` is the byte offset inside the member.
- **Two criticals, one artifact.** `SC4N-PICKLE-GLOBAL-CRITICAL` says a sink is
  reachable; `SC4N-MALICE-CONSTRUCTED` says the reach *passes code the artifact
  supplies* (`os.system` called with the stream's own argument). If only the first
  were present, the reach would be structural.
- **`CONFIDENCE` is per rule, not per artifact.** The two criticals are `high`; the
  two mediums are `low` for a reason stated in their evidence.

## Read a finding as data

```sh
./sc4n scan -format json -out scan.json testdata/fixtures/joblib_object_array.joblib
```

```json
{
  "ruleId": "SC4N-PICKLE-GLOBAL-CRITICAL",
  "title": "Pickle references a direct code-execution primitive",
  "severity": "critical",
  "confidence": "high",
  "cwe": ["CWE-502", "CWE-94"],
  "class": "pickle",
  "artifact": "testdata/fixtures/joblib_object_array.joblib:object-array.pkl",
  "offset": 14,
  "evidence": "os.system: sink process and filesystem primitives (os.system, os.popen, …)"
}
```

| field | use |
|---|---|
| `ruleId` | look it up in [`docs/rules.md`](rules.md) — severity, rationale, references |
| `artifact` | the exact file, plus the member chain when the finding is inside a container |
| `offset` | byte offset inside that member; `docs/triage.md` explains why it is not part of a finding's identity |
| `evidence` | the decoded fact behind the finding: the sink, its argument, the path, the header field |
| `cwe` | the weakness class, for a ticket or an exception policy |

## Decide

[`docs/triage.md`](triage.md) is the decision procedure: severity × confidence →
what to do, then one section per finding family. The short version:

- **critical** — treat the artifact as hostile until you have read the evidence.
  In the pickle family the model's loader *is* the code path.
- **high/medium** — check whether the reach is structural (no
  `SC4N-MALICE-CONSTRUCTED`) and whether the container is one your loader opens.
- **info** — triage once, then baseline it. `SC4N-LIMIT-*` means "not scanned
  here", not "clean".

## Gate CI, and stop re-triaging

```sh
./sc4n scan -format json -out baseline.json ./models     # 1. review this
./sc4n scan -baseline baseline.json -fail-on high ./models  # 2. gate on this
```

The second run suppresses what the first contained and says so:

```text
sc4n: 1 artifact(s), 0 finding(s); suppressed: 6
```

Suppression is keyed on `(rule, artifact, evidence)`, not on the byte offset, so
an unrelated edit does not resurrect every finding — and the count is printed, so a
baseline can never turn a new finding into a clean run. `-max-findings` is applied
after suppression, and keeps the *most severe* findings, so a flood of low
severity findings cannot push a critical out.

For GitHub code scanning, [`docs/github-code-scanning.md`](github-code-scanning.md)
has the upload workflow; the SARIF output is validated against the format's schema
by `make sarif-check`.

## Scan real artifacts

A downloaded model directory works as-is:

```sh
./sc4n scan -fail-on high ./models/bert-base-uncased
```

Two flags matter on real repositories:

- `-partial PATH` — you told the fetch that this file is a truncated slice (a
  campaign budget, a partial download), so an extent check reports
  `SC4N-PARTIAL-SLICE` instead of a violation caused by the truncation.
- `-symlinks root` (the default) — a symbolic link whose target escapes the scanned
  tree is refused and named, not followed.

For bytes you do not trust, run the container. `--network=none` is safe because
`scan` never dials, `--read-only` bounds writes, and the process is non-root:

```sh
docker run --rm --network=none --read-only --tmpfs /tmp:rw,size=1g \
  --user "$(id -u):$(id -g)" \
  -v "$PWD:/scan:ro" \
  ghcr.io/fr0g-66723067-io/sc4n:v1.0.1 \
  scan -format sarif -out /tmp/sc4n.sarif -fail-on high /scan
```

A Hugging Face repository can be fetched and scanned in one command (this is the
only path that touches the network, and it writes only under `-out`):

```sh
./sc4n hub -out one -repo LiquidAI/LFM3-1.7B -level any -defaults=false -stage all
```

## Prove a critical, without letting it run here

The scanner never executes anything, so "these bytes ran" needs a sandbox. The
harness builds one once, then loads the artifact the way a user would:

```sh
make confirm-image
go run ./tools/sc4nconfirm -artifact testdata/fixtures/pickle_gadget_os_system.pkl -out /tmp/attestation.json
./sc4n scan -attestation /tmp/attestation.json testdata/fixtures/pickle_gadget_os_system.pkl
```

```text
CRITICAL  high    SC4N-MALICE-DEMONSTRATED   testdata/fixtures/pickle_gadget_os_system.pkl
    loading with pickle.load executed "/bin/sh -c -- id", "/usr/bin/id"; attempted to connect to "unix:/var/run/nscd/socket"…

sc4n: 1 artifact(s), 6 finding(s) [3 critical, 1 high, 1 medium, 1 info], max severity critical
sc4n: attestation /tmp/attestation.json: 1 of 1 run(s) matched a scanned artifact
```

The demonstration is *additional* information: the capability and constructed
findings stay, and the merge line says how many runs matched, so an attestation
that matched nothing is visible instead of silent. An artifact that *failed* to
load demonstrates nothing either — `loaded: false` with the error is recorded
rather than read as "no effects". The digest key is the full SHA-256, which is why
a scan run with `-max-hash` cannot be attested. The format, and how to produce one from a VM, a pod or your own
harness instead of Docker, is [`docs/attestation.md`](attestation.md).

## Where to go next

| document | what it answers |
|---|---|
| [`docs/triage.md`](triage.md) | what to do with the finding in front of you |
| [`docs/rules.md`](rules.md) | every rule, its severity and rationale (generated from the registry) |
| [`docs/threat-model.md`](threat-model.md) | threat class → evidence → rule → residual risk; the justification for every detector |
| [`docs/architecture.md`](architecture.md) | pipeline, limits, measured performance, how to add a format or rule |
| [`docs/measurements.md`](measurements.md) | what the scanner actually did on real corpora: findings, false-positive rate, recall, limits |
| [`docs/attestation.md`](attestation.md) | the demonstration format, and producing one without Docker |
| [`docs/github-code-scanning.md`](github-code-scanning.md) | the SARIF upload workflow and its traps |
| [`docs/release.md`](release.md) | how a release is built, verified and published |
