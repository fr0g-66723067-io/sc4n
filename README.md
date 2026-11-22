# sc4n

Static scanner for ML model artifacts and the code around them.

sc4n answers one question for a machine-learning artifact it is pointed at: *what
in here executes, reads files, or talks to the network when this thing is loaded?*
It answers it by decoding bytes — pickle opcodes, archive directories, format
headers, Python source, chat templates, cards — and never by running anything.

- **No execution, ever.** The artifact is not imported, not unpickled, not
  extracted to disk, not passed to an external parser or decompressor. The only
  path it writes permanently is `-out`: an archive member too large to hold in
  memory is materialised in an unlinked temporary file under `TMPDIR` and mapped,
  never extracted to a visible path.
- **Content-based dispatch.** The format comes from the bytes, not the file name.
  A `.safetensors` that is a zip is scanned as a zip, and the disagreement is
  itself a finding (`SC4N-FORMAT-EXTENSION-MISMATCH`). An extension is exempt where
  the pair is a real convention rather than a contradiction: `.pt` may be a 7z
  archive and `.bin` may be a pickle — the torch and Hugging Face save conventions —
  so neither is reported as a mismatch.
- **Report-only.** sc4n never rewrites, repairs or quarantines an artifact. It
  emits findings, plus an exit code a CI job can gate on. The report itself is
  escaped, not echoed: a crafted file name or evidence string cannot inject
  terminal escapes into a log or reflow the text table.
- **Bounded and deterministic.** One worker per artifact, a size-weighted memory
  budget, memory-mapped reads, and sorted output: two runs over the same bytes
  produce byte-identical JSON.

## Coverage

| family | formats |
|---|---|
| pickle | bare pickle, joblib (zlib/gzip/bzip2 unwrapped; lzma/xz/lz4/zstd recognised and reported, not decompressed), torch zip, torch legacy, TorchScript, `.pt2` export archives |
| numeric | safetensors, `.npy`/`.npz` (including object dtype), msgpack (Flax/JAX/MLX), XGBoost UBJSON |
| model | GGUF, ONNX, TF SavedModel/GraphDef and checkpoints, Keras `.keras`/`.h5`, TFLite, CoreML `.mlmodel`/`.mlpackage`, ExecuTorch `.pte`, TensorRT `.engine`/`.plan` (magic only) |
| containers | zip (including zip64, prefixed archives and large stored members), tar, gzip, zlib, bzip2 (xz/lzma/lz4/zstd/7z/rar are recognised and reported, never decompressed — see `sc4n formats`) |
| code and metadata | Python source, notebooks, Jinja chat templates, model/dataset cards, `config.json`/`tokenizer_config.json`/`adapter_config.json`, `setup.py`, `pyproject.toml`, `.pth`, `*.start`, GitHub workflows, wheels inside a repo |

`sc4n formats` prints the same table with the **analysis depth** of every format,
including the ones that are deliberately recognised but not parsed. Every rule
states its severity, confidence and class, and a CWE where one applies. `sc4n
rules` prints the live catalogue with the rule count and how many name a
weakness; the rest are the ones where there is nothing to name, such as "the
weights are all zero" or "the extent could not be verified". Counts are not
repeated in this document: they are generated from the rule definitions, and
prose copies of them drifted twice.

## Install

```sh
# released binary (linux/amd64; arm64, darwin and windows builds are published too)
curl -LO https://github.com/fr0g-66723067-io/sc4n/releases/download/v1.0.1/sc4n_v1.0.1_linux_amd64
curl -LO https://github.com/fr0g-66723067-io/sc4n/releases/download/v1.0.1/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing

# container, built locally from this tree: the release page carries binaries only
VERSION=v1.0.1 make docker

# or from source: Go 1.27.3, no code generation, no third-party tooling
go build -o sc4n ./cmd/sc4n
```

`v1.0.1` is published by `.github/workflows/release.yml`: five static binaries and
`SHA256SUMS` on the release page. The container image is not published — CI builds
no image — and `make docker` builds it locally from the same tag. Nothing is
published from a branch, and `make release` builds and verifies the same artifacts
locally.

The release assets are checksums-only: `SHA256SUMS` and no signature on the
binaries. The git history and the release tags are signed with the project's SSH
signing key, so the tag a build claims can be verified before you trust it.
[`docs/release.md`](docs/release.md) §Provenance gives the key and the command,
and states what each check does and does not prove.

## Quickstart

```sh
# a downloaded model directory
./sc4n scan ./models/bert-base-uncased

# one artifact, machine-readable
./sc4n scan -format json ./model.safetensors

# a repository, gated, with SARIF for GitHub code scanning
./sc4n scan -format sarif -out sc4n.sarif -fail-on high .

# scan untrusted bytes in the container (scan never dials, so no network needed)
docker run --rm --network=none --read-only --tmpfs /tmp:rw,size=1g \
  --user "$(id -u):$(id -g)" -v "$PWD:/scan:ro" \
  sc4n:v1.0.1 scan -fail-on high /scan
```

[`docs/quickstart.md`](docs/quickstart.md) is the ten-minute version: install, a
clean tree and a hostile artifact with their real output, reading a finding as
data, the baseline loop, and the sandbox demonstration.

## Campaigns: the Hugging Face unsafe round

The Hub runs its own scanner and exposes the verdict per repo
(`/api/models/{id}/scan`); it has no listing filter for that verdict, so the only
complete method is to enumerate candidates and probe each one. `sc4n hub` does
exactly that, then fetches the flagged files, scans them, and joins the two
verdicts into one report:

```sh
./sc4n hub -out hf-campaign -stage all      # the whole round
./sc4n hub -out hf-campaign -stage fetch    # resume at one stage
```

Each stage is a file -> file transform over one directory (`candidates.json`,
`verdicts.json`, `fetch.json`, `repos/`, `scan.json`, then `campaign.json` and
`campaign.md`), so a campaign can be interrupted, inspected and resumed, and a
re-run over the same stage files is byte-identical. Nothing is dropped silently:
a gated file, a budget refusal, a traversal path and an unrecognised format each
become a status with a reason, and `campaign.md` lists the files that were fully
covered and produced no finding — the misses are the visible artifact. A gated
file's reason names the gate mode and the URL: `automatic approval` means the
account accepts the terms once (in a browser) and the same token then works,
`manual approval` means only the repository owner can grant access, so no client
retry can change the outcome.

A campaign does not have to start from a search. Three other universes are
first-class, and `-level any` scans every repo in the universe instead of only the
ones the Hub already flagged:

```sh
# the ten most-downloaded models (the Hub's 30-day count; it publishes no 7-day figure)
./sc4n hub -out top10 -rank downloads -top 10 -level any -defaults=false -stage all

# the ten most trending models (trendingScore — the Hub's recent-window ranking)
./sc4n hub -out trending -rank trendingScore -top 10 -level any -defaults=false -stage all

# one model, no list file anywhere
./sc4n hub -out one -repo LiquidAI/LFM3-1.7B -level any -defaults=false -stage all

# an arbitrary list (one repo id per line, '#' comments)
./sc4n hub -out custom -repos-file repos.txt -level any -defaults=false -stage all
```

`-rank` is one request against the Hub's own ordering and records what it ordered
by: `candidates.json` keeps the rows exactly as the Hub returned them (downloads,
likes, trending score, pipeline tag, last modified), so "why is this repo in the
set" is answerable from the campaign directory alone, and `campaign.md` states
"top N by <sort> (the Hub's 30-day download count / recent-window ranking)". The
value matters: `downloads` is a 30-day count, `?period=week` is accepted and
ignored, and `trendingScore` is the only week-scale ordering the API exposes — a
campaign that does not say which one it used is read as the wrong question. A
ranked universe with an explicit list or an extra search selector is refused
rather than silently unioned.

`-repo` is repeatable and needs no file: one model is a campaign of that model.
`-repos-file` remains for arbitrary sets. Whichever universe is used,
`verdicts.json` still records the Hub's own per-file level and every fetched file
appears in `campaign.json` with that level (or `none`) rather than being filtered
out. Nothing about the selection rule is implicit: a verdict-level campaign reviews
flagged files, an `any` campaign reviews every file it fetched, and a list or rank
campaign always records its provenance.

`campaign.md` carries a per-rule table (count and severest severity) — the triage
view you would otherwise compute from `campaign.json` — and `-baseline` makes a
re-scan differential: findings already present in a previous report are suppressed
and the number suppressed is printed in the summary line and in `campaign.md`, so
"what changed since the last round" is one flag instead of two files and a script:

```sh
./sc4n hub -out top10 -rank downloads -top 10 -level any -baseline top10/scan.json -refresh -stage all
```

`sc4n scan` never touches the network. Only `hub` does, and it writes only under
`-out`. The token is read from `-token-file`, `$HF_TOKEN`,
`$HUGGING_FACE_HUB_TOKEN` or `$HF_HOME/token`; without one the campaign runs
anonymously and reports the gated files instead of hiding them.

## Flags

`sc4n scan` (all flags are also in `sc4n scan -h`):

| flag | meaning |
|---|---|
| `-format text\|json\|sarif\|cyclonedx` | output format; `text` is the default and is the only one that colourises (only when stdout is a TTY) |
| `-out FILE` | write the report to a file instead of stdout |
| `-fail-on info\|low\|medium\|high\|critical` | severity threshold for exit code 1 (default `high`) |
| `-baseline FILE` | suppress findings already present in a previous JSON report, and say how many were suppressed |
| `-attestation FILE` | merge an attestation written by `tools/sc4nconfirm`: an artifact whose full SHA-256 appears in it gets `SC4N-MALICE-DEMONSTRATED` with the effects that were observed |
| `-j N` | worker count (default: one per CPU) |
| `-mem-budget BYTES` | total size of artifacts mapped concurrently (default 1 GiB) |
| `-max-artifact`, `-max-depth`, `-max-decompress`, `-max-ratio` | override the resource caps in `docs/architecture.md` |
| `-timeout DURATION` | bound the whole scan; a cancelled scan says so rather than presenting a partial result as complete |
| `-root DIR` | containment root for path-shaped values (ONNX external data, SavedModel assets, symlinks) |
| `-partial PATH` | repeatable: the named path is a truncated copy of a larger file, so an extent check reports `SC4N-PARTIAL-SLICE` (info) instead of a violation caused by the truncation |
| `-symlinks root\|follow` | what a symbolic link met during the walk may resolve to: `root` (default) refuses a target outside the scanned tree and records it as unreadable, naming the escape; `follow` reads it wherever it resolves |
| `-hf-cache` | scan a Hugging Face download cache instead of paths: `snapshots/` symlinks are resolved into `blobs/`, each blob is scanned once no matter how many revisions point at it, and each artifact row carries the `refs/` names it is reachable from in its `revision` field |
| `-hf-cache-dir DIR` | the cache root for `-hf-cache` (default `$HF_HOME/hub`, else `~/.cache/huggingface/hub`) |
| `-deep-stats` | enable the informational weight-statistics rules (NaN/Inf, duplicates, outliers, entropy) |
| `-timings` | include per-phase timings in the report |
| `-quiet`, `-color` | output control |
| `-stdin -name NAME` | scan a single artifact from standard input |

`sc4n hub` (all flags are also in `sc4n hub -h`):

| flag | meaning |
|---|---|
| `-out DIR` | campaign directory; every stage file and the fetched bytes live under it |
| `-stage all\|candidates\|verdicts\|fetch\|scan\|report` | run every stage, or resume at one |
| `-rank downloads\|trendingScore\|likes\|lastModified\|createdAt` | take the universe from the Hub's ranking |
| `-top N` | keep the first N rows of `-rank` (0 = the whole listing request) |
| `-repo ID` | one repo (repeatable); a single `-repo` is a campaign of that model |
| `-repos-file FILE` | an explicit repo list, one id per line |
| `-search`, `-tag`, `-author`, `-search-file` | the query universe; `-defaults=true` adds the built-in term/tag/author set |
| `-level unsafe\|suspicious\|caution\|error\|any` | which candidates are scanned; `any` scans the whole universe |
| `-baseline FILE` | suppress findings already in a previous report and report how many |
| `-full-limit`, `-flagged-limit`, `-slice`, `-repo-budget`, `-total-budget` | fetch budgets; a file above the limit is kept as a header slice and says so |
| `-jobs`, `-scan-jobs`, `-timeout` | concurrency and the request/deadline budget |
| `-refresh` | recompute a stage that already wrote its file |
| `-fail-on LEVEL` | exit 1 when a campaign finding is at or above it |
| `-json` | also print `campaign.json` to stdout |
| `-api`, `-token-file` | Hub base URL and token file (`$HF_TOKEN`, `$HUGGING_FACE_HUB_TOKEN`, `$HF_HOME/token` otherwise) |

## Grading: capability, constructed, demonstrated

A critical finding says a sink is reachable from the normal load path. It does not
say the artifact runs anything, and on a corpus of hostile repositories that
difference is the whole question. Three grades answer it:

| grade | finding | how it is decided |
|---|---|---|
| capability | the critical that fired (`SC4N-PICKLE-GLOBAL-CRITICAL`, `SC4N-CONFIG-AUTO-MAP`, `SC4N-JINJA-PY-OBJECT`, …) | from bytes: a sink is reachable |
| constructed | `SC4N-MALICE-CONSTRUCTED` | from bytes: the load path runs code the artifact supplies, and the finding names the sink and the payload. `getattr(Model, "forward")` stays capability; `posix.system("nslookup …")` does not |
| demonstrated | `SC4N-MALICE-DEMONSTRATED` | from a sandbox: these exact bytes, loaded in a container with no network, executed this program / dialled this address / read this path |

Absence of a `SC4N-MALICE-*` finding *is* the capability grade; it means the
reach is structural. The mechanism per family, and what a demonstration can and
cannot prove, are in `docs/threat-model.md` §13.

### Demonstrating: `tools/sc4nconfirm`

```sh
make confirm-image                     # once: python + torch + transformers, pinned
sc4nconfirm -artifact model.bin -out attestation.json
sc4n scan -attestation attestation.json -format json ./models
```

`sc4nconfirm` loads the artifact the way a user would (`torch.load`,
`pickle.load`, `joblib.load`, `numpy.load(allow_pickle=True)` for `.npy`/`.npz`,
a model directory's `auto_map` modules with `trust_remote_code`, or a chat
template rendered by Jinja2) in a disposable container: `--network=none`, `--read-only`, tmpfs scratch, canary credentials,
`--memory`/`--pids-limit`/`--cpus`, and one capability, `SYS_PTRACE`, because
`strace` is the only effect source a payload cannot blind from native code.

The attestation is a plain JSON file, documented field by field in
[`docs/attestation.md`](docs/attestation.md): a VM, a Kubernetes job or your own
harness can produce one, and the scanner treats it as evidence only for the full
SHA-256 it names.

Executing an artifact is this tool's job and never the scanner's: `internal/**`
and `cmd/**` contain no `os/exec`, and a boundary test fails the build if that
changes. The attestation is keyed by the full SHA-256, so a prefix digest
(`-max-hash`) never matches; a run that could not load the artifact because a
framework is missing records `missingModules` instead of a verdict, so "we could
not load it" never reads as "it did nothing".

## Baselines

A finding you have reviewed and accepted should not have to be triaged again on
every run. `-baseline` takes a previous JSON report and suppresses the findings it
already contains:

```sh
./sc4n scan -format json -out baseline.json ./models
# after reviewing baseline.json:
./sc4n scan -baseline baseline.json -fail-on high ./models
```

Suppression is by `(rule, artifact, hash of the evidence window)` — the byte
offset is deliberately *not* part of the key, because inserting an unrelated byte
shifts every later offset and a baseline that un-suppresses on such an edit is
worse than none. A *redacted* finding (a secret value, whose evidence is a masking
string rather than the value) is the exception: its offset is the only identity it
has, so it is part of the key. Without that, two secrets baselined in one file
suppressed a third secret added later. The summary line always states how many
findings were suppressed, so a baseline can never silently turn a new finding into
a clean run. `-max-findings` is applied *after* suppression for the same reason:
baselined findings do not consume cap slots and cannot evict a new one. The cap
itself keeps the *most severe* findings, breaking ties by the report's own order,
so a flood of low-severity findings cannot push a critical one out of the list —
`exit 0` means nothing at or above `-fail-on` was dropped, not merely that nothing
at or above it happened to arrive before the cap filled.

## Digests

The scan computes a sha256 per artifact as an identity (for the report and for
`-hf-cache` de-duplication). Because sha256 is CPU-bound (measured 0.35 GB/s on
the reference host, which has AVX2 but no SHA-NI), the digest is capped at
`MaxHashBytes` (256 MiB) by default and the report states the scope:
`sha256Scope` is `full` or `prefix:<bytes>`. A row whose digest could not be read
says so in `subFormat` rather than carrying an empty digest and no reason. `sc4n
hash <path>` computes a full sha256 (and sha1) when a real provenance digest is
what you need.

## Exit codes

| code | meaning |
|---|---|
| 0 | clean: no finding at or above `-fail-on` |
| 1 | findings at or above `-fail-on` (default `high`) |
| 2 | usage error (including an unreadable or malformed `-attestation` file) |
| 3 | a path you named could not be opened, or the scan was cancelled by `-timeout` — the requested scope was not fully scanned |

Exit 3 is deliberately distinct from 1: findings are about the artifact, while 3
is about the scan, and a CI job that treats them the same cannot tell "your model
is malicious" from "the mount is missing". A cancelled run also carries
`summary.cancelled` in the JSON report and `sc4n:cancelled` in the CycloneDX BOM,
because a consumer that reads only the report must not see a partial scan as a
clean one.

## CI usage

```yaml
name: scan-models
on: [push, pull_request]
jobs:
  sc4n:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: {go-version: '1.27'}
      - run: go build -o sc4n ./cmd/sc4n
      - run: ./sc4n scan -format sarif -out sc4n.sarif -fail-on high .
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: {sarif_file: sc4n.sarif}
```

GitHub code scanning caps an upload at 25 000 results and a 10 MB gzipped SARIF
file. sc4n does not sample: if a run exceeds the cap, tighten with
`-max-findings` and triage, or split the scan by directory.

### Scanning an untrusted repository in the container

The image is the recommended way to scan bytes you do not trust. `--network=none`
is safe for `scan` (only `hub` dials the Hub and it is not used here),
`--read-only` stops a write to the filesystem, and the process runs as an
unprivileged user, so a bug in a parser reaches nothing the mounted scan root and
the bounded `/tmp` do not already contain. The `--user` is what lets a bind mount
whose files are not world-readable be read:

```sh
VERSION=v1.0.1 make docker
docker run --rm --network=none --read-only --tmpfs /tmp:rw,size=1g \
  --user "$(id -u):$(id -g)" \
  -v "$PWD:/scan:ro" -v "$PWD/out:/out" \
  sc4n:$(VERSION) scan -format sarif -out /out/sc4n.sarif -fail-on high /scan
```

`sc4n hub` needs the network and a writable `-out` directory, so it is run on the
host, not with these flags.

## What sc4n does not do

- **No dynamic analysis in the scanner.** Anything that only manifests at load
  time is inferred from structure, not observed. Observation exists, but it is a
  separate tool: `tools/sc4nconfirm` loads the artifact in a disposable container
  and writes an attestation that `sc4n scan -attestation` merges. The scanner
  itself still runs nothing.
- **No weight-level backdoor proof.** Neural Cleanse, ABS, STRIP, spectral
  signatures and activation clustering are documented in
  `docs/threat-model.md` as out-of-band techniques with their compute cost and
  false-positive caveats; they are never a gate here. sc4n ships only structural
  and statistical anomaly checks (entropy, NaN/Inf, duplicate rows, undeclared or
  trailing data) as informational findings behind `-deep-stats`.
- **No rewriting.** sc4n reports; it does not sanitise.
- **No xz/lz4/zstd/7z/rar decompression.** A payload inside one of those is
  reported as unscanned (`SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION`) rather than
  guessed at, because sc4n links nothing but the standard library and
  `google.golang.org/protobuf`.
- **No signature verification.** Provenance (`model_signing`, `cosign verify`) is
  an external step; `docs/threat-model.md` explains how to combine it.
- **No execution, and nothing it reads is executed.** sc4n opens artifacts,
  parses them and reports; it spawns no process, and the scan path imports no
  network package (only `sc4n hub` dials). Device nodes and FIFOs met during a walk
  are recorded as unreadable instead of opened, decompression is bounded by the
  caps in `docs/architecture.md`, and with the default `-symlinks root` a link
  whose target resolves outside the scanned tree is not read at all.
- **The container is the boundary for what those checks cannot see.** A hardlink
  is a file, not a path, so a scan can read one that lives outside the tree; run
  untrusted repositories in the image (below), where `--network=none
  --read-only` and a non-root user bound what the process can reach at all.

## Documentation

- [`docs/quickstart.md`](docs/quickstart.md) — install, first scan, triage, gate.
- [`docs/triage.md`](docs/triage.md) — what to do with the finding in front of you:
  severity × confidence, then one section per finding family.
- [`docs/rules.md`](docs/rules.md) — the full rule catalogue, generated from the
  registry, each rule linked to its triage section.
- [`docs/threat-model.md`](docs/threat-model.md) — threat class → real-world
  evidence → rule → mitigation → residual risk. This is the review that justifies
  every rule.
- [`docs/architecture.md`](docs/architecture.md) — pipeline, limits, performance
  budget, how to add a format or a rule.
- [`docs/measurements.md`](docs/measurements.md) — what the scanner actually did on
  real corpora: findings, false-positive differential, recall, demonstration
  coverage, and the limits of each number.
- [`docs/attestation.md`](docs/attestation.md) — the demonstration format, and how
  to produce one from a VM, a pod or your own harness instead of Docker.
- [`docs/github-code-scanning.md`](docs/github-code-scanning.md) — the SARIF upload
  workflow, its traps, and the de-duplication contract.
- [`docs/release.md`](docs/release.md) — how a release is built, verified and
  published, and what it does not claim.
- [`SECURITY.md`](SECURITY.md) — how to report a defect in the scanner, what is
  in scope, and what is a documented limitation rather than a vulnerability.

## Recommended posture

Treat every artifact sc4n flags at `critical` as hostile until proven otherwise,
and load it only inside a sandbox with no network, no credentials mounted and no
write access to the host: the entire pickle family's normal load path *is* code
execution, so a critical finding is not "a vulnerability in the model" but "the
model's loader will run this".

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
