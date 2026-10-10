# sc4n

Static scanner for ML model artifacts and the code around them.

sc4n answers one question for a machine-learning artifact it is pointed at: *what
in here executes, reads files, or talks to the network when this thing is loaded?*
It answers it by decoding bytes — pickle opcodes, archive directories, format
headers, Python source, chat templates, cards — and never by running anything.

- **No execution, ever.** The artifact is not imported, not unpickled, not
  extracted to disk, not passed to an external parser or decompressor. The only
  path sc4n writes is `-out`.
- **Content-based dispatch.** The format comes from the bytes, not the file name.
  A `.pt` that is a 7z archive, a `.bin` that is a pickle and a `.safetensors`
  that is a zip are all scanned as what they are, and the disagreement is itself a
  finding (`SC4N-FORMAT-EXTENSION-MISMATCH`).
- **Report-only.** sc4n never rewrites, repairs or quarantines an artifact. It
  emits findings, plus an exit code a CI job can gate on.
- **Bounded and deterministic.** One worker per artifact, a size-weighted memory
  budget, memory-mapped reads, and sorted output: two runs over the same bytes
  produce byte-identical JSON.

## Coverage

| family | formats |
|---|---|
| pickle | bare pickle, joblib (all compression methods), torch zip, torch legacy, TorchScript, `.pt2` export archives |
| numeric | safetensors, `.npy`/`.npz` (including object dtype), msgpack (Flax/JAX/MLX), XGBoost UBJSON |
| model | GGUF, ONNX, TF SavedModel/GraphDef and checkpoints, Keras `.keras`/`.h5`, TFLite, CoreML `.mlmodel`/`.mlpackage`, ExecuTorch `.pte` |
| containers | zip (including zip64, prefixed archives and large stored members), tar, gzip, zlib, bzip2 (xz/lz4/zstd/7z/rar are recognised and reported, never decompressed — see `sc4n formats`) |
| code and metadata | Python source, notebooks, Jinja chat templates, model/dataset cards, `config.json`/`tokenizer_config.json`/`adapter_config.json`, `setup.py`, `pyproject.toml`, `.pth`, `*.start`, GitHub workflows, wheels inside a repo |

`sc4n formats` prints the same table with the **analysis depth** of every format,
including the ones that are deliberately recognised but not parsed. Every rule
states its severity, confidence, CWE and class: `sc4n rules`.

## Quickstart

```sh
go build -o sc4n ./cmd/sc4n

# a downloaded model directory
./sc4n scan ./models/bert-base-uncased

# one artifact, machine-readable
./sc4n scan -format json ./model.safetensors

# a repository, gated, with SARIF for GitHub code scanning
./sc4n scan -format sarif -out sc4n.sarif -fail-on high .
```

## Flags

`sc4n scan` (all flags are also in `sc4n scan -h`):

| flag | meaning |
|---|---|
| `-format text\|json\|sarif\|cyclonedx` | output format; `text` is the default and is the only one that colourises (only when stdout is a TTY) |
| `-out FILE` | write the report to a file instead of stdout |
| `-fail-on info\|low\|medium\|high\|critical` | severity threshold for exit code 1 (default `high`) |
| `-baseline FILE` | suppress findings already present in a previous JSON report, and say how many were suppressed |
| `-j N` | worker count (default: one per CPU) |
| `-mem-budget BYTES` | total size of artifacts mapped concurrently (default 1 GiB) |
| `-max-artifact`, `-max-depth`, `-max-decompress`, `-max-ratio` | override the resource caps in `docs/architecture.md` |
| `-timeout DURATION` | bound the whole scan; a cancelled scan says so rather than presenting a partial result as complete |
| `-root DIR` | containment root for path-shaped values (ONNX external data, SavedModel assets, symlinks) |
| `-hf-cache [DIR]` | scan a Hugging Face download cache, resolving `snapshots/` symlinks into `blobs/` and scanning each blob once |
| `-deep-stats` | enable the informational weight-statistics rules (NaN/Inf, duplicates, outliers, entropy) |
| `-timings` | include per-phase timings in the report |
| `-quiet`, `-color` | output control |
| `-stdin -name NAME` | scan a single artifact from standard input |

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
worse than none. The summary line always states how many findings were
suppressed, so a baseline can never silently turn a new finding into a clean run.

## Digests

The scan computes a sha256 per artifact as an identity (for the report and for
`-hf-cache` de-duplication). Because sha256 is CPU-bound (measured 0.35 GB/s on
the reference host, which has AVX2 but no SHA-NI), the digest is capped at
`MaxHashBytes` (256 MiB) by default and the report states the scope:
`sha256Scope` is `full` or `prefix:<bytes>`. `sc4n hash <path>` computes a full
sha256 (and sha1) when a real provenance digest is what you need.

## Exit codes

| code | meaning |
|---|---|
| 0 | clean: no finding at or above `-fail-on` |
| 1 | findings at or above `-fail-on` (default `high`) |
| 2 | usage error |
| 3 | a path you named could not be opened — the requested scope was not fully scanned |

Exit 3 is deliberately distinct from 1: findings are about the artifact, while 3
is about the scan, and a CI job that treats them the same cannot tell "your model
is malicious" from "the mount is missing".

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

## What sc4n does not do

- **No dynamic analysis.** Anything that only manifests at load time is inferred
  from structure, not observed.
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

## Documentation

- `docs/threat-model.md` — threat class → real-world evidence → rule → mitigation
  → residual risk. This is the review that justifies every rule.
- `docs/architecture.md` — pipeline, limits, performance budget, how to add a
  format or a rule.

## Recommended posture

Treat every artifact sc4n flags at `critical` as hostile until proven otherwise,
and load it only inside a sandbox with no network, no credentials mounted and no
write access to the host: the entire pickle family's normal load path *is* code
execution, so a critical finding is not "a vulnerability in the model" but "the
model's loader will run this".

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
