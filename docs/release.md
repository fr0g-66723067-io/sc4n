# Cutting a release

`v1.0.0` is the first tag. The process is three commands and one push, and it is
reproducible by anyone:

```sh
git tag -a v1.0.0 -m "sc4n v1.0.0"
make release                      # builds, verifies, builds the image, verifies it
git push origin v1.0.0            # the tag, not the branch — CI does the rest
```

`make release` is `release-binaries` + `release-image` + `verify-release`:

| target | what it produces |
|---|---|
| `make release-binaries` | `dist/sc4n_<version>_<os>_<arch>` for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, and `dist/SHA256SUMS` over all of them |
| `make release-image` | `sc4n:<version>` from `Dockerfile` (distroless, non-root, OCI labels) |
| `make verify-release` | runs `tools/release/verify.sh` against both |

Verification is not a formality; each check exists because it has caught something
or would have:

- `sha256sum -c SHA256SUMS` — an asset that does not verify teaches users to skip
  the check;
- `file` on every cross-built binary — a mistyped `GOARCH` builds a binary that
  runs on nothing, and `go build` exits 0;
- the native binary's `version` — must equal the tag, because every report carries
  it and a stale binary is invisible until someone compares a SARIF file;
- the benign fixture tree scans clean at `-fail-on low`, and the critical fixture
  exits 1 — the release gate applied to the *artifact*, not to the tree it was
  built from;
- the same two checks through the image, plus its `version`.

A run looks like this:

```text
== checksums
   5 artifact(s) verified
== architectures
   sc4n_v1.0.0_darwin_amd64: x86_64, format ok
   sc4n_v1.0.0_darwin_arm64: arm64, format ok
   sc4n_v1.0.0_linux_amd64: x86-64, format ok
   sc4n_v1.0.0_linux_arm64: aarch64, format ok
   sc4n_v1.0.0_windows_amd64.exe: x86-64, format ok
== native binary
   sc4n v1.0.0
   benign tree: clean
   critical fixture: exits 1
== image sc4n:v1.0.0
   sc4n v1.0.0
   benign tree: clean
   critical fixture: exits 1
verify-release: ok
```

## What the tag triggers

`.github/workflows/release.yml` runs the full test gate at the tag, then:

- **binaries** — `make release-binaries`, the same verification, then
  `gh release create` with the five binaries and `SHA256SUMS` as assets;
- **image** — builds `ghcr.io/fr0g-66723067-io/sc4n:<tag>`, verifies it (version,
  benign tree clean, critical fixture exits 1), pushes it, and moves `:latest`
  unless the tag is a pre-release (`v1.1.0-rc1` does not move `:latest`).

Nothing is published from a branch. A tag that fails the test gate publishes
nothing, because both publishing jobs `needs: test`.

`v1.0.0` is published: the five binaries and `SHA256SUMS` are assets on the
release, and the image is `ghcr.io/fr0g-66723067-io/sc4n:v1.0.0` and `:latest`.
Both are private with the repository, so a consumer authenticates first:
`gh release download` for the assets, and `docker login ghcr.io` with a token that
has `read:packages` (the default `gh` token does not; `gh auth refresh -s
read:packages` adds it). `make release` produces exactly
the same artifacts from the tag.

## Before tagging

```sh
make test                         # vet + test + test -race
make fixtures && git diff --exit-code testdata/fixtures
make rules-doc && git diff --exit-code docs/rules.md
make sarif-check                  # skipped loudly without python3 + jsonschema
VERSION=v1.0.0 make release       # the same artifacts CI will build
```

`make release` with `VERSION` overridden is how to prove a tag will work before
pushing it: the tree is dirty at that point, so the version string is yours to
give, and the artifacts are byte-comparable with what CI produces apart from the
embedded version.

## What a release does not claim

- **No signature and no provenance attestation.** The assets carry `SHA256SUMS`
  and nothing else; there is no signing key in this project and no
  `actions/attest-build-provenance` step. Verify the checksum against the release
  page and, if you need provenance, build from the tag yourself — the build is
  `go build` with two flags and no code generation.
- **No semantic-versioning promise beyond the report schema.** The JSON report
  carries `schemaVersion` and the exit codes are a contract
  ([README](../README.md#exit-codes)); rule IDs are stable once published, and a
  rule that changes meaning is renamed rather than reused. `sc4n rules` is the
  authority on what exists.
- **The fixture corpus in the release is the same one in the tree**, so a released
  binary's own gate (`benign clean, critical exits 1`) is reproducible with
  `make release` from the same tag.
