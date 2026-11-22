# GitHub code scanning

sc4n emits SARIF 2.1.0, validated against the official schema
(`make sarif-check`) and pinned to what code scanning actually reads: every
result's `ruleId` is described in `tool.driver.rules`, levels map to
error/warning/note, `security-severity` carries the band GitHub sorts by, and each
result has a `primaryLocationLineHash` fingerprint so a re-run de-duplicates
instead of opening every alert again.

## A workflow that works

This runs the released image, so the job needs no Go toolchain:

```yaml
name: sc4n
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required by upload-sarif

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          lfs: true                     # model weights are often LFS pointers

      - name: scan
        run: |
          # Capture the exit code instead of failing here: a failed step skips
          # later ones, and the findings must still reach the upload. 0 clean,
          # 1 findings at or above -fail-on, 3 an unscanned scope.
          set +e
          docker run --rm --network=none --read-only --tmpfs /tmp:rw,size=1g \
            --user "$(id -u):$(id -g)" \
            -v "$PWD:/work" \
            ghcr.io/fr0g-66723067-io/sc4n:v1.0.1 \
            scan -format sarif -out /work/sc4n.sarif -fail-on high /work
          echo "$?" > /tmp/sc4n-status

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: sc4n.sarif
          category: sc4n

      - name: gate
        run: |
          status=$(cat /tmp/sc4n-status)
          if [ "$status" -ne 0 ]; then
            echo "sc4n exited $status: findings at or above high, or a scope it could not scan"
            exit 1
          fi
```

Two details are easy to get wrong, and both are why the example is shaped this
way:

- **`continue-on-error: true` on the scan.** `sc4n scan -fail-on high` exits 1 when
  it finds something. A step that exits 1 fails the job, and a failed job skips
  later steps unless they carry `if: always()`. Splitting scan → upload → gate
  keeps the findings visible *and* the run red.
- **`security-events: write`.** Without it the upload fails with a permissions
  error that reads like a SARIF problem.

## What a developer sees

| sc4n severity | SARIF `level` | `security-severity` | GitHub band |
|---|---|---|---|
| critical | error | 9.5 | Critical |
| high | error | 8.0 | High |
| medium | warning | 5.0 | Medium |
| low | warning | 3.0 | Low |
| info | note | 0.5 | no band |

A finding's message is the rule title, the rule ID, the member path when the
finding is inside a container (`model.zip:member/path`), and the evidence window.
The rule's help text and references are in the rule descriptor, so the alert page
explains the finding without a second lookup.

## De-duplication across runs

Code scanning keys an alert on `(rule, path, primaryLocationLineHash)`. sc4n's
fingerprint deliberately excludes the byte offset — inserting an unrelated byte
would otherwise reopen every alert in the file — and appends the 1-based
occurrence count of that fingerprint inside the artifact, so two findings with
identical evidence in one file stay two alerts instead of collapsing into one.
The same key is what `-baseline` uses, so a finding suppressed locally is also
stable remotely.

## Limits

- One upload is capped at **25 000 results** and a **10 MB gzipped SARIF** file.
  sc4n does not sample: if a run exceeds the cap, tighten with `-max-findings`,
  scan subtrees separately with different `category` values, or gate on
  `-fail-on critical` and upload only the critical subset.
- Code scanning is free for public repositories; private repositories need GitHub
  Advanced Security.
- `upload-sarif` requires the result locations to resolve inside the checked-out
  repository. Scanning a directory outside `$GITHUB_WORKSPACE` (a sibling model
  cache, for example) produces `http://`-style URIs that GitHub discards: copy or
  mount the artifacts under the workspace, or scan a mirror repository.

## Without code scanning

The same file feeds any SARIF consumer (`jq`, an internal dashboard, `sarif-tools`):

```sh
sc4n scan -format sarif -out sc4n.sarif -fail-on critical ./models
jq '.runs[0].results[] | {rule: .ruleId, level, msg: .message.text}' sc4n.sarif
```

Because the document is deterministic and its rule descriptors come from the
registry, two scanners at the same version produce byte-identical SARIF for the
same bytes: a diff of two reports is a diff of findings, not of formatting.
