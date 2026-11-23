# Triaging a finding

A finding is a claim about bytes, not a verdict about intent. This page is the
decision procedure for one finding: what it means, what to check next, and what
to record when you accept it. The rule's own rationale is in
[`docs/rules.md`](rules.md); the threat it belongs to, with real-world evidence,
is in [`docs/threat-model.md`](threat-model.md).

## The decision in one page

Two fields of the finding decide most of the work: **severity** is the impact if
the finding is real, **confidence** is how sure the detector is that it is.

| severity | confidence | what to do |
|---|---|---|
| critical | any | Treat the artifact as hostile until you have read the evidence. Do not load it outside a sandbox. A critical in the pickle family is not "a vulnerability in the model": the model's loader *is* the code |
| high | high | Almost always real. Check the evidence window, then decide between quarantine and a documented acceptance |
| high | medium | Read the evidence: the reach may be structural (`getattr(Model, "forward")`, an allowlisted callable) rather than code the artifact supplies. `SC4N-MALICE-CONSTRUCTED` is the distinction, and if it is absent the reach is structural |
| medium | any | Usually a coverage or convention problem: an unscanned payload, a header that disagrees with its extension. Decide whether the bytes are reachable from *your* load path before spending time |
| low, info | any | Triage once, baseline it, and stop reading it. `SC4N-LIMIT-*` at `info` means a cap was hit, not that the artifact is malicious |

Three grades answer "will it actually run", and only the third is observation:

| grade | finding | decided by |
|---|---|---|
| capability | the critical itself | bytes: a sink is reachable from the normal load path |
| constructed | `SC4N-MALICE-CONSTRUCTED` | bytes: the load path runs code *the artifact supplies*, and the finding names the sink and the payload |
| demonstrated | `SC4N-MALICE-DEMONSTRATED` | a sandbox: these bytes, loaded for real, executed this program / dialled this address |

Absence of a `SC4N-MALICE-*` finding is the capability grade. See
[§ Grading](../README.md#grading-capability-constructed-demonstrated).

## The loop

```sh
sc4n scan -format json -out scan.json ./models      # 1. see everything
sc4n scan -baseline scan.json -fail-on high ./models  # 2. only what changed
sc4n scan -format text ./models/model.bin            # 3. read one artifact's findings
sc4n rules | grep -A20 SC4N-RULE-ID                  # 4. read the rule's rationale
```

Step 2 is what makes the scanner usable on a real estate: a finding you have
reviewed is suppressed by `(rule, artifact, evidence)` — deliberately not by
offset, so inserting an unrelated byte does not bring it back — and the summary
line always states how many were suppressed, so a baseline cannot turn a new
finding into a clean run.

Step 5, when you want to know whether a critical is real, is the harness:

```sh
make confirm-image
sc4nconfirm -artifact ./models/model.bin -out attestation.json
sc4n scan -attestation attestation.json -format json ./models | grep DEMONSTRATED
```

## The load path runs code

<a id="load-path-code"></a>

**What it means.** The format's *normal* load call (`torch.load`, `pickle.load`,
`joblib.load`, `numpy.load(allow_pickle=True)`, `trust_remote_code`) executes
something the artifact supplies: a global, a `REDUCE` with a callable argument, a
`__reduce__` on a class the stream defines, an operator lambda, a `marshal` blob.

**What to check.** The evidence window names the sink and its argument. Compare
what the argument is: `posix.system("nslookup x")`, `eval(source)` and
`getattr(x, "__globals__")` are code the artifact supplies; `getattr(Detect,
"forward")` and an allowlisted callable are the ordinary weights-only shape. If
the finding is `SC4N-MALICE-CONSTRUCTED`, that comparison has already been made.
`SC4N-JOBLIB-UNSCANNED-PAYLOAD` is different: the payload was not read at all
(xz/lzma/lz4), so the grade is "unknown", not "clean".

**What to do.** Quarantine, then demonstrate (or accept as hostile without
demonstrating). Re-hosting is not a fix: the bytes are the artifact.

## Code the repository ships

<a id="shipped-code"></a>

**What it means.** A `.py` file, notebook, `setup.py`, `.pth`, chat template or
`config.json` `auto_map` that runs on import, on load, or on model instantiation.
Hugging Face's `trust_remote_code=True` is the delivery mechanism: the config
names a module, the module runs.

**What to check.** Whether the code is imported at load (`import`, a module-level
`socket.getaddrinfo` inside `try`, a class body's decorator) versus only defined
(a function nobody calls). `SC4N-CONFIG-AUTO-MAP` with a `local` class means the
module must be beside the config; with a `remote` class the code is fetched from
another repository at load time, and the finding names it.

**What to do.** Read the named function. A model that needs custom code needs a
review of that file at that revision; pin the revision, not the repository.

## Containers, members and what stopped the walk

<a id="containers"></a>

**What it means.** An archive, its members, or the walk's own limits: a member
that is executable, a polyglot whose header disagrees with its extension, a
traversal path, a truncated archive whose local headers were recovered, a member
inside a compression sc4n does not decode (7z, rar, lz4, xz, zstd) — the last is
a coverage gap stated as a finding, not a clean result.

**What to check.** Whether the payload is reachable: a `.pt` whose members are
`<name>/data.pkl` is the torch save format; a `.zip` with an executable member is
not something a model loader opens. `SC4N-ARCHIVE-MEMBER-HIDDEN` means a member
the central directory does not list, which no normal extractor will show you.
`SC4N-ARCHIVE-DIRECTORY-AMBIGUOUS` means two central directories validate at
different offsets, so the member list sc4n scanned is not provably the one a
loader will read; treat the artifact as unscanned until the prefix/base question
is resolved.

**What to do.** For unscanned compression: extract it yourself in a sandbox and
scan the payload, or treat the artifact as unscanned. For a member: name it in the
ticket; the finding's `artifact` field is `file.zip:member/path`.

## Model formats and graph semantics

<a id="model-graphs"></a>

**What it means.** Graph and header structure: an ONNX external-data path that
escapes the model directory, an operator domain that is not an official opset, a
`FunctionProto` body, a Keras lambda layer, a SavedModel with a `pyfunc` or file-
reading op, a GGUF chat template, a safetensors length that disagrees with the
file.

**What to check.** Whether the loader acts on it. External data is read at load,
so a traversal path is a file read; a custom operator domain is only a problem if
an implementation is shipped beside it; a graph with no `pyfunc` and no file IO
does not execute on load, whatever its ops are.

**What to do.** For a path: confirm the escape against the load root. For a
custom domain/operator: find the implementation, or treat the model as
unloadable. For a header inconsistency: the file is malformed; a loader will
either reject it or read past the declared extent.

## Content, text and persuasion

<a id="content-persuasion"></a>

**What it means.** Text aimed at a reader or an agent: instructions in a model
card, invisible characters, a decodable string placed next to a decoder, a
tokenizer file carrying credentials, an image with a payload in a comment or a
trailing segment.

**What to check.** Who reads it. A card is documentation; a chat template is
*rendered* and its expressions are evaluated by Jinja; a tokenizer JSON is parsed
as data, never executed. A redacted secret finding is never baseline-suppressed:
its identity is not reproducible enough to hide a later secret behind an old
one.

**What to do.** Rotation, if a secret value is named (`SC4N-STRING-SECRET-VALUE`
masks the value in the report — the finding is the rotation trigger, not the
value). Otherwise treat it as an input-trust problem for whatever agent or
pipeline reads the text, and keep the artifact out of that pipeline until it is
reviewed.

## Repository-level supply chain

<a id="repo-supply-chain"></a>

**What it means.** How the repository is assembled: a `.gitattributes` filter
that runs a process on checkout (`filter=`, `textconv`), a symlink that escapes
the tree, a submodule or LFS pointer, a cache blob a ref points at that is
missing or mismatched.

**What to check.** Whether your fetch path honours it. `git clone` honours
`.gitattributes` filters *only* when the filter is already configured, so a
filter definition is a threat to the developer who has it in `~/.gitconfig`, not
to a plain clone. A symlink escape is refused by default (`-symlinks root`) and
named in the report. `SC4N-REPO-TRUNCATED` means a repository file was analysed
only on its prefix; the tail was not read, so treat the file as unscanned.
`SC4N-REPO-BACKEND-PATH` means repository code is placed ahead of the PEP 517
backend. `SC4N-HFCACHE-NOT-SCANNED` means a cache entry was omitted, so the
cache-wide coverage claim is false; `SC4N-GITATTRIBUTES-DIFF-NAME` records a
built-in diff driver whose local config may still name a `textconv`.

**What to do.** Review the repository before cloning it into a trusted place;
clone with a scratch `HOME` if you cannot.

## Coverage limits and dispatch

<a id="coverage-limits"></a>

**What it means.** A cap or a routing decision: `SC4N-LIMIT-*` means a bound in
`docs/architecture.md` was hit and the named bytes were not analysed;
`SC4N-FORMAT-EXTENSION-MISMATCH` means the name disagreed with the bytes (the
bytes win, and the disagreement is itself reported); `SC4N-PARTIAL-SLICE` means
you told the scan the file is a truncated copy, so the extent check is expected to
fail; `SC4N-INTERNAL-PANIC` means a parser recovered from a panic on crafted input
and the artifact was not fully analysed.

**What to check.** Which bytes were skipped, which the finding names. `info`
severity here is a statement of coverage, not of risk.

**What to do.** Raise the cap for that artifact (`-max-artifact`,
`-max-depth`, `-max-decompress`), rescan it alone, and keep the result. Never
read `info` as "clean": a limit finding means the answer is "not scanned here".

## Weight statistics

<a id="weights-statistics"></a>

**What it means.** `-deep-stats` only: NaN/Inf values, duplicate rows, outliers,
an entropy that is implausible for the declared dtype. These are anomaly
signals, not backdoor proofs; a backdoor that survives Neural Cleanse-class
detection is out of scope by design (see `docs/threat-model.md`).

**What to check.** Whether the shape is plausible for the declared dtype and
provenance, and whether a known-good baseline of the same model shows it too.

**What to do.** Compare against the upstream checkpoint. A difference in the
weights of a model you did not produce is a provenance question, not a scanner
question.
