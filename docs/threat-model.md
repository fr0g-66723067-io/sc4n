# sc4n threat model

This is the review that justifies every rule in the tree. It is written for two
readers: the engineer deciding whether sc4n's verdict on an artifact can be
trusted, and the next maintainer adding a detector. Every row states the
mechanism, the real-world evidence that the mechanism is used, the rule IDs that
detect it, the mitigation a consumer should apply, and — deliberately — the
residual risk, including the cases where the honest mitigation is "do not load
this".

## 1. What sc4n is, and what it is not

sc4n is a **static, read-only** scanner for ML artifacts and the code and
metadata around them. It parses container and format bytes, decodes structure,
reconstructs the data a loader would act on (pickle opcodes, config JSON, chat
templates, tokenizer patterns), and grades findings with evidence. It never
executes the artifact, never extracts an archive member to a visible path, never
runs a system decompressor, and never rewrites what it scans. The only path it
writes permanently is the report named by `-out`; a member too large to hold in
memory is materialised in an unlinked temporary file under `TMPDIR` and mapped
(`source.Spill`), so it is never visible to another process and never left behind
by a crash.

Two consequences follow, and both are load-bearing:

- **A clean report is not a safety proof.** sc4n sees bytes and structure; a
  loader's behaviour depends on the loader's version, its configuration, the
  environment, and the model's *weights*. Where a class of attack cannot be
  decided statically, this document says so and the tool stays quiet rather than
  guessing (§7).
- **A finding is evidence, not a verdict.** Every finding carries a severity, a
  confidence, a CWE and the bytes that triggered it. Severity is calibrated to
  the ecosystem's load path (critical = code execution or credential
  exfiltration reachable from the normal load path; high = exploitable file
  access or an unvalidated code-loading surface; medium = suspicious but
  unproven; low/info = structural anomalies and statistics). Confidence is
  independent: a critical rule can fire at low confidence (for example
  `SC4N-PICKLE-REQUIRES-UNSAFE-LOADER`, which is a statement about protocol
  shape, not about intent).

### Threat model of the scanner itself

sc4n is routinely pointed at hostile input, so its own attack surface is part of
the model:

| Surface | Property that holds |
|---|---|
| Parsers | Bounded by `limits.Limits`; no allocation from an attacker-controlled length before it is validated against the bytes remaining; no panics (a parser panic is caught and reported as `SC4N-INTERNAL-PANIC` rather than killing the scan) |
| Memory | One mapping per file, reused by every parser; large members are zero-copy sections or spilled to an unlinked temporary file (`source.Section`/`source.Spill`); anonymous RSS stays flat on multi-gigabyte artifacts |
| Recursion | `MaxDepth` with a per-artifact budget; containers recurse, they do not loop |
| Disk | Nothing is written permanently except `-out`; a spilled member is materialised in an unlinked temporary file under `TMPDIR`, so it is never visible to another process and never left behind by a crash |
| Execution | No `os/exec` in the tree; unsupported compression is *reported*, never delegated to a system tool |
| Paths | Every path-shaped value that is resolved goes through `os.Root` containment; escape is `SC4N-PATH-ESCAPE`, never a silent read |
| Output | The report is escaped, not echoed: every artifact path, evidence string and parser error goes through the same control-byte filter (ESC and other C0 bytes become a visible placeholder, tab and newline become spaces) and evidence is truncated at a rune boundary. JSON escapes them and SARIF percent-encodes them, so a crafted file name cannot inject terminal escapes into a CI log or split the text report's columns |

## 2. Taxonomy

| # | Threat class | Evidence | Detectors | Mitigation | Residual risk |
|---|---|---|---|---|---|
| 3 | Deserialization code execution (pickle family) | CVE-2026-23001, CVE-2026-31239, arXiv 2508.19774, arXiv 2607.17503, arXiv 2508.15987 | `SC4N-PICKLE-*` (24 rules) | Load only with `weights_only=True` (torch ≥ 2.6 default) or a safetensors artifact; never `pickle.load` untrusted data | Weights-only is not a sandbox: it constrains the *opcode* surface, not the model's behaviour once loaded |
| 4 | Loader- and config-driven execution | VU#456290, CVE-2026-4372, VU#253266 / CVE-2024-3660, CVE-2025-1550, CVE-2026-12481/12484 | `SC4N-CONFIG-*`, `SC4N-LOADER-*`, `SC4N-KERAS-*` | `trust_remote_code=False`, `safe_mode=True` with a current Keras, pin `revision=` | The allowlist is a moving target; a new layer class is unknown until the list is updated |
| 5 | Container and format-confusion smuggling | Feb-2025 nullifAI campaign, modelscan issue #354, CVE-2022-25882, CVE-2024-27318 | `SC4N-ARCHIVE-*`, `SC4N-POLYGLOT-*`, `SC4N-FORMAT-*`, `SC4N-TORCH-*`, `SC4N-ONNX-EXTERNAL-*`, `SC4N-HDF5-EXTERNAL-LINK` | Verify provenance out of band; never trust the extension | A container the scanner cannot decompress (xz/zstd/lz4/7z) is reported, not read: the payload inside it is not analysed |
| 6 | Template, op and layer code paths | CVE-2026-5760 / VU#915947, arXiv 2602.04653 | `SC4N-JINJA-*`, `SC4N-TEMPLATE-INJECTION`, `SC4N-TF-PYFUNC`, `SC4N-TF-FILE-IO`, `SC4N-COREML-CUSTOM-LAYER`, `SC4N-TFLITE-CUSTOM-OP`, `SC4N-PTE-*` | Run templates in a sandboxed renderer with no globals; do not load a model that names a host-supplied class or plugin | Template engines differ; a layer/op name is reported as a *surface*, not as proof that a plugin is present |
| 7 | Prompt injection and exfiltration via metadata | OWASP LLM01 | `SC4N-CARD-*`, `SC4N-METADATA-*`, `SC4N-UNICODE-ANOMALY` | Treat all card text as untrusted input; datamarking/spotlighting | A detector for instruction-shaped text cannot be complete; novel phrasing is missed by design |
| 8 | Resource exhaustion | CVE-2025-5197, CVE-2025-3263, CVE-2025-2099, CVE-2024-12720 | `SC4N-LIMIT-*`, `SC4N-TOKENIZER-REDOS` | Serve untrusted models behind a resource-capped process | Caps bound the *scanner*; they do not bound the consumer's loader |
| 9 | Weight-level backdoors | Neural Cleanse, ABS, STRIP, spectral signatures, MIST, Z-PEFT | `SC4N-WEIGHTS-*` (info only, behind `-deep-stats`) | Out-of-band dynamic analysis; provenance | **Static scanning cannot prove or disprove a backdoor.** See §6 |
| 10 | Provenance and supply chain | sigstore `model_signing`, `cosign verify`, CycloneDX ML-BOM | CycloneDX output, `SC4N-GITATTRIBUTES-*`, `SC4N-HFCACHE-*` | Verify signatures before download; pin revisions | The Hub exposes no native signature badge; absence of a signature is not evidence of malice |
| 11 | Scanner bypass (why parsers look like this) | picklescan CVE-2025-10157, fickling CVE-2025-67747 / CVE-2026-14534, modelscan issue #354 | the parser contract itself | Keep the scanner current; treat "no findings" as "nothing matched", not "safe" | Every bypass in the history is a case where a scanner returned before the payload was reached. See §5 |

## 3. Deserialization code execution

### 3.1 Mechanism

A pickle is a program. `GLOBAL`/`STACK_GLOBAL` name a callable, `REDUCE` calls it
with the arguments on the stack, `BUILD` applies a state dict, `INST`/`OBJ`/
`NEWOBJ`/`NEWOBJ_EX` construct classes. An unpickler that resolves arbitrary
globals executes whatever the stream names. The same shape appears one level down
in `.npy` object arrays (`allow_pickle=True`), joblib's `NumpyArrayWrapper`
substreams, torch's legacy and zip formats, TorchScript's `constants.pkl`,
`.pt2`'s `data/sample_inputs/*.pt`, legacy XGBoost `.model` files and the
CatBoost `python` export.

**Evidence.** `CVE-2026-23001` (Hugging Face Transformers) and `CVE-2026-31239`
(mamba) are the current generation of remote-code-execution-in-a-checkpoint
reports; the February 2025 nullifAI campaign on the Hugging Face Hub shipped
broken-pickle and 7z-disguised payloads that defeated extension-driven scanners.
`arXiv 2508.19774` ("Exception-Oriented Programming") catalogued 133 gadgets and
22 loading paths that reach a pickle, and showed 19 of them missed by every
state-of-the-art scanner; `arXiv 2607.17503` (ShadowPickle) showed that an
allowlisted callable can carry the payload in its *argument*, which is why
`SC4N-PICKLE-CODE-STRING` fires on an otherwise allowlisted stream. `arXiv
2508.15987` (PickleBall) is the same story for the Hub's own scanning. The
Hub's `pickletools.genops`-based check is a denylist of opcode shapes and is
explicitly documented as not a security boundary.

**Detectors.** The engine is allowlist-by-default, transcribed from PyTorch's
`torch/_weights_only_unpickler.py`, so the rule set is auditable against the
unpickler users actually get:

| Rule | Fires on |
|---|---|
| `SC4N-PICKLE-GLOBAL-CRITICAL` / `-HIGH` / `-UNKNOWN` | a callable global outside the allowlist, graded by a three-tier gadget table (`internal/pickle/gadgets.go`) |
| `SC4N-PICKLE-REDUCE` | `REDUCE` whose callable is not an allowlisted safe constructor |
| `SC4N-PICKLE-BUILD-STATE` | `BUILD` applying attacker state to a non-allowlisted class |
| `SC4N-PICKLE-INST` / `-OBJ` / `-NEWOBJ` / `-NEWOBJ_EX` | class construction from stream-controlled data |
| `SC4N-PICKLE-CODE-STRING` | a `str`/`bytes` constant ≥ 24 bytes passed as a `REDUCE` argument that looks like executable source — the ShadowPickle case, and the one rule that fires on an allowlisted callable |
| `SC4N-PICKLE-MEMO-ALIAS` | the same `(module, qualname)` bound twice, or reached through an overwritten memo slot — the overwritten-module evasion |
| `SC4N-PICKLE-SETITEM-TARGET` | `SETITEM`/`SETITEMS` against a non-dict target: the pre-2.10 heap-corruption class (CVE-2026-24747 / GHSA-63cw-57p8-fm3p) |
| `SC4N-PICKLE-PERSID` | `BINPERSID` for anything other than the `("storage", …)` tuple |
| `SC4N-PICKLE-EXT` | extension-registry lookups, which resolve through an environment-dependent registry that cannot be verified statically |
| `SC4N-PICKLE-APPEND-TARGET`, `SC4N-PICKLE-STACK` | the other loader guards (append into a non-list, stack underflow) |
| `SC4N-PICKLE-PREFIX` / `-TRAILING` / `-SEGMENT` / `-INCOMPLETE` / `-OFFSET-ZERO` / `-STRUCT` | stream-shape violations: bytes before the first `PROTO`, bytes after the first `STOP` (the nullifAI shape), concatenated segments, a walk that did not reach a clean end, and the offset-zero class of scanner bug |
| `SC4N-PICKLE-SAFE-GLOBALS`, `SC4N-PICKLE-REQUIRES-UNSAFE-LOADER` | informational: the stream only uses the weights-only surface, or it cannot be loaded by `weights_only=True` at all |
| `SC4N-STRING-*` | indicators over reconstructed constants: `SC4N-STRING-C2`, `-CREDENTIAL`, `-SHELL`, `-DECODER`, `-OBFUSCATION`, `-RAW-IP-URL`, `-SECRET-VALUE`, `-LOADER-FLAG` |
| `SC4N-NUMPY-OBJECT-ARRAY`, `SC4N-JOBLIB-WRAPPER-MISMATCH` | the same execution surface reached through numpy and joblib |

**Mitigation.** Load checkpoints with `weights_only=True` (the default from torch
2.6) or, better, use safetensors, which has no code path at all. For `.npy`,
never set `allow_pickle=True` on untrusted data. For joblib, treat a `.joblib`
file as a pickle. Pin `revision=` on every Hub fetch so the bytes you audited are
the bytes you load.

**Residual risk.** Weights-only constrains opcodes, not behaviour: a model with
`trust_remote_code` code or a Lambda layer still runs code, and the whole
weight-level class in §6 is untouched by pickle rules. A denylist of *names*
inside an allowlist of *modules* is defeated by anything that reuses an
allowlisted name for a different object at load time; `SC4N-PICKLE-MEMO-ALIAS`
narrows that hole but cannot close it, because sc4n cannot know what a module
attribute resolves to in the loader's process.

### 3.2 The `SETITEM` heap-corruption class

`CVE-2026-24747` / `GHSA-63cw-57p8-fm3p`: a crafted stream that applies
`SETITEM` to a target that is not a dict corrupted the unpickler's heap before
2.10.0. It is a memory-safety bug, not a gadget call, so name-based scanners miss
it entirely; the loader guard (`SETITEM` only on `dict`/`OrderedDict`/`Counter`)
is what `SC4N-PICKLE-SETITEM-TARGET` encodes.

## 4. Loader- and config-driven execution

### 4.1 `trust_remote_code` and `auto_map`

**Mechanism.** `config.json`'s `auto_map` names `module.ClassName` for
`AutoModel`, and `trust_remote_code=True` makes `transformers` import and execute
that module from the repository. The code is *in* the repo the user is
downloading; the flag is the only thing standing between a download and
execution.

**Evidence.** `CERT VU#456290` and `CVE-2026-4372` document the pattern.

**Detectors.** `SC4N-CONFIG-AUTO-MAP` (critical) with evidence naming the
`module.ClassName` and whether the referenced file is present next to the config;
`SC4N-CONFIG-TRUST-REMOTE-CODE` (high); `SC4N-CONFIG-ARCHITECTURE-UNKNOWN` (info)
for architectures outside the known list; `SC4N-ADAPTER-EXTERNAL-BASE` (high) for
a PEFT adapter whose base model resolves to another repository;
`SC4N-MODULES-REMOTE-MODULE` for sentence-transformers module stacks.

**Mitigation.** `trust_remote_code=False`, and if you must use custom code, vendor
it, read it, and pin the revision. `local_files_only=True` when a local copy is
intended.

**Residual risk.** The referenced module is only analysed when the scan walks the
file; a config scanned alone reports the reference, not the module's content.
`SC4N-LOADER-NO-LOCAL-ONLY` and `SC4N-LOADER-NO-REVISION` catch the *caller's*
mistake only where sc4n is scanning the calling code.

### 4.2 Keras: Lambda layers, `safe_mode`, and the `__lambda__` code blob

**Mechanism.** A `.keras` file is a zip whose `config.json` can declare
`class_name: "Lambda"` with an embedded
`{"function": {"class_name": "__lambda__", "config": {"code": …}}}`, and Keras'
`func_load` base64-decodes `code`, runs `marshal.loads` on it and rebuilds a
`FunctionType` — arbitrary bytecode execution from a model file. `.h5` is worse:
`safe_mode=True` is **silently ignored** for HDF5 (GHSA-36rr-ww3j-vrjv), so an
H5 `Lambda` is at least as dangerous as a `.keras` one. `TorchModuleWrapper`
hands attacker data to `torch.load`.

**Evidence.** `VU#253266` / `CVE-2024-3660`, `CVE-2025-1550` (crafted
`config.json` bypassing `safe_mode=True`), `CVE-2026-12481` (`safe_mode=None`
falsey fallback reaching `func_load`), `CVE-2026-12482` (malicious tar bypassing
`filter_safe_tarinfos`), `CVE-2026-12484` (`TorchModuleWrapper`), and the sibling
loader bugs `CVE-2026-12479` / `CVE-2026-12480` / `CVE-2026-12570` (path
traversal, HDF5 arbitrary read, shape-bomb DoS).

**Detectors.** `SC4N-KERAS-LAMBDA` (critical), `SC4N-KERAS-TORCH-WRAPPER`
(critical), `SC4N-KERAS-CLASS-UNKNOWN` for any other `class_name`/
`registered_name` outside the safe set, `SC4N-KERAS-STRUCT`,
`SC4N-HDF5-STRUCT` and `SC4N-HDF5-EXTERNAL-LINK` for external-link/
external-storage references. Extracted `code`/`closure`/`defaults` strings go to
the Python analyzer and the indicator engine.

**Mitigation.** `keras.models.load_model(..., safe_mode=True)` on a current Keras,
and treat any H5 as if `safe_mode` did not exist. Do not load `.keras` from an
untrusted source at all if a Lambda is present.

**Residual risk.** The allowlist is a curated list of layer names; a new layer
class with a `from_config` that does something surprising is unknown until the
list is updated. `SC4N-LOADER-KERAS-SAFE-MODE` catches the caller passing
`safe_mode=False` only when sc4n is scanning the caller's code.

### 4.4 TensorFlow: ops, file I/O and assets

**Mechanism.** A SavedModel's `GraphDef` is a program for the TF runtime.
`PyFunc`/`EagerPyFunc` call into a Python function supplied by the environment;
`ReadFile`/`WriteFile`/`SaveV2`/`RestoreV2`/`MatchingFiles`/`FileName` read and
write paths named *inside the graph*, so a model that carries an absolute path or
a `..` traversal is an arbitrary file read/write primitive once loaded. A file
under `assets/`/`assets.extra/` is served by the loader, so a native executable or
a shell script there is code shipped with the model. TFLite's `custom_code` /
`builtin_code` names a **device plugin** the host must supply, and
`custom_options` is an opaque blob; TF.js flex ops are the same class.

**Detectors.** `SC4N-TF-PYFUNC`, `SC4N-TF-FILE-IO` (absolute/`..` path constants
only), `SC4N-TF-ASSET-EXECUTABLE`, `SC4N-TF-STRUCT`,
`SC4N-TF-CHECKPOINT-STRUCT` / `SC4N-TF-CHECKPOINT-NO-CODE` (a bare checkpoint
carries no inline code — the rule says so), `SC4N-TFLITE-CUSTOM-OP`,
`SC4N-TFLITE-NATIVE-MAGIC`, `SC4N-TFLITE-ENTROPY`, `SC4N-TFLITE-STRUCT`,
`SC4N-TFJS-FLEX-OP`.

**Mitigation.** Load SavedModels from a sandbox with no filesystem access beyond
the model directory; treat any `PyFunc` op as "the environment must supply code".

**Residual risk.** An op name is a *capability*, not a payload: a legitimate
SavedModel can use `ReadFile` on a relative path, and a custom op can be a
first-party plugin. The findings say which, and the severity is set so a
path-shaped constant is what raises it.

### 4.5 CoreML and ExecuTorch: host-supplied code

**Mechanism.** A CoreML `CustomModel` (protobuf field 555) or a neural-network
layer with `CustomLayerParams.className` (field 500) names a class **the host
application** must provide; a poisoned package pairs with a host plugin that
resolves the name, which is why it is high rather than critical. ExecuTorch
`.pte` carries segments and can embed native code.

**Detectors.** `SC4N-COREML-CUSTOM-LAYER`, `SC4N-COREML-STRUCT`,
`SC4N-COREML-PROGRAM-UNVERIFIED`, `SC4N-PTE-NATIVE`, `SC4N-PTE-STRUCT`, and
`SC4N-PTE-UNVERIFIED` (info: the deep flatbuffer parse is out of v1 and the rule
says so).

**Residual risk.** The class name is reported, not resolved: whether it is
dangerous depends on the host, which a scanner cannot see.

### 4.3 Chat templates: SSTI and inference-time backdoors

**Mechanism.** A chat template is Jinja2 that the *serving stack* renders. A
template that reaches `__class__`/`__subclasses__`/`__globals__`, or that
concatenates a dunder name to evade a naive matcher, is server-side template
injection. A template can also be a *backdoor channel*: it can inject text into
every conversation, exfiltrate the system prompt through a crafted URL, or
suppress the model's own guardrails — which is a model-behaviour attack that
never touches a shell.

**Evidence.** `CVE-2026-5760` / `CERT VU#915947`; "Pillar 18 models / 4 engines"
template-injection work; `arXiv 2602.04653`.

**Detectors.** `SC4N-JINJA-PY-OBJECT` (dunder introspection),
`SC4N-JINJA-DANGEROUS-GLOBAL` (`lipsum`, `cycler`, `namespace`, … combined with
attribute access), `SC4N-JINJA-DYNAMIC-NAME` (a name assembled by concatenation
or subscript — the `'__g'+'lobals__'` evasion), `SC4N-JINJA-INCLUDE`,
`SC4N-JINJA-RAW`, `SC4N-TEMPLATE-INJECTION`. There is one analyser and one rule
set: a template carried inside GGUF metadata (`tokenizer.chat_template`) is
handed to the same `internal/jinja` code path as a `*.jinja` file, so a GGUF
template cannot be analysed less thoroughly than the same text on disk.
Templates are found in `*.jinja`/`*.j2`/`*.tmpl`,
`tokenizer_config.json:chat_template` (string **and** list-of-objects shapes),
`chat_template.json`, `config.json`, GGUF metadata and embedded code strings.

**Mitigation.** Render templates in a sandboxed environment with no globals and no
loader, and review a template change like a code change.

**Residual risk.** sc4n analyses Jinja2's construct surface. Another engine (or a
Jinja2 extension) with different globals is not covered, and a backdoor that is
ordinary Jinja2 (an `{% if %}` that changes wording) is indistinguishable from a
legitimate template by any static rule.

## 5. Container, compression and format-confusion smuggling

### 5.1 Why the parser contract is shaped the way it is

Every entry in the bypass history is the same failure: **the scanner stopped
before it reached the payload, and reported clean.**

- `modelscan` issue #354: an unreadable member *before* `archive/data.pkl` made
  the zip iterator raise, and the scan reported CLEAN. sc4n's contract is
  fail-closed iteration: a corrupt member emits `SC4N-ARCHIVE-MEMBER-ERROR` and
  the walk continues; only an unreadable *container* fails the artifact.
- `picklescan` `CVE-2025-10157`: a denylist matched module names exactly, so
  `asyncio.subprocess` slipped past `subprocess`. sc4n matches with
  `<module> == m || strings.HasPrefix(<module>, m+".")`.
- `fickling` `CVE-2025-67747` and `CVE-2026-14534`: bypasses of a pickle-safety
  check. sc4n's answer is structural (a total walk that never aborts, and
  allowlist-by-default rather than denylist-by-name), not a longer denylist.
- The published modelscan double-compression PoC: `gzip(zlib(pickle))` where the
  scanner unwraps one layer. sc4n recurses on any member that itself sniffs as
  compressed, up to `MaxDepth`, and reports `SC4N-ARCHIVE-NESTED-COMPRESSION`.
- The February 2025 Hugging Face campaign: `.pt` files that were 7z archives,
  where every extension-driven scanner saw "not a zip" while the loader still
  deserialised the payload. sc4n dispatches on **content, never extension**, and
  a recognised-but-undecompressable wrapper is a finding
  (`SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION`), never a silent pass.

### 5.2 Zip and tar member handling

| Rule | Fires on |
|---|---|
| `SC4N-ARCHIVE-PATH` | absolute paths, `..` segments, NUL, drive letters, backslash separators, over-long names — the zip-slip class |
| `SC4N-ARCHIVE-LINK` | symlink/hardlink/device members |
| `SC4N-ARCHIVE-NAME-MISMATCH` | the local header name differing from the central directory name: the classic way to make a scanner read one file and a loader another |
| `SC4N-ARCHIVE-DUPLICATE-NAME`, `-ENCRYPTED`, `-CRC` | duplicate names, encrypted members (which cannot be inspected), CRC mismatches |
| `SC4N-ARCHIVE-NATIVE-MEMBER`, `-SHEBANG` | a validated native executable or a script inside an archive (high, not critical: loading the model does not run the member) |
| `SC4N-ARCHIVE-NESTED-COMPRESSION`, `-UNSUPPORTED-COMPRESSION` | a wrapper inside a wrapper, and a wrapper with no stdlib decoder (xz, lzma, lz4, zstd, 7z, rar, joblib-legacy `ZF`) |
| `SC4N-LIMIT-ENTRIES`, `-RATIO`, `-DECOMPRESSED`, `-DEPTH`, `-SPILL` | the bomb defences, each naming the limit and the observed value |

**Residual risk.** A member inside a wrapper sc4n cannot decompress is *not
analysed*; the finding says so, but the bytes are unread. `MaxDepth` bounds a
legitimate nest (`joblib → object pickle`, `zip → pickle`) and will also stop a
pathological one — the limit finding is how you tell.

### 5.3 Torch archive shapes

**Mechanism.** `torch.save` has three shapes and the loader accepts all of them,
which is why a scanner that only looks for a zip misses two thirds of the attack
surface: the *new* format (an uncompressed zip holding `data.pkl` and
`data/<n>`), the *legacy* format (`MAGIC_NUMBER` + a protocol-1001 pickle + raw
storage appended) and legacy tar archives with `storages`/`tensors`/`pickle`
members. A **prefixed** archive (bytes before the first local header) still loads,
because Python's `_is_zipfile` checks the current offset while the C++ reader
initialises miniz over the whole range. A `.pt` that is really a 7z archive is the
February 2025 campaign: the loader deserialised it while every extension-driven
scanner saw "not a zip".

**Detectors.** `SC4N-TORCH-ZIP`, `SC4N-TORCH-LEGACY`, `SC4N-TORCH-LEGACY-TAR`,
`SC4N-TORCH-SCRIPT` and `SC4N-TORCH-PT2` (info: the shape was recognised and
handed to the right engine), `SC4N-TORCH-PREFIXED-ARCHIVE` (high),
`SC4N-TORCH-7Z` (critical), `SC4N-TORCH-STRUCT`. Every pickle inside every shape
goes to the pickle engine — a fixture proves `data.pkl` with a `REDUCE` of
`os.system` is reported *through* the torch path — and `code/**/*.py` inside a
TorchScript archive goes to the Python analyzer.

**Residual risk.** The 7z case is detected and reported but not decompressed
(no stdlib 7z decoder): the payload inside is unread, and the finding says so.

### 5.4 Polyglots and single-file executables

**Mechanism.** A file can be two things at once: a `.safetensors` with an ELF
appended, a GGUF with an APE stub (llamafile), a zip that is also a tar. The
loader reads its format; the OS or the shell may read the other.

**Detectors.** A universal layer runs before every parser, on every artifact and
every nested member: `SC4N-POLYGLOT-NATIVE` (a *validated* native header, high),
`SC4N-POLYGLOT-MAGIC-ONLY` (a bare magic that does not validate, info — a tensor
of bytes can contain `\x7fELF` by chance), `SC4N-POLYGLOT-CONTAINER`,
`SC4N-POLYGLOT-SHEBANG`, `SC4N-NATIVE-VALID`, `SC4N-NATIVE-EMBEDDED-PAYLOAD`
(a second validated header), and `SC4N-FORMAT-EXTENSION-MISMATCH` when the sniffed
format contradicts the extension. `SC4N-GGUF-POLYGLOT` and
`SC4N-SAFETENSORS-NATIVE-MAGIC` are the format-specific statements of the same
condition.

**Residual risk.** The universal layer reads the first and last 1 MiB. A payload
buried in the middle of a 13 GiB tensor file is not found by a window scan; the
format parsers' own trailing-data rules (`SC4N-SAFETENSORS-TRAILING-DATA`,
`SC4N-GGUF-TRAILING-DATA`, `SC4N-NUMPY-TRAILING`) are what cover the tail.

### 5.5 ONNX external data

**Mechanism.** `TensorProto.external_data` names a file and an offset; the loader
reads it. An absolute path, a `..` traversal, or a symlink that leaves the model
directory turns model loading into arbitrary file read; a crafted
`external_data` key (`__class__` and friends) is attribute injection.

**Evidence.** `CVE-2022-25882`, `CVE-2024-27318`, `CVE-2026-34447` =
`GHSA-p433-9wv8-28xj`, `CVE-2026-27489` = `GHSA-3r9x-f23j-gc73`,
`CVE-2026-34445` = `GHSA-538c-55jv-c5g9`, `GHSA-cmw6-hcpp-c6jp`.

**Detectors.** `SC4N-ONNX-EXTERNAL-TRAVERSAL` (high: a file-read primitive, the
same calibration as every other path-escape rule),
`SC4N-ONNX-EXTERNAL-KEY` (high; dunder keys are marked in the evidence),
`SC4N-ONNX-EXTERNAL-BOUNDS` (high), `SC4N-ONNX-EXTERNAL-SYMLINK` (high),
`SC4N-ONNX-CUSTOM-DOMAIN`, `SC4N-ONNX-FUNCTION`, `SC4N-ONNX-STRUCT`, and
`SC4N-PATH-ESCAPE` when containment (`os.Root`) rejects a resolved path.

`SC4N-ONNX-CUSTOM-DOMAIN` is reported once per distinct `(domain, kind)` per
artifact, with the number of uses in the extra fields, not once per node: an
onnxruntime-optimised model binds every one of its nodes to `com.microsoft`, and
per-node reporting turned one fact into a hundred findings (measured on the
corpus: 100 → 5). Every node still counts towards the number in the evidence, so
nothing is hidden; what changed is how many times the same fact is stated.

**Residual risk.** Only the whitelisted `external_data` keys are resolved at all;
a legitimate-but-unusual layout may therefore be reported rather than followed,
and a file that is *not* present at scan time cannot be judged.

### 5.6 GGUF metadata and parser structure

**Mechanism.** GGUF carries arbitrary key/value metadata, including the chat
template, and a parser that trusts declared counts can be made to allocate,
over-read or mis-map tensor extents. Metadata poisoning is the *content* attack
(template SSTI, backdoor templates, exfiltration URLs in `general.*` strings);
structure bugs are the *parser* attack.

A `tokenizer.chat_template` value is handed to the Jinja analyser — the same code
path a `*.jinja` file takes — so a template inside a GGUF is judged by section
7's rules rather than by a GGUF-specific subset of them.

**Evidence.** `CVE-2024-21802`, `CVE-2024-23496`, `CVE-2024-23605`,
`CVE-2025-53630`, `CVE-2026-33298`, `GHSA-8wwf-w4qm-gpqr`.

**Detectors.** `SC4N-GGUF-STRUCT` (counts beyond the file, illegal or duplicate
keys, retired or out-of-range ggml types, rank above 4, zero dimension, non-zero
alignment padding, misaligned/unsorted/overlapping tensor offsets),
`SC4N-GGUF-TRAILING-DATA`, `SC4N-GGUF-ENDIAN-AMBIGUOUS`,
`SC4N-GGUF-EXTENT-UNVERIFIED` (a tensor whose extent cannot be computed from the
pinned type table — reported rather than guessed), plus the template rules and the
shared indicator engine over every metadata string.

Two calibrations matter for reading this rule's output. The type table is
transcribed from the upstream `enum ggml_type` and cross-checked against the
`static_assert`s on the block structs; it is pinned at `GGML_TYPE_COUNT = 43`
(MXFP4, NVFP4, Q1_0, Q2_0 are the last four verified entries), and an id beyond
that is reported as a violation. A *truncated* file (a partial download, or a
header-only slice) is the shape the aggregate covers: every tensor whose extent
runs past EOF is the same fact — the file ends — so the first such tensor is
reported by name and the rest are one finding whose extra fields carry
`further_tensor_extents`, `first_past_eof_end` and `last_past_eof_end`. On the
corpus that turned 9270 findings over 256 artifacts into 287, while misalignment,
out-of-order offsets, in-file overlaps and unknown type ids stay per tensor
because each of those is a fact about that tensor alone.

**Residual risk.** The ggml type table is a transcription; a type whose
`block_size`/`type_size` cannot be confirmed is marked unverified and its extent
check is skipped, so a wrong table entry can never manufacture an "overlap"
finding — but it also means an unverified type is not geometry-checked. An id
above the pinned `COUNT` is a violation, and a *new* upstream type therefore
reports until the table is re-transcribed; the evidence names the id so the
difference is visible.

## 6. Weight-level backdoors (out of band, never a gate)

**Mechanism.** A model can be malicious without containing a single dangerous
opcode: a trigger phrase that flips a classifier, a fine-tuned adapter that
exfiltrates through generated text, poisoned weights that behave differently on a
distribution the defender cannot see. This is the class the pickle rules cannot
touch, and it is the reason "sc4n reported nothing" must never be read as "this
model is safe".

**Why it is out of band.** The published techniques — Neural Cleanse, ABS,
STRIP, spectral signature defence, activation clustering, MIST, Z-PEFT — are
*dynamic*: they need the model loaded, a dataset, and compute. Each has published
false-positive rates and each assumes a threat model (single trigger, known
classes, white-box access) that a CI gate cannot assume. Running them inside a
scanner would trade a false sense of coverage for a large bill.

**What sc4n ships instead.** `-deep-stats` enables informational statistics over a
bounded sample of each tensor body: `SC4N-WEIGHTS-NAN` (NaN/Inf payloads),
`SC4N-WEIGHTS-DUPLICATE` (byte-identical tensors), `SC4N-WEIGHTS-ALL-ZERO`,
`SC4N-WEIGHTS-OUTLIER`, `SC4N-WEIGHTS-ENTROPY`. These are **structural anomaly
signals at info severity**, with named thresholds and their rationale in the code,
and they are off by default. They can find a payload smuggled *in* weights (a
NaN-encoded blob, an appended encrypted region) and they cannot find a trained
trigger.

**Residual risk.** Stated plainly: a backdoored model with clean structure, clean
metadata and clean code passes sc4n. Provenance (§10) and dynamic evaluation are
the mitigations; neither is a scanner's job.

## 7. Prompt injection, exfiltration and metadata channels

**Mechanism.** Everything a model or its tooling reads is an input channel: the
model card (`README.md`), `dataset_info.json`, `model_index.json`, `*.md` docs,
metadata string values, and the tokenizer's special tokens. Text can instruct the
consuming agent, hide instructions in HTML comments or zero-width/bidi
characters, or carry an exfiltration URL. Unicode anomalies do double duty:
homoglyphs and mixed scripts evade a human reviewer while remaining renderable.

**Evidence.** OWASP LLM01 (prompt injection); the spotlighting/datamarking line of
mitigation work.

**Detectors.** `SC4N-CARD-INJECTION`, `SC4N-CARD-HIDDEN` (instruction text in an
HTML comment, or a bidi run that reorders text), `SC4N-CARD-COMMENT` (an HTML
comment with no instruction in it — informational, because a commented-out
heading, a lint directive and an uploader's section markers are editorial
practice), `SC4N-CARD-INVISIBLE` (a zero-width run that reorders nothing — what a
copy-paste from a rendered page leaves behind), `SC4N-CARD-PARSE` (frontmatter
that does not parse — reported, then the raw text is still scanned),
`SC4N-METADATA-INJECTION`, `SC4N-METADATA-CODE` (a metadata value that looks like
code), `SC4N-UNICODE-ANOMALY`, and the shared indicator engine's `SC4N-STRING-C2`,
`-RAW-IP-URL`, `-CREDENTIAL`, `-SECRET-VALUE` over every metadata string. The
chat-control-tag half of `SC4N-METADATA-INJECTION` is exempt in the five documents
that *declare* the tokenizer's tokens (`tokenizer.json`, `tokenizer_config.json`,
`special_tokens_map.json`, `added_tokens.json`, `chat_template.json`): a file that
defines `<|im_start|>` is naming its own token, not smuggling text into a model's
input. The instruction phrases, the secrets and the endpoints are still reported
there, and the same bytes under any other name are scanned as ordinary text.

Three details of that set are worth reading, because each is a channel that was
invisible until it was measured:

- **The Unicode Tags block (U+E0000–U+E007F)** is part of the anomaly walk and of
  the card analyser's invisible runs. The characters draw nothing in any renderer
  and a tokenizer still reads them, which makes them the purest form of a hidden
  instruction; an enumerated list of zero-width and bidi code points missed them
  entirely.
- **The above-anaphora phrasings** (`ignore the above`, `ignore all previous`,
  `disregard the above`, `forget the above`) are in the phrase table, the template
  table and the card directives. The tables had "ignore previous instructions" and
  "disregard previous instructions", which a document that says "ignore the above"
  never contains — the classic card/template override went unreported.
- **A credential value is reported on its shape, and a placeholder is not
  reported at all.** `SC4N-STRING-SECRET-VALUE` matches vendor token shapes
  (`ghp_`, `github_pat_`, `sk-`, `AKIA`/`ASIA`, `AIza`, `xoxb-`, a JWT) as well as
  `NAME=value` assignments, and redacts whatever it matched. Because the literal
  table cannot see the value, the assignment half drops the ones a reader can see
  are not credentials: `api_key="EMPTY"`, `api_key="none"`, `api_key='your-api-key'`,
  `${VAR}`, `<your-key>`, `password=password`. Measured on the corpus, every
  assignment-shaped hit it had was one of those — the local-server example a model
  card ships — so the filter removed 11 false positives there while the token shapes
  kept firing wherever a value actually has a credential's shape.

**Mitigation.** Treat card text as untrusted input, never as documentation to be
obeyed. Datamarking/spotlighting reduces (does not eliminate) injection success.
Strip or refuse to render zero-width and bidi characters in a review UI.

**Residual risk.** Instruction-shaped text detection is a heuristic on phrasing
and structure. A novel phrasing, a non-English instruction, or an instruction that
is genuinely part of the documentation is either missed or reported as noise. The
rules deliberately prefer the lower severity when a phrase could be legitimate.

## 8. Resource exhaustion

| Threat | Mechanism | Detector | Cap (default) |
|---|---|---|---|
| Zip bomb | nested/recursive compression | `SC4N-LIMIT-RATIO`, `-DECOMPRESSED`, `-ENTRIES`, `-DEPTH`, `-SPILL` | ratio 200, 8 GiB, 100 000 entries, depth 4, spill 4 GiB |
| Header bomb | a declared length that precedes the payload | `SC4N-LIMIT-STRING`, format structure rules | 100 MiB header, 16 MiB string/blob |
| Stack/segment bomb | a pickle that builds an unbounded stack | `SC4N-LIMIT-*` via `MaxStackDepth` | 1<<20 |
| Finding flood | a crafted artifact with a million trigger sites | `SC4N-LIMIT-FINDINGS` (the drop is reported, never silent) | 100 000 |
| Tokenizer ReDoS | a `pre_tokenizer` regex that is catastrophic on attacker-influenced strings | `SC4N-TOKENIZER-REDOS`, `SC4N-TOKENIZER-UNKNOWN-CLASS` | pattern shape (not execution) |

**Evidence.** `CVE-2024-12720`, `CVE-2025-2099`, `CVE-2025-3263`, `CVE-2025-5197`
are Python-side ReDoS reports in the tokenizer/pattern ecosystem; the Rust
`tokenizers` crate uses RE2-family syntax while Python `re`/`regex` sites
backtrack, so the same pattern means different things in different consumers —
which is exactly why sc4n reports backreferences, lookaround, atomic groups,
recursion and nested quantifiers as *shapes* rather than trying to run them.

**Residual risk.** Caps bound sc4n, not the consumer. A pattern that is fine in
RE2 and catastrophic in Python `re` is reported; a pattern that is slow but not
classically catastrophic is not.

## 9. Repository files that execute on install or interpreter start

| Rule | Trigger |
|---|---|
| `SC4N-REPO-PTH` (critical) | a `.pth` line starting `import`/`exec` — executed at **every** interpreter start |
| `SC4N-REPO-START` (critical) | a Python 3.15+ `*.start` entry point (`pkg.mod:callable`) |
| `SC4N-REPO-SETUP-HOOK` | `setup.py` with a `cmdclass`/`install`/`develop`/`build_py` hook or top-level code |
| `SC4N-REPO-BUILD-BACKEND` | a `pyproject.toml` build backend outside the allowlist — PEP 517 runs the backend's `requires` at build time |
| `SC4N-REPO-SITE-CUSTOMIZE` | `sitecustomize.py`/`usercustomize.py` |
| `SC4N-REPO-PYC-ORPHAN`, `-WORKFLOW-PRT`, `-WHEEL-IN-MODEL`, `-DOCKERFILE`, `-SPACE-APP` | an orphan `.pyc`, a PR-triggered workflow with write permissions, a package archive in the tree, a `Dockerfile`, a Space `app.py` |
| `SC4N-GITATTRIBUTES-LFS`, `-FILTER` | `.gitattributes` LFS patterns and any non-LFS filter/diff driver that names a command |
| `SC4N-HFCACHE-SYMLINK-ESCAPE` (high) | a cache snapshot symlink resolving outside the cache root — `os.Root` containment rejects it rather than following it |
| `SC4N-HFCACHE-BLOB-MISSING`, `SC4N-HFCACHE-REF-MALFORMED` | a referenced blob that is absent, and a `refs/` entry that is not a 40-hex commit |

**Mitigation.** Never `pip install` an untrusted model repository; inspect
`.pth`/`.start`/`setup.py` before any install; treat a `Dockerfile` and a workflow
file as code.

**Residual risk.** Name- and shape-based: `SC4N-REPO-SPACE-APP` fires on any
`app.py` because one file cannot prove the tree is a Space, and a `setup.py`
whose hook is spelled unusually is reported at lower confidence.
`SC4N-REPO-WHEEL-IN-MODEL` is in that group deliberately: `.whl`, `.tar.gz` and
`.tgz` are matched by *name*, and a name cannot tell `dataset.tar.gz` from an sdist,
so it is reported at medium severity and low confidence as a pointer to the archive
walk that actually reads the members — at high severity it made `-fail-on high` fail
on any repository that ships a data tarball, while the same bytes named `.zip`
produced nothing. The content rules in this section are the ones that decide.

## 10. Provenance and supply chain

- **Verify before you load.** `sigstore`'s `model_signing` project and
  `cosign verify` are the external steps; sc4n has no signature client (the
  dependency ceiling is stdlib + `protowire`) and says so rather than implying a
  verification it did not perform.
- **The Hub's own scanning is not a safety badge.** Hugging Face runs ClamAV,
  pickle scanning and secret scanning on uploads; the pickle check is
  `pickletools.genops`-shaped and is documented as not a security boundary. There
  is no Hub-native *signature* badge: an absent signature means nothing was
  signed, not that the artifact is malicious.
- **Emit machine-readable inventory.** `-format cyclonedx` produces a CycloneDX
  1.6 ML-BOM with `machine-learning-model` components carrying the sha256 of each
  artifact, so a downstream policy engine can pin exactly what was scanned. The
  BOM's `vulnerabilities[].id` is the sc4n rule ID, and one vulnerability is
  emitted per *finding*, so N findings of one rule produce N entries with the same
  `id` — the 1.6 schema does not require uniqueness, and rewriting the id (say
  `SC4N-X:2`) would break every consumer that maps `id` to a rule. Disambiguate by
  `affects` (the component `bom-ref`) and by `sc4n:fingerprint` in the entry's
  properties. `metadata.properties` always states `sc4n:suppressed` and
  `sc4n:dropped`, so a baselined or capped run is never read as a clean one.
  `-format sarif` produces SARIF 2.1.0 with severity bands mapped to GitHub's
  (`critical` 9.5 → `error`, `high` 8.0, `medium` 5.5 → `warning`, `low` 3.0,
  `info` 0.0 → `note`), for code-scanning-style gating.
- **Pin revisions.** `SC4N-LOADER-NO-REVISION` and `SC4N-LOADER-NO-LOCAL-ONLY`
  catch the caller-side mistakes that make every other finding moot.

**Residual risk.** Provenance proves *who* produced bytes, not that the bytes are
safe. A signed model can still be a backdoor; an unsigned one is usually just
unsigned.

## 11. Coverage limits (stated, not implied)

1. **Undecompressable wrappers are reported, not read** (xz, lzma, lz4, zstd, 7z,
   rar, joblib-legacy `ZF`). The finding names the algorithm and offset.
2. **HDF5 has no object-header reader in v1.** The bounded scan finds the root
   attributes and any JSON blob; the capability table says so. A `Lambda` hidden
   in a structure the scan does not reach is missed.
3. **ExecuTorch `.pte` is header-verified and shallow** (`SC4N-PTE-UNVERIFIED`);
   the flatbuffer is not deep-parsed.
4. **Weight-level backdoors are out of band** (§6).
5. **Windows and macOS hosts** get the in-memory source path rather than mmap;
   behaviour is identical, memory is not.
6. **The digest is capped** at `MaxHashBytes` (256 MiB) by default, because
   sha256 is CPU-bound (measured 0.35 GB/s on the reference host, which has AVX2
   but no SHA-NI) and a full digest of a 13 GiB checkpoint would cost more than
   the entire scan. The report states the scope (`sha256Scope`) — `full` or
   `prefix:<bytes>` — so a prefix digest can never be mistaken for a file digest.
   `sc4n hash` is the command that computes a full sha256 when you need one.
7. **A file the scanner cannot open is exit code 3**, not a finding: "the mount
   is missing" and "your model is malicious" must never be confusable in CI.
8. **An artifact no sniffer claims is still silent about its content.** It is
   recorded as `unknown`, only the format-independent layers run, and no finding
   says so. The exception is the text shape above (a document with a binary tail is
   now claimed as text and reported through `SC4N-CONTENT-NOT-UTF8`); a binary
   artifact with no recognisable header, and a document whose binary content begins
   within its first 64 bytes, remain in that class.
9. **The pickle prefix search is 64 bytes.** A pickle stream that starts more than
   64 bytes into an artifact is found only by the container that exists around it
   (a zip member, a framework's own reader), never by the top-level sniffer.
10. **The fat Mach-O variants the standard library cannot read** (`FAT_CIGAM`,
    `FAT_MAGIC_64`) are not claimed as native and therefore not reported as
    validated executables.
11. **A named pipe, socket or device node in a scanned tree is reported, not
    opened.** A directory walk records it as an unreadable path (exit code 3) with
    the reason, because `open(2)` on a FIFO with no writer blocks inside the
    syscall: the worker never returns, and neither the deadline nor context
    cancellation can interrupt it. An explicitly named FIFO is still opened, which
    is what makes `sc4n scan <(producer)` and a `mkfifo`-fed path work; a symlink
    whose target is one of these is reported like the target itself.

## 12. Mapping from rule to fixture

Every rule a committed fixture exercises is pinned by
`testdata/fixtures/expectations.json`: the malicious fixtures list the rule IDs they
must produce (`expect`) and the IDs they must not (`forbid`), and `internal/scan`'s
corpus gate asserts the scanner's finding set is a superset of `expect` and
disjoint from `forbid` for every file on disk. The benign set
(`testdata/fixtures/benign/`) is the false-positive gate: it must produce no
`high` or `critical` finding at all.

The gate covers the fixtures that exist, not the rule catalogue: 142 of the 189
rules are named in `expectations.json`, and the rest — the limit rules, the
parse-failure rules and the hf-cache collector rules, which need a crafted input or
a crafted cache to reach — are covered by Go tests only. `sc4n rules` prints the
live catalogue with each rule's CWE, and `sc4n formats` prints the per-format depth
of analysis and the deliberate gaps.

A fixture whose contract is a *count* rather than an ID set (one aggregate finding
instead of N, exactly one finding for a duplicate key) cannot be expressed by
`expect`/`forbid`, so those live in the owning package's Go tests — see
`TestPastEOFCascadeIsAggregated`, `TestCustomDomainIsAggregated` and
`TestDuplicateTopLevelKeyIsOneFinding` — and are proven by running them against the
tree at the commit before the fix.
