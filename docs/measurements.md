# Measurements

What the scanner actually did, on corpora that exist outside this repository, with
the numbers and the commands that produced them. Everything below was measured on
2026-11-07 with the `v1.0.0` binary; the two numbers that come from an earlier
round say so.

The point of this page is to make claims falsifiable. A scanner that only reports
"X rules, Y formats" is unmeasurable; these are the tables a user needs to decide
whether the tool is worth running and what its false-positive cost will be.

## Method

Three Hugging Face corpora, each fetched by `sc4n hub` and then scanned with the
CLI directly, so the numbers are CLI-to-CLI and a reader can reproduce them
without the campaign machinery:

```sh
# one corpus (the command used for every row below)
cd $CORPUS/top25-downloads/repos
sc4n scan -root . -format json -out scan.json \
  $(for p in $(cat partials.txt); do printf -- '-partial %s ' "$p"; done) .
```

`partials.txt` is one line per file whose `fetch.json` status is `slice`:
`repos × files × (id + "/" + path)`. A slice is a truncated copy of a larger file,
so `-partial` is what makes its extent finding `SC4N-PARTIAL-SLICE` (info) instead
of a violation caused by the truncation. Without it every slice looks malformed.

| corpus | repos | artifacts scanned | bytes | wall time |
|---|---|---|---|---|
| `top25-downloads` (the Hub's 30-day download ranking, top 25) | 25 | 1038 | 1.14 GiB | 5.6 s |
| `top25-trending` (`trendingScore`, top 25) | 25 | 1358 | 2.34 GiB | 13.0 s |
| `unsafe` (the Hub's own `unsafe` verdict, 129 of 2391 candidates) | 129 | 1723 | 8.71 GiB | 41.3 s |

The trending corpus shows fewer artifacts here than the campaign report did
(1358 vs 1708): the campaign counts rows the Hub returned, including budget
refusals and unreadable names, while this is what the CLI opened. Both numbers are
in `campaign.json` and `scan.json` for the same run; this page reports the CLI's.

## Findings

| corpus | critical | high | medium | low | info | total |
|---|---|---|---|---|---|---|
| `top25-downloads` | 1 | 0 | 3 | 4 | 315 | 323 |
| `top25-trending` | 19 | 65 | 56 | 15 | 1048 | 1203 |
| `unsafe` | 306 | 4267 | 2864 | 28 | 1238 | 8703 |

What dominates each corpus matters more than the totals:

- **`top25-downloads`** — 315 of the 323 findings are `info`, and 173 of those are
  `SC4N-PARTIAL-SLICE` (the fetch budget kept a header, so the extent check was
  told not to call it malformed), 49 `SC4N-FORMAT-AMBIGUOUS`, 41
  `SC4N-COREML-PROGRAM-UNVERIFIED` — statements about what was not interpreted, not
  about risk. The single critical is
  `nomic-ai/nomic-embed-text-v1.5/config.json`: an `auto_map` whose 7 entries load
  `configuration_hf_nomic_bert.NomicBertConfig` and the module that implements it
  **from another repository** (`nomic-ai/nomic-bert-2048`), which is a real
  remote-code dependency of a top-25 model, not an artefact of the scanner.
- **`top25-trending`** — 71 of the 84 critical/high findings are one repository,
  `baidu/Unlimited-OCR-2`, whose `deepencoder.py` and sglang wheel genuinely call
  `subprocess`, `torch.load` without `weights_only`, remote loaders and `eval` on
  tainted input. The other 13 are `config.json` `auto_map` entries in
  `microsoft/Mage-VL-Cowork`, `Edge0/Audio8-TTS-Realistic-Air`,
  `LiquidAI/LFM3-1.7B`, `burner22/numbat`, `moonshotai/Kimi-K3.1-Pro`,
  `ricursiveAI/Ripple-65B-Preview` and `sensenova/SenseNova-Loop-9B-Preview` (13
  `SC4N-CONFIG-AUTO-MAP` between them) plus one `.py` loader
  (`microsoft/Mage-VL-Cowork/osworld_eval/mm_agents/mage_hybrid_agent.py`).
- **`unsafe`** — 1427 of the 4267 highs are `SC4N-METADATA-CODE`, and 1208 of those
  are one webshell dataset (`dataset.jsonl`) that is a catalogue of code snippets;
  the finding is true and the volume is the artifact's shape. The pickle family
  (`SC4N-PICKLE-REDUCE` 909, `-BUILD-STATE` 357, `-NEWOBJ` 352) is what the corpus
  is for.

## Precision: what the fixes removed

The honest question is not "how many findings" but "how many were wrong". Both
benign corpora were scanned with the binary from the round's start
(`5f968cd` — rebuilt from the tag for this measurement) and with `v1.0.0`, over
exactly the **fully fetched** files, so the comparison needs no `-partial` and the
two runs see identical bytes:

| corpus | binary | critical | high | medium | low | info | total |
|---|---|---|---|---|---|---|---|
| `top25-downloads` (767 full files) | `5f968cd` | 7 | 29 | 32 | 4 | 67 | **139** |
| | `v1.0.0` | 1 | 0 | 3 | 4 | 73 | **81** |
| `top25-trending` (420 full files) | `5f968cd` | 28 | 181 | 353 | 15 | 110 | **687** |
| | `v1.0.0` | 19 | 65 | 56 | 15 | 114 | **269** |

Six criticals and 29 highs on `top25-downloads` were false positives that no
longer fire; the surviving critical is the `nomic-ai` remote `auto_map` above.
Each removed class has a fixture or a test pinning the new behaviour; the classes
were: pickles inside a *compressed* stream being walked as raw pickles and
resynced through deflate; a zlib frame's junk prefix being reported as a pickle
prefix; `.bin` legacy torch tars treated as malformed zip; one `auto_map` finding
per repository entry instead of per repository; tokenizer vocabularies scanned as
prose; model cards treated as instructions to the scanner rather than
documentation; `subprocess` helpers counted as proof of execution rather than as
capability; taint reported per tainted value rather than per sink; GGUF slices
reported as violations; raw-IP indicators reported per buffer instead of per
artifact; ONNX snapshots claimed on `ir_version` alone.

The remaining `high` in `top25-trending` (65) are all inside the two repositories
named above, and each was read: they are the payload of a 2000-line inference
harness that calls `subprocess` and loads checkpoints without `weights_only`.

## Demonstration: capability vs what ran

The `unsafe` corpus was also run through the sandbox
(`tools/sc4nconfirm`, image whose loader matrix is `torch.load`, `pickle.load`,
`joblib.load`, `numpy.load(allow_pickle=True)`, `auto_map` modules and a rendered
`chat_template`). Of the artifacts carrying `SC4N-MALICE-CONSTRUCTED`, 84 paths
resolve to **62 distinct digests** (the corpus copies one payload into several
repositories); **55 matched a scanned artifact**, the other 7 are paths the
`fetch.json` budget truncated.

| result | count | meaning |
|---|---|---|
| effects observed | **38** | `id`, `hostname`, `cat /etc/passwd`, `curl ifconfig.me`, `echo …`, writes to `/tmp/rce_proof.txt`, dials to `150.230.216.13:8080`, `136.243.156.104:27303`, `10.10.10.10:8080` |
| no loader for the type | 11 | `.zip`, `.gz`, `.nemo`, `.txt`, `.safetensors` — no user load path executes these |
| load failed before the payload | 13 | `AttributeError`/`RuntimeError`/`SystemExit`/`ModuleNotFoundError` (`xgboost`, `sklearn` absent from the image), or the loader wrote no result |

Merging the attestation takes the corpus from 306 to **344 criticals** (38
`SC4N-MALICE-DEMONSTRATED`). "Not demonstrated" is never "inert": every one of the
24 remaining runs carries its reason in the attestation, and the merge line states
how many runs matched, so an attestation that matched nothing cannot pass as a
quiet success.

## Recall

Recall is harder to measure than precision, because it needs labels. The labels
used were the Hub's own verdicts plus a per-file read of each flagged artifact
(this table is the 2026-11-05 round, whose per-file reads were done by hand and
not re-run for this page):

| measurement | result |
|---|---|
| files with a readable payload | 151 |
| files where a rule fired | **150** (99.3%) |
| documented out-of-scope miss | 1 — `nono31/malicious-models-repo/tensorflow_saved_model.pb`, a `SaveV2`/`RestoreV2` graph with no `pyfunc`, file IO or native op: nothing in it executes at load |
| unfetchable (Hub-gated) | 34, reported as gated with a reason rather than counted as clean |

One **real** false negative was found this way and fixed: a 45-byte
`compressed_joblib_marker.joblib` (zlib level 2, header `78 5e`, payload
`builtins.eval(42)`) was dispatched as a pickle through junk-prefix resync instead
of being decompressed. Two causes, both fixed: the zlib magic table listed only
levels 1/6/9 (`78 01|9c|da`), and the pickle sniffer accepted a stream that opens
with a compressor frame.

What this cannot tell you is the miss rate on an artifact nobody has labelled. That
is what `tools/sc4nlab` (the validity-oracle lab) exists for: it mutates real
artifacts, keeps only mutants an independent validator still accepts, and measures
whether a rule still fires. Its first matrix is in `docs/architecture.md`.

## Performance

Per-corpus throughput from the table above: 1.14 GiB in 5.6 s (~210 MiB/s),
2.34 GiB in 13.0 s (~185 MiB/s), 8.71 GiB in 41.3 s (~216 MiB/s) — including
hashing, on a host whose sha256 runs at 0.35 GB/s. The per-phase numbers (13 GiB
safetensors in 1.25 s at 7.8 MiB anonymous RSS, entropy at 1.65 GB/s, pickle walk
at 360 MB/s opcode-dense, indicator engine at 131 MB/s and why it is not 1 GB/s)
are in [`docs/architecture.md`](architecture.md#performance) with their measurement
conditions.

## Limits

These are the places where the numbers above are *not* evidence of absence:

- **Slices.** 271, 938 and 310 files respectively were fetched as headers and
  scanned as headers. A payload past the slice is not seen, and the finding says
  `SC4N-PARTIAL-SLICE` rather than pretending the file was complete.
- **Gated repositories.** 34 files in the unsafe corpus could not be fetched at
  all. They are reported with the gate mode and URL, never as clean.
- **Undecoded payloads.** xz, lzma, lz4, zstd, 7z and rar are recognised and
  reported as unscanned (`SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION`, and
  `SC4N-JOBLIB-UNSCANNED-PAYLOAD` for the joblib coders); the bytes are not
  guessed at, because the scanner links no decompressor beyond the standard
  library.
- **ONNX tensor payloads.** The graph, operators, external-data references and
  metadata are walked; raw tensor values are not decoded, so a backdoor encoded in
  weights is out of scope here and in the `info`-level statistics.
- **No dynamic analysis.** A critical is a statement about reachability, not about
  what happened. Only `tools/sc4nconfirm` observes effects, and only for the
  loader matrix it ships.
- **Volumes are shapes, not verdicts.** `SC4N-METADATA-CODE` at 1427 on one corpus
  is one dataset that is a list of code; a reader who triages by count alone will
  draw the wrong conclusion. The per-rule table in `campaign.md` and
  [`docs/triage.md`](triage.md) are the intended path.

## What this page does not measure

- How often sc4n is *right* about intent. A rule that fires on real code that is
  not malicious is still a true positive structurally; the corpus has plenty.
- Any other scanner's behaviour on the same bytes. Comparative numbers need the
  same labels applied to both tools, and sc4n does not link or shell out to
  another scanner by design.
- Wall time on a machine unlike the reference host. The numbers are single-host,
  warm cache, `-j` = one worker per CPU.
