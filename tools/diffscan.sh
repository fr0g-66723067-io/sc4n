#!/bin/sh
# Differential check against the tools the reference host does not have.
#
# This is a manual-triage aid, not a gate: it runs fickling, picklescan and
# modelscan over the fixture corpus if they happen to be installed and prints
# each tool's verdict next to sc4n's, so a disagreement can be read by a human.
# It never runs as part of `make test`, and it never downloads anything.
#
# Usage: ./tools/diffscan.sh [fixture-dir]   (default: testdata/fixtures)

set -u

dir="${1:-testdata/fixtures}"
if [ ! -d "$dir" ]; then
	echo "diffscan: $dir is not a directory" >&2
	exit 2
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sc4n="$root/sc4n"
if [ ! -x "$sc4n" ]; then
	echo "diffscan: $sc4n is not built; run 'make build' first" >&2
	exit 2
fi

have() { command -v "$1" >/dev/null 2>&1; }

found=0
for tool in fickling picklescan modelscan; do
	have "$tool" && found=1
done
if [ "$found" -eq 0 ]; then
	echo "diffscan: none of fickling, picklescan or modelscan is installed."
	echo "diffscan: skipping loudly — this host has no Python scanner to diff against."
	echo "diffscan: sc4n's own verdicts are pinned by testdata/fixtures/expectations.json."
	exit 0
fi

echo "== sc4n =="
"$sc4n" scan -quiet -format json "$dir" | sed -n 's/.*"ruleId": "\([^"]*\)".*/\1/p' | sort | uniq -c | sort -rn

if have fickling; then
	echo "== fickling --check-safety =="
	find "$dir" -type f -name '*.pkl' -print0 2>/dev/null | xargs -0 -r -n1 fickling --check-safety 2>&1 | head -50
fi
if have picklescan; then
	echo "== picklescan =="
	picklescan --path "$dir" 2>&1 | head -50
fi
if have modelscan; then
	echo "== modelscan =="
	modelscan -p "$dir" 2>&1 | head -50
fi

echo
echo "diffscan: verdicts above are for manual triage only. A tool that reports"
echo "diffscan: nothing has not cleared the file, and a disagreement is a question"
echo "diffscan: to answer, not a bug to file."
