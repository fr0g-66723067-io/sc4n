#!/bin/sh
# Proves the tag reaches no shell before tag-check.sh has rejected it.
#
# A ref name may carry backticks or `$(...)`. When a recipe interpolated
# `$(VERSION)` into its shell text, make expanded the tag before the shell parsed
# the line, so the substitution ran first — inside the write-enabled publish job —
# and tag-check.sh, the only validator, saw the result of that execution. The
# recipes now pass the tag as `$${VERSION}`, a variable the shell substitutes
# after parsing, so the value is never read as syntax.
set -eu

cd "${1:-.}"

marker=$(mktemp -u "${TMPDIR:-/tmp}/sc4n-tagcheck.XXXXXX")
trap 'rm -f "$marker"' EXIT

hostile="v1.0.0-\`touch $marker\`"
if VERSION=$hostile make -s release-binaries >/dev/null 2>&1; then
	echo "tag-check_test: a hostile tag was accepted" >&2
	exit 1
fi
if [ -e "$marker" ]; then
	echo "tag-check_test: the tag was executed as shell before validation" >&2
	exit 1
fi

nl='
'
for bad in "1.0.0" "v1.0" "v1.0.0;id" 'v1.0.0-$(id)' "v1.0.0/../x" "v1.0.0-\`id\`" "v1.0.0${nl}\$(id)" "bad${nl}v1.0.0"; do
	if sh tools/release/tag-check.sh "$bad" >/dev/null 2>&1; then
		echo "tag-check_test: accepted $bad" >&2
		exit 1
	fi
done
sh tools/release/tag-check.sh v1.2.3-rc.1
echo "tag-check_test: ok"
