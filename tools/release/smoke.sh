#!/bin/sh
# Artifact-level gate: the binary a user downloads must still apply the scan
# gate the tree's tests describe — benign clean, critical exits 1.
set -eu
bin=${1:?usage: smoke.sh BINARY}
root=$(cd "$(dirname "$0")/../.." && pwd)
"$bin" scan -quiet -fail-on low "$root/testdata/fixtures/benign" >/dev/null
set +e
"$bin" scan -quiet -fail-on critical "$root/testdata/fixtures/joblib_object_array.joblib" >/dev/null 2>&1
status=$?
set -e
if [ "$status" -ne 1 ]; then
	echo "smoke: the critical fixture exited $status, want 1" >&2
	exit 1
fi
echo "   benign tree clean; critical fixture exits 1"
