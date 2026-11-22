#!/bin/sh
# Verifies the local release image (the image is not published). It must report
# the same version and apply the same scan gate as the binary: --network=none,
# --read-only and a non-root user bound what the scanner may read and write.
#
# Usage: image-check.sh BIN VERSION
set -eu

bin=${1:?usage: image-check.sh BIN VERSION}
version=${2:?usage: image-check.sh BIN VERSION}
image=${IMAGE:-$bin:$version}
root=$(cd "$(dirname "$0")/../.." && pwd)
fail() { echo "verify-image: $*" >&2; exit 1; }

echo "== image $image"
got=$(docker run --rm --network=none --read-only --tmpfs /tmp "$image" version 2>&1) ||
	fail "the image's version exited non-zero: $got"
case "$got" in
*"$version"*) : ;;
*) fail "image version reports '$got', wanted '$version'" ;;
esac
echo "   $got"
docker run --rm --network=none --read-only --tmpfs /tmp \
	--user "$(id -u):$(id -g)" \
	-v "$root/testdata/fixtures/benign:/scan:ro" "$image" \
	scan -quiet -fail-on low /scan >/dev/null 2>&1 ||
	fail "the image did not scan the benign tree clean"
echo "   benign tree: clean"
set +e
docker run --rm --network=none --read-only --tmpfs /tmp \
	--user "$(id -u):$(id -g)" \
	-v "$root/testdata/fixtures:/scan:ro" "$image" \
	scan -quiet -fail-on critical /scan/joblib_object_array.joblib >/dev/null 2>&1
status=$?
set -e
[ "$status" -eq 1 ] || fail "the image run on the critical fixture exited $status, want 1"
echo "   critical fixture: exits 1"
echo "verify-image: ok"
