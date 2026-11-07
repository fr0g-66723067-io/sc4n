#!/bin/sh
# Verifies the release artifacts `make release-binaries` produced and, when
# asked, the release image.
#
# What this proves, and why each check is here:
#
#   - the checksum file matches the bytes (a release asset that does not verify is
#     worse than no checksum: it teaches users to ignore the check);
#   - every cross-built binary is the architecture its name claims (a mistyped
#     GOARCH produces a binary that runs on nothing, and `go build` is happy);
#   - the native binary reports the version the tag says (a stale binary is
#     indistinguishable from a correct one until a report carries the wrong
#     tool version);
#   - the native binary still finds the critical fixture and still leaves the
#     benign tree clean (the release gate, on the artifact rather than on the tree);
#   - the image reports the same version and applies the same gate.
#
# Usage: verify.sh DIST VERSION [--with-image]
# DIST may be absent when --with-image is passed (the release workflow's image job
# verifies only the image).
set -eu

dist=${1:?usage: verify.sh DIST VERSION [--with-image]}
version=${2:?usage: verify.sh DIST VERSION [--with-image]}
with_image=${3:-}

fail() { echo "verify-release: $*" >&2; exit 1; }

root=$(cd "$(dirname "$0")/../.." && pwd)

verify_artifacts() {
	[ -f "$dist/SHA256SUMS" ] || fail "no $dist/SHA256SUMS"

	echo "== checksums"
	(cd "$dist" && sha256sum -c --quiet SHA256SUMS) || fail "SHA256SUMS does not match the artifacts"
	echo "   $(grep -c . "$dist/SHA256SUMS") artifact(s) verified"

	echo "== architectures"
	for f in "$dist"/sc4n_*; do
		base=$(basename "$f")
		# sc4n_VERSION_os_arch[.exe]
		os=$(echo "$base" | awk -F_ '{print $(NF-1)}')
		arch=$(echo "$base" | sed 's/\.exe$//' | awk -F_ '{print $NF}')
		desc=$(file -b "$f")
		case "$os/$arch" in
		linux/amd64)   want='x86-64' ;;
		linux/arm64)   want='aarch64' ;;
		darwin/amd64)  want='x86_64' ;;
		darwin/arm64)  want='arm64' ;;
		windows/amd64) want='x86-64' ;;
		*) fail "unexpected target $os/$arch in $base" ;;
		esac
		case "$desc" in
		*"$want"*) : ;;
		*) fail "$base: file reports '$desc', wanted $want" ;;
		esac
		case "$os" in
		windows) case "$desc" in *PE32*) : ;; *) fail "$base is not a PE binary" ;; esac ;;
		darwin)  case "$desc" in *Mach-O*) : ;; *) fail "$base is not a Mach-O binary" ;; esac ;;
		linux)   case "$desc" in *ELF*) : ;; *) fail "$base is not an ELF binary" ;; esac ;;
		esac
		echo "   $base: $want, format ok"
	done

	native="$dist/sc4n_${version}_linux_amd64"
	if [ -f "$native" ] && [ "$(uname -s)/$(uname -m)" = "Linux/x86_64" ]; then
		echo "== native binary"
		got=$("$native" version 2>&1) || fail "version exited non-zero: $got"
		case "$got" in
		*"$version"*) : ;;
		*) fail "version reports '$got', wanted '$version'" ;;
		esac
		echo "   $got"
		"$native" scan -quiet -fail-on low "$root/testdata/fixtures/benign" >/dev/null 2>&1 ||
			fail "the benign fixture tree did not scan clean, which is a false positive in a release"
		echo "   benign tree: clean"
		if "$native" scan -quiet -fail-on critical "$root/testdata/fixtures/joblib_object_array.joblib" >/dev/null 2>&1; then
			fail "the critical fixture did not fail the run"
		fi
		echo "   critical fixture: exits 1"
	else
		echo "== native binary: skipped (not a Linux/x86_64 host, or no such artifact)"
	fi
}

verify_image() {
	image=${IMAGE:-sc4n:$version}
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
}

if [ -d "$dist" ]; then
	verify_artifacts
elif [ "$with_image" = "--with-image" ]; then
	echo "== artifacts: no $dist directory, image-only verification"
else
	fail "no $dist directory: run 'make release-binaries' first"
fi

if [ "$with_image" = "--with-image" ]; then
	verify_image
fi

echo "verify-release: ok"
