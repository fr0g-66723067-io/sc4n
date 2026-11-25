#!/bin/sh
# Rejects a VERSION that is not the release grammar. Every release path expands
# VERSION into a shell command line and an output path; an arbitrary string is
# how a tag becomes command injection in the privileged publish job.
set -eu

tag=${1:?usage: tag-check.sh TAG}
nl='
'
case "$tag" in
	*"$nl"*)
		echo "tag-check: tag contains newline" >&2
		exit 1
		;;
esac
printf '%s\n' "$tag" | grep -Eq \
	'^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$' || {
	echo "tag-check: $tag is not vMAJOR.MINOR.PATCH[-PRE]" >&2
	exit 1
}
