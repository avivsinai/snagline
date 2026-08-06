#!/bin/sh
set -eu

version=v0.11.0
archive="shellcheck-${version}.linux.x86_64.tar.xz"
archive_sha256=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
destination=${1:?"usage: $0 ABSOLUTE_DESTINATION"}

case "$destination" in
/*) ;;
*)
	printf '%s\n' "destination must be absolute" >&2
	exit 2
	;;
esac

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
	printf '%s\n' "the pinned installer supports Linux x86_64 only" >&2
	exit 2
fi

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

curl --fail --location --silent --show-error \
	--output "$work_dir/$archive" \
	"https://github.com/koalaman/shellcheck/releases/download/${version}/${archive}"
printf '%s  %s\n' "$archive_sha256" "$work_dir/$archive" | sha256sum --check --status
tar -xJf "$work_dir/$archive" -C "$work_dir"
mkdir -p "$(dirname "$destination")"
install -m 0755 "$work_dir/shellcheck-${version}/shellcheck" "$destination"
"$destination" --version | grep -Fx "version: ${version#v}" >/dev/null
