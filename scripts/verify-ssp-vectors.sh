#!/bin/sh
set -eu

# Keep verification hermetic: importing the checked-in lock checker from its
# test must not leave interpreter cache artifacts in the source tree.
export PYTHONDONTWRITEBYTECODE=1

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
repo_root=$(CDPATH= cd "$script_dir/.." && pwd)
vector_dir="$repo_root/docs/ssp/vectors"
requirements_source="$vector_dir/generator/requirements.txt"
requirements_lock="$vector_dir/generator/requirements.lock"
requirements_source_reference="docs/ssp/vectors/generator/requirements.txt"
requirements_checker="$vector_dir/generator/check_lock.py"
requirements_checker_tests="$vector_dir/generator/test_check_lock.py"
timestamp_corpus="$vector_dir/timestamp-v1-corpus.json"
verify_at="2026-07-28T12:00:00Z"
go_cmd=${GO:-go}
python_cmd=${PYTHON:-python3}
uv_cmd=${UV:-uv}

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/snagline-ssp-vectors.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
verifier="$tmp_dir/snagline-ssp-verify"
venv="$tmp_dir/venv"

require_file() {
	if [ ! -r "$1" ]; then
		printf '%s\n' "missing required SSP vector fixture: $1" >&2
		exit 1
	fi
}

require_python_312() {
	if ! python_version=$("$python_cmd" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")' 2>/dev/null); then
		printf '%s\n' "SSP vector dependency verification requires Python 3.12; PYTHON=$python_cmd is not usable" >&2
		exit 1
	fi
	if [ "$python_version" != "3.12" ]; then
		printf '%s\n' "SSP vector dependency verification requires Python 3.12; PYTHON=$python_cmd reports $python_version" >&2
		exit 1
	fi
}

check_dependency_lock() {
	"$python_cmd" "$requirements_checker_tests"
	"$python_cmd" "$requirements_checker" "$requirements_source" "$requirements_lock" \
		--source-reference "$requirements_source_reference" \
		--uv "$uv_cmd"
}

run_verified() {
	fixture="$1"
	public_key="$2"
	key_id="$3"
	if ! output=$("$verifier" --public-key "$public_key" --key-id "$key_id" --now "$verify_at" < "$fixture"); then
		printf '%s\n' "expected verification success for $fixture" >&2
		printf '%s\n' "$output" >&2
		exit 1
	fi
	if [ "$output" != '{"ok":true,"code":"verified"}' ]; then
		printf '%s\n' "unexpected verifier output for $fixture: $output" >&2
		exit 1
	fi
}

run_rejected() {
	fixture="$1"
	public_key="$2"
	key_id="$3"
	if output=$("$verifier" --public-key "$public_key" --key-id "$key_id" --now "$verify_at" < "$fixture"); then
		printf '%s\n' "expected verification failure for $fixture" >&2
		printf '%s\n' "$output" >&2
		exit 1
	fi
	if [ "$output" != '{"ok":false,"code":"verification_failed"}' ]; then
		printf '%s\n' "unexpected rejection output for $fixture: $output" >&2
		exit 1
	fi
}

require_file "$vector_dir/edge-public-key.txt"
require_file "$vector_dir/dispatcher-public-key.txt"
require_file "$vector_dir/registry-pinned-public-key.txt"
require_file "$vector_dir/case-v1.signed.json"
require_file "$vector_dir/advice-v1.signed.json"
require_file "$vector_dir/case-v1-tampered-routing-epoch.json"
require_file "$vector_dir/case-v1-duplicate-key.json"
require_file "$vector_dir/registry-v1.signed.json"
require_file "$vector_dir/registry-v1-header-body-revision-mismatch.signed.json"
require_file "$requirements_source"
require_file "$requirements_lock"
require_file "$requirements_checker"
require_file "$requirements_checker_tests"
require_file "$timestamp_corpus"

require_python_312
case "$#" in
	0)
		;;
	1)
		if [ "$1" != "--check-python-dependency-lock" ]; then
			printf '%s\n' "usage: $0 [--check-python-dependency-lock]" >&2
			exit 2
		fi
		check_dependency_lock
		printf '%s\n' 'SSP Python dependency lock verified'
		exit 0
		;;
	*)
		printf '%s\n' "usage: $0 [--check-python-dependency-lock]" >&2
		exit 2
		;;
esac

check_dependency_lock

edge_public_key=$(tr -d '\r\n' < "$vector_dir/edge-public-key.txt")
dispatcher_public_key=$(tr -d '\r\n' < "$vector_dir/dispatcher-public-key.txt")
registry_pinned_public_key=$(tr -d '\r\n' < "$vector_dir/registry-pinned-public-key.txt")
if [ -z "$edge_public_key" ] ||
	[ -z "$dispatcher_public_key" ] ||
	[ -z "$registry_pinned_public_key" ]; then
	printf '%s\n' 'SSP vector public key is empty' >&2
	exit 1
fi

cd "$repo_root"
"$go_cmd" build -o "$verifier" ./cmd/snagline-ssp-verify

run_verified "$vector_dir/case-v1.signed.json" "$edge_public_key" "edge-key-2026-07"
run_verified "$vector_dir/advice-v1.signed.json" "$dispatcher_public_key" "dispatcher-key-2026-07"
run_rejected "$vector_dir/case-v1-tampered-routing-epoch.json" "$edge_public_key" "edge-key-2026-07"
run_rejected "$vector_dir/case-v1-duplicate-key.json" "$edge_public_key" "edge-key-2026-07"

# The registry family is implemented in Go, so the Go verifier — not only the
# Python checker — must accept the signed snapshot and reject a body that
# contradicts its signed header.
run_verified "$vector_dir/registry-v1.signed.json" "$registry_pinned_public_key" "registry-pinned-key-2026-07"
run_rejected "$vector_dir/registry-v1-header-body-revision-mismatch.signed.json" "$registry_pinned_public_key" "registry-pinned-key-2026-07"

"$python_cmd" -m venv "$venv"
"$venv/bin/python" -m pip install \
	--disable-pip-version-check \
	--quiet \
	--only-binary=:all: \
	--require-hashes \
	-r "$requirements_lock"
"$venv/bin/python" "$vector_dir/generator/generate.py" --check

printf '%s\n' 'SSP vectors verified'
