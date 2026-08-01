#!/usr/bin/env bash
set -euo pipefail

mode="${1:-tree}"
gitleaks_bin="${GITLEAKS:-gitleaks}"

if ! command -v "$gitleaks_bin" >/dev/null 2>&1; then
  echo "gitleaks is required. Install it, or set GITLEAKS=/path/to/gitleaks." >&2
  exit 127
fi

case "$mode" in
  tree|current)
    "$gitleaks_bin" dir --no-banner --redact=100 --log-level warn .
    ;;
  history|private-history)
    "$gitleaks_bin" git --no-banner --redact=100 --log-level warn --log-opts="--all" .
    ;;
  *)
    echo "usage: $0 [tree|history]" >&2
    exit 2
    ;;
esac
