#!/usr/bin/env bash
# Run only against a separately deployed, unmodified stock block/buzz v0.5.2.
# The manifest is configuration, not a Buzz fork or a Snagline correctness path.
set -euo pipefail

usage() {
  echo "usage: $0 --manifest FILE --evidence FILE --acp-config ROLE=FILE [--acp-config ROLE=FILE]" >&2
  exit 2
}

manifest=""
evidence=""
acp_configs=()
while (($#)); do
  case "$1" in
    --manifest) manifest=${2:-}; shift 2 ;;
    --evidence) evidence=${2:-}; shift 2 ;;
    --acp-config) acp_configs+=("${2:-}"); shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$manifest" && -n "$evidence" && ${#acp_configs[@]} -eq 2 ]] || usage

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
args=(live --manifest "$manifest" --evidence "$evidence")
for config in "${acp_configs[@]}"; do args+=(--acp-config "$config"); done
exec python3 "$script_dir/stock-buzz-gate.py" "${args[@]}"
