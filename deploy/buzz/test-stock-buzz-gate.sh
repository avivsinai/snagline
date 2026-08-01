#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

openssl_bin=${SNAGLINE_OPENSSL_BIN:-openssl}
if ! "$openssl_bin" genpkey -algorithm ED25519 -out "$scratch/attestor.pem" >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1 && brew_prefix=$(brew --prefix openssl@3 2>/dev/null) && [ -x "$brew_prefix/bin/openssl" ]; then
    openssl_bin="$brew_prefix/bin/openssl"
    "$openssl_bin" genpkey -algorithm ED25519 -out "$scratch/attestor.pem" >/dev/null 2>&1
  else
    echo "OpenSSL with Ed25519 support is required; set SNAGLINE_OPENSSL_BIN" >&2
    exit 1
  fi
fi
export SNAGLINE_OPENSSL_BIN="$openssl_bin"

cp "$root/stock-buzz.manifest.example.json" "$scratch/manifest.json"
"$openssl_bin" pkey -in "$scratch/attestor.pem" -pubout -outform DER >"$scratch/attestor.der"

cat >"$scratch/specialist-acp.toml" <<'EOF'
[[rules]]
channel = "123e4567-e89b-42d3-a456-426614174000"
kinds = [9]
require_mention = true
respond_to = "allowlist"
respond_to_allowlist = [
  "1111111111111111111111111111111111111111111111111111111111111111",
  "3333333333333333333333333333333333333333333333333333333333333333"
]
EOF
cat >"$scratch/dispatcher-acp.toml" <<'EOF'
[[rules]]
channel = "123e4567-e89b-42d3-a456-426614174000"
kinds = [9]
require_mention = true
respond_to = "allowlist"
respond_to_allowlist = [
  "1111111111111111111111111111111111111111111111111111111111111111",
  "2222222222222222222222222222222222222222222222222222222222222222"
]
EOF

# The committed example is intentionally unlaunchable: mutable or placeholder
# image coordinates must never be mistaken for a pinned stock deployment.
if python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" >/dev/null; then
  echo "placeholder image unexpectedly passed" >&2
  exit 1
fi

python3 - "$scratch/manifest.json" "$scratch/evidence.json" "$scratch/attestor.der" "$scratch/attestation-payload.json" <<'PY'
import base64
import datetime
import hashlib
import json
import sys

manifest_path, evidence_path, key_path, payload_path = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["stock_buzz"]["relay_image"] = "registry.example.invalid/block/buzz-relay@sha256:" + "a" * 64
policy = manifest["external_dispatcher_tool_policy"]
with open(key_path, "rb") as handle:
    policy["attestor_public_key"] = base64.urlsafe_b64encode(handle.read()[-32:]).rstrip(b"=").decode()
policy["attestor_key_id"] = "test-attestor-2026-07"
with open(manifest_path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, sort_keys=True)
canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
members = manifest["channels"][0]["members"]
observed_at = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
payload = {
    "schema": "snagline.dispatcher-policy-attestation.v1",
    "key_id": policy["attestor_key_id"],
    "manifest_sha256": hashlib.sha256(canonical).hexdigest(),
    "dispatcher_pubkey": manifest["identities"]["dispatcher"]["pubkey"],
    "allowed_tools": policy["allowed_tools"],
    "observed_at": observed_at,
}
with open(payload_path, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
evidence = {
    "schema": "snagline.stock-buzz.live-evidence.v1",
    "manifest_sha256": hashlib.sha256(canonical).hexdigest(),
    "observed_at": observed_at,
    "channel_memberships": [{"channel": manifest["channels"][0]["id"], "members": members}],
    "nonmember_denial": {"pubkey": "f" * 64, "denied": True, "reason": "restricted: not a channel member"},
    "acp_wake_reply": {
        "identity": "specialist", "woke": True, "replied": True,
        "author_pubkey": manifest["identities"]["specialist"]["pubkey"],
        "channel": manifest["channels"][0]["id"],
        "trigger_event_id": "1" * 64, "reply_event_id": "2" * 64
    },
}
with open(evidence_path, "w", encoding="utf-8") as handle:
    json.dump(evidence, handle, sort_keys=True)
PY
"$openssl_bin" pkeyutl -sign -rawin -inkey "$scratch/attestor.pem" -in "$scratch/attestation-payload.json" -out "$scratch/attestation.sig"
python3 - "$scratch/evidence.json" "$scratch/attestation-payload.json" "$scratch/attestation.sig" <<'PY'
import base64
import json
import sys
path, payload_path, signature_path = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    evidence = json.load(handle)
with open(payload_path, encoding="utf-8") as handle:
    attestation = json.load(handle)
with open(signature_path, "rb") as handle:
    signature = base64.urlsafe_b64encode(handle.read()).rstrip(b"=").decode()
attestation["signature"] = signature
evidence["external_dispatcher_policy_attestation"] = attestation
with open(path, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(evidence, sort_keys=True))
PY

python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" \
  --acp-config "dispatcher=$scratch/dispatcher-acp.toml" >/dev/null
if python3 "$root/stock-buzz-gate.py" live --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" >/dev/null; then
  echo "live gate unexpectedly passed without live evidence" >&2
  exit 1
fi
python3 "$root/stock-buzz-gate.py" live --manifest "$scratch/manifest.json" --evidence "$scratch/evidence.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" >/dev/null

# The gate reads the actual ACP rule file; a manifest cannot paper over a
# widened rule.
sed -i.bak 's/require_mention = true/require_mention = false/' "$scratch/specialist-acp.toml"
if python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" >/dev/null; then
  echo "widened ACP rule unexpectedly passed" >&2
  exit 1
fi
mv "$scratch/specialist-acp.toml.bak" "$scratch/specialist-acp.toml"

# TOML floats compare equal to Python integers, so the gate must reject a
# numerically equal but type-wrong ACP kind.
python3 - "$scratch/specialist-acp.toml" <<'PY'
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
path.write_text(path.read_text(encoding="utf-8").replace("kinds = [9]", "kinds = [9.0]"), encoding="utf-8")
PY
if python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" >/dev/null; then
  echo "floating-point ACP kind unexpectedly passed" >&2
  exit 1
fi
python3 - "$scratch/specialist-acp.toml" <<'PY'
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
path.write_text(path.read_text(encoding="utf-8").replace("kinds = [9.0]", "kinds = [9]"), encoding="utf-8")
PY

# A self-asserted current timestamp is insufficient because it invalidates the
# signed payload; an old signed observation is rejected too.
python3 - "$scratch/evidence.json" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    evidence = json.load(handle)
evidence["observed_at"] = "2020-01-01T00:00:00Z"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(evidence, handle)
PY
if python3 "$root/stock-buzz-gate.py" live --manifest "$scratch/manifest.json" --evidence "$scratch/evidence.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" >/dev/null; then
  echo "stale signed evidence unexpectedly passed" >&2
  exit 1
fi

# An arbitrary singleton tool is not a bounded policy.
python3 - "$scratch/manifest.json" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["external_dispatcher_tool_policy"]["allowed_tools"] = ["shell"]
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle)
PY
if python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" >/dev/null; then
  echo "arbitrary singleton tool policy unexpectedly passed" >&2
  exit 1
fi
python3 - "$scratch/manifest.json" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["external_dispatcher_tool_policy"]["allowed_tools"] = ["submit_inert_advice"]
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle)
PY

# Any widening of the external tool policy invalidates the evidence binding.
python3 - "$scratch/manifest.json" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["external_dispatcher_tool_policy"]["allowed_tools"].append("forbidden")
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle)
PY
if python3 "$root/stock-buzz-gate.py" live --manifest "$scratch/manifest.json" --evidence "$scratch/evidence.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" >/dev/null; then
  echo "widened tool policy unexpectedly passed" >&2
  exit 1
fi

# A non-dispatcher cannot be given an MCP command, even before live evidence.
python3 - "$scratch/manifest.json" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["identities"]["specialist"]["mcp_command"] = "/forbidden"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle)
PY
if python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" >/dev/null; then
  echo "non-dispatcher MCP command unexpectedly passed" >&2
  exit 1
fi
