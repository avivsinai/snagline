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

cp "$root/stock-v0.5.2-acp-rules.fixture.toml" "$scratch/specialist-acp.toml"
cp "$root/stock-v0.5.2-acp-rules.fixture.toml" "$scratch/dispatcher-acp.toml"
runtime_args=(
  --acp-runtime-env "specialist=$scratch/specialist-acp.env"
  --acp-runtime-env "dispatcher=$scratch/dispatcher-acp.env"
)

# The committed example is intentionally unlaunchable: mutable or placeholder
# image coordinates must never be mistaken for a pinned stock deployment.
if python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" >/dev/null; then
  echo "placeholder image unexpectedly passed" >&2
  exit 1
fi

python3 - "$scratch/manifest.json" "$scratch/evidence.json" "$scratch/attestor.der" "$scratch/attestation-payload.json" \
  "$scratch/example-placeholder-identities.json" \
  "$scratch/specialist-acp.env" "$scratch/dispatcher-acp.env" \
  "$scratch/specialist-acp.toml" "$scratch/dispatcher-acp.toml" <<'PY'
import base64
import copy
import datetime
import hashlib
import json
import secrets
import sys

FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GENERATOR = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
COMMITTED_SAMPLE_PUBKEYS = {
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
}
ephemeral_pubkeys = set()


def point_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    if left[0] == right[0] and (left[1] != right[1] or left[1] == 0):
        return None
    if left == right:
        slope = 3 * left[0] * left[0] * pow(2 * left[1], -1, FIELD)
    else:
        slope = (right[1] - left[1]) * pow(right[0] - left[0], -1, FIELD)
    slope %= FIELD
    x = (slope * slope - left[0] - right[0]) % FIELD
    return x, (slope * (left[0] - x) - left[1]) % FIELD


def point_mul(scalar, point=GENERATOR):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def tagged_hash(tag, value):
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + value).digest()


def schnorr_sign(secret, message):
    public = point_mul(secret)
    adjusted_secret = secret if public[1] % 2 == 0 else ORDER - secret
    public_x = public[0].to_bytes(32, "big")
    auxiliary = bytes(32)
    mask = tagged_hash("BIP0340/aux", auxiliary)
    nonce_input = bytes(a ^ b for a, b in zip(adjusted_secret.to_bytes(32, "big"), mask))
    nonce = int.from_bytes(
        tagged_hash("BIP0340/nonce", nonce_input + public_x + message), "big"
    ) % ORDER
    if nonce == 0:
        raise RuntimeError("invalid deterministic test nonce")
    nonce_point = point_mul(nonce)
    if nonce_point[1] % 2:
        nonce = ORDER - nonce
        nonce_point = point_mul(nonce)
    challenge = int.from_bytes(
        tagged_hash(
            "BIP0340/challenge",
            nonce_point[0].to_bytes(32, "big") + public_x + message,
        ),
        "big",
    ) % ORDER
    signature = nonce_point[0].to_bytes(32, "big") + (
        (nonce + challenge * adjusted_secret) % ORDER
    ).to_bytes(32, "big")
    return public_x.hex(), signature.hex()


def fresh_identity():
    while True:
        secret = secrets.randbelow(ORDER - 1) + 1
        point = point_mul(secret)
        public_key = point[0].to_bytes(32, "big").hex()
        if (
            public_key not in COMMITTED_SAMPLE_PUBKEYS
            and public_key not in ephemeral_pubkeys
        ):
            ephemeral_pubkeys.add(public_key)
            return secret, public_key


def profile_event(identity, secret, created_at, auth_tag, extra_auth_tag=None):
    content = json.dumps(
        identity["profile"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    public_key, _ = schnorr_sign(secret, bytes(32))
    if public_key != identity["pubkey"]:
        raise RuntimeError("test profile signing key does not match manifest")
    tags = [json.loads(auth_tag)]
    if extra_auth_tag is not None:
        tags.append(json.loads(extra_auth_tag))
    serialized = json.dumps(
        [0, public_key, created_at, 0, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    event_id = hashlib.sha256(serialized).digest()
    _, signature = schnorr_sign(secret, event_id)
    return {
        "id": event_id.hex(),
        "pubkey": public_key,
        "created_at": created_at,
        "kind": 0,
        "tags": tags,
        "content": content,
        "sig": signature,
    }


def nip_oa_auth_tag(agent_pubkey, owner_secret, conditions=""):
    message = hashlib.sha256(
        f"nostr:agent-auth:{agent_pubkey}:{conditions}".encode()
    ).digest()
    owner_pubkey, signature = schnorr_sign(owner_secret, message)
    return json.dumps(
        ["auth", owner_pubkey, conditions, signature],
        separators=(",", ":"),
    )


(
    manifest_path,
    evidence_path,
    key_path,
    payload_path,
    placeholder_manifest_path,
    specialist_env_path,
    dispatcher_env_path,
    specialist_config_path,
    dispatcher_config_path,
) = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["stock_buzz"]["relay_image"] = "registry.example.invalid/block/buzz-relay@sha256:" + "a" * 64
policy = manifest["external_dispatcher_tool_policy"]
with open(key_path, "rb") as handle:
    attestor_public_key = base64.urlsafe_b64encode(handle.read()[-32:]).rstrip(b"=").decode()
policy["attestor_public_key"] = attestor_public_key
policy["attestor_key_id"] = "test-attestor-2026-07"
with open(placeholder_manifest_path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, sort_keys=True)
identity_secrets = {}
for name in ("operator", "projector", "specialist", "dispatcher"):
    secret, public_key = fresh_identity()
    identity_secrets[name] = secret
    manifest["identities"][name]["pubkey"] = public_key
operator_pubkey = manifest["identities"]["operator"]["pubkey"]
manifest["relay"]["owner_pubkey"] = operator_pubkey
for name in ("projector", "specialist", "dispatcher"):
    manifest["identities"][name]["owner_pubkey"] = operator_pubkey
with open(manifest_path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, sort_keys=True)
for role, env_path, config_path in (
    ("specialist", specialist_env_path, specialist_config_path),
    ("dispatcher", dispatcher_env_path, dispatcher_config_path),
):
    allowed = [
        identity["pubkey"]
        for name, identity in manifest["identities"].items()
        if name != role
    ]
    with open(env_path, "w", encoding="utf-8") as handle:
        handle.write(
            "BUZZ_ACP_SUBSCRIBE=config\n"
            f"BUZZ_ACP_CONFIG={config_path}\n"
            "BUZZ_ACP_RESPOND_TO=allowlist\n"
            f"BUZZ_ACP_RESPOND_TO_ALLOWLIST={','.join(allowed)}\n"
        )
canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
observed_at = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
profile_created_at = int(datetime.datetime.fromisoformat(observed_at.replace("Z", "+00:00")).timestamp())
auth_tags = {
    name: nip_oa_auth_tag(
        manifest["identities"][name]["pubkey"], identity_secrets["operator"]
    )
    for name in ("projector", "specialist", "dispatcher")
}
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
    "schema": "snagline.stock-buzz.live-evidence.v2",
    "manifest_sha256": hashlib.sha256(canonical).hexdigest(),
    "observed_at": observed_at,
    "channel_inventory_complete": True,
    "channel_inventory": [
        {"id": channel["id"], "type": channel["type"], "visibility": channel["visibility"]}
        for channel in manifest["channels"]
    ],
    "relay_members": [manifest["identities"]["operator"]["pubkey"]],
    "nip_oa_bindings": [
        {
            "agent_pubkey": identity["pubkey"],
            "auth_tag": auth_tags[name],
        }
        for name, identity in manifest["identities"].items()
        if identity["kind"] == "agent"
    ],
    "agent_profile_events": [
        profile_event(
            manifest["identities"][name], identity_secrets[name], profile_created_at,
            auth_tags[name]
        )
        for name in ("projector", "specialist", "dispatcher")
    ],
    "acp_wake_reply": {
        "identity": "specialist", "woke": True, "replied": True,
        "author_pubkey": manifest["identities"]["specialist"]["pubkey"],
        "trigger_author_pubkey": manifest["identities"]["operator"]["pubkey"],
        "channel": manifest["channels"][0]["id"],
        "trigger_event_id": "1" * 64, "reply_event_id": "2" * 64
    },
}
with open(evidence_path, "w", encoding="utf-8") as handle:
    json.dump(evidence, handle, sort_keys=True)

projector = manifest["identities"]["projector"]
projector_binding = next(
    index
    for index, binding in enumerate(evidence["nip_oa_bindings"])
    if binding["agent_pubkey"] == projector["pubkey"]
)
projector_profile = next(
    index
    for index, event in enumerate(evidence["agent_profile_events"])
    if event["pubkey"] == projector["pubkey"]
)


def write_negative(name, mutated):
    with open(f"{evidence_path}.{name}", "w", encoding="utf-8") as handle:
        json.dump(mutated, handle, sort_keys=True)


mutated = copy.deepcopy(evidence)
mutated["nip_oa_bindings"][projector_binding]["auth_tag"] = (
    " " + auth_tags["projector"]
)
write_negative("noncanonical-auth-tag", mutated)

mutated = copy.deepcopy(evidence)
mutated["nip_oa_bindings"][projector_binding]["auth_tag"] = nip_oa_auth_tag(
    projector["pubkey"], identity_secrets["specialist"]
)
write_negative("wrong-manifest-owner", mutated)

mutated = copy.deepcopy(evidence)
mutated["agent_profile_events"][projector_profile] = profile_event(
    projector,
    identity_secrets["projector"],
    profile_created_at,
    auth_tags["projector"],
    auth_tags["projector"],
)
write_negative("resigned-extra-auth-tag", mutated)

for name, conditions in (
    ("unauthorized-profile-kind", "kind=9"),
    ("unauthorized-profile-time", f"created_at<{profile_created_at}"),
):
    restrictive_auth_tag = nip_oa_auth_tag(
        projector["pubkey"], identity_secrets["operator"], conditions
    )
    mutated = copy.deepcopy(evidence)
    mutated["nip_oa_bindings"][projector_binding]["auth_tag"] = restrictive_auth_tag
    mutated["agent_profile_events"][projector_profile] = profile_event(
        projector,
        identity_secrets["projector"],
        profile_created_at,
        restrictive_auth_tag,
    )
    write_negative(name, mutated)
PY

if python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/example-placeholder-identities.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" \
  --acp-config "dispatcher=$scratch/dispatcher-acp.toml" \
  "${runtime_args[@]}" >"$scratch/example-placeholder-result.json"; then
  echo "real image and valid attestor admitted example identity placeholders" >&2
  exit 1
fi
if ! grep -q '64 lowercase hexadecimal characters' "$scratch/example-placeholder-result.json"; then
  echo "example identity placeholders did not fail as invalid public keys" >&2
  exit 1
fi
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

# A real immutable image and a valid, unrelated external attestor must not make
# any previously committed fixture identity launchable. Exercise every old
# identity fingerprint, the relay-owner position, and every declared agent's
# owner_pubkey position independently.
mkdir "$scratch/sample-identities"
python3 - "$scratch/manifest.json" "$scratch/sample-identities" <<'PY'
import json
import pathlib
import sys

manifest_path, output_dir = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as handle:
    manifest = json.load(handle)
samples = {
    "operator": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "projector": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    "specialist": "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    "dispatcher": "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
}
root = pathlib.Path(output_dir)
for role, public_key in samples.items():
    mutated = json.loads(json.dumps(manifest))
    mutated["identities"][role]["pubkey"] = public_key
    (root / f"identity-{role}.json").write_text(
        json.dumps(mutated, sort_keys=True), encoding="utf-8"
    )
sample_values = tuple(samples.values())
agent_roles = [
    role
    for role, identity in manifest["identities"].items()
    if identity.get("kind") == "agent"
]
for index, role in enumerate(agent_roles):
    mutated = json.loads(json.dumps(manifest))
    mutated["identities"][role]["owner_pubkey"] = sample_values[
        index % len(sample_values)
    ]
    (root / f"agent-owner-{role}.json").write_text(
        json.dumps(mutated, sort_keys=True), encoding="utf-8"
    )
mutated = json.loads(json.dumps(manifest))
mutated["relay"]["owner_pubkey"] = samples["operator"]
(root / "relay-owner.json").write_text(json.dumps(mutated, sort_keys=True), encoding="utf-8")
mutated = json.loads(json.dumps(manifest))
mutated["external_dispatcher_tool_policy"]["attestor_public_key"] = (
    "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
)
(root / "attestor.json").write_text(json.dumps(mutated, sort_keys=True), encoding="utf-8")
PY
for sample_manifest in "$scratch"/sample-identities/*.json; do
  if python3 "$root/stock-buzz-gate.py" validate --manifest "$sample_manifest" \
    --acp-config "specialist=$scratch/specialist-acp.toml" \
    --acp-config "dispatcher=$scratch/dispatcher-acp.toml" \
    "${runtime_args[@]}" >"$scratch/sample-identity-result.json"; then
    echo "real image and valid attestor admitted $(basename "$sample_manifest")" >&2
    exit 1
  fi
  if ! grep -q 'committed fixture/sample' "$scratch/sample-identity-result.json"; then
    echo "$(basename "$sample_manifest") did not hit the explicit sample-key rejection" >&2
    exit 1
  fi
done

python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" \
  --acp-config "dispatcher=$scratch/dispatcher-acp.toml" \
  "${runtime_args[@]}" >/dev/null
if python3 "$root/stock-buzz-gate.py" live --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null; then
  echo "live gate unexpectedly passed without live evidence" >&2
  exit 1
fi
python3 "$root/stock-buzz-gate.py" live --manifest "$scratch/manifest.json" --evidence "$scratch/evidence.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null
"$root/run-stock-buzz-live-gate.sh" --manifest "$scratch/manifest.json" --evidence "$scratch/evidence.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" \
  "${runtime_args[@]}" >/dev/null

assert_live_rejected() {
  local evidence_path=$1
  local expected_error=$2
  local description=$3
  if python3 "$root/stock-buzz-gate.py" live --manifest "$scratch/manifest.json" --evidence "$evidence_path" \
    --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" \
    >"$scratch/nip-oa-negative-result.json"; then
    echo "$description unexpectedly passed" >&2
    exit 1
  fi
  if ! grep -Fq "$expected_error" "$scratch/nip-oa-negative-result.json"; then
    echo "$description failed for the wrong reason" >&2
    exit 1
  fi
}

assert_live_rejected \
  "$scratch/evidence.json.noncanonical-auth-tag" \
  "live NIP-OA auth tag is not canonical" \
  "noncanonical raw NIP-OA credential"
assert_live_rejected \
  "$scratch/evidence.json.wrong-manifest-owner" \
  "live NIP-OA binding differs from the managed-by manifest" \
  "cryptographically valid NIP-OA credential from the wrong manifest owner"
assert_live_rejected \
  "$scratch/evidence.json.resigned-extra-auth-tag" \
  "live signed kind-0 agent profile does not match" \
  "re-signed profile carrying an extra auth tag"
assert_live_rejected \
  "$scratch/evidence.json.unauthorized-profile-kind" \
  "NIP-OA conditions do not authorize the signed profile event" \
  "NIP-OA kind condition that excludes the profile"
assert_live_rejected \
  "$scratch/evidence.json.unauthorized-profile-time" \
  "NIP-OA conditions do not authorize the signed profile event" \
  "NIP-OA created_at condition that excludes the profile"

# The live gate must verify the raw owner-signed NIP-OA credential itself.
# A caller assertion cannot turn a forged signature into evidence of the
# agent-to-human ownership binding.
cp "$scratch/evidence.json" "$scratch/evidence.before-forged-nip-oa.json"
python3 - "$scratch/evidence.json" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    evidence = json.load(handle)
auth_tag = json.loads(evidence["nip_oa_bindings"][0]["auth_tag"])
auth_tag[3] = "0" * 128
evidence["nip_oa_bindings"][0]["auth_tag"] = json.dumps(
    auth_tag, separators=(",", ":")
)
with open(path, "w", encoding="utf-8") as handle:
    json.dump(evidence, handle)
PY
if python3 "$root/stock-buzz-gate.py" live --manifest "$scratch/manifest.json" --evidence "$scratch/evidence.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null; then
  echo "caller-asserted forged NIP-OA credential unexpectedly passed" >&2
  exit 1
fi
mv "$scratch/evidence.before-forged-nip-oa.json" "$scratch/evidence.json"

# A raw signed kind-0 profile must expose the exact name and display_name that
# identify its declared human operator. Mutating signed content while retaining
# the claimed event ID and signature is rejected.
cp "$scratch/evidence.json" "$scratch/evidence.before-profile.json"
python3 - "$scratch/evidence.json" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    evidence = json.load(handle)
evidence["agent_profile_events"][0]["content"] = json.dumps({
    "name": "Anonymous projector",
    "display_name": "Anonymous projector",
}, separators=(",", ":"))
with open(path, "w", encoding="utf-8") as handle:
    json.dump(evidence, handle)
PY
if python3 "$root/stock-buzz-gate.py" live --manifest "$scratch/manifest.json" --evidence "$scratch/evidence.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null; then
  echo "forged agent profile event unexpectedly passed" >&2
  exit 1
fi
mv "$scratch/evidence.before-profile.json" "$scratch/evidence.json"

cp "$scratch/evidence.json" "$scratch/evidence.before-profile-signature.json"
python3 - "$scratch/evidence.json" <<'PY'
import hashlib
import json
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    evidence = json.load(handle)
event = evidence["agent_profile_events"][0]
event["content"] = json.dumps({
    "name": "Anonymous projector",
    "display_name": "Anonymous projector",
}, separators=(",", ":"))
serialized = json.dumps(
    [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]],
    separators=(",", ":"),
    ensure_ascii=False,
).encode()
event["id"] = hashlib.sha256(serialized).hexdigest()
with open(path, "w", encoding="utf-8") as handle:
    json.dump(evidence, handle)
PY
if python3 "$root/stock-buzz-gate.py" live --manifest "$scratch/manifest.json" --evidence "$scratch/evidence.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null; then
  echo "agent profile with forged content and event id unexpectedly passed" >&2
  exit 1
fi
mv "$scratch/evidence.before-profile-signature.json" "$scratch/evidence.json"

# DMs are the only private channels. They remain valid when their two
# participants are declared identities in the same community.
cp "$scratch/manifest.json" "$scratch/manifest.before-dm.json"
python3 - "$scratch/manifest.json" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["channels"].append({
    "id": "223e4567-e89b-42d3-a456-426614174000",
    "name": "operator-specialist-dm",
    "type": "dm",
    "visibility": "private",
    "participants": ["operator", "specialist"],
})
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle)
PY
python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null
mv "$scratch/manifest.before-dm.json" "$scratch/manifest.json"

# The pinned stock enum is exact. Unknown channel types are not treated as
# ordinary channels merely because their visibility is open.
cp "$scratch/manifest.json" "$scratch/manifest.before-channel-type.json"
python3 - "$scratch/manifest.json" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["channels"][0]["type"] = "chat"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle)
PY
if python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null; then
  echo "unknown stock channel type unexpectedly passed" >&2
  exit 1
fi
mv "$scratch/manifest.before-channel-type.json" "$scratch/manifest.json"

# Relay owner is a real community operator, never an undeclared key.
cp "$scratch/manifest.json" "$scratch/manifest.before-relay-owner.json"
python3 - "$scratch/manifest.json" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["relay"]["owner_pubkey"] = "f" * 64
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle)
PY
if python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null; then
  echo "undeclared relay owner unexpectedly passed" >&2
  exit 1
fi
mv "$scratch/manifest.before-relay-owner.json" "$scratch/manifest.json"

# Fresh deployment policy: private ordinary channels are forbidden. Privacy is
# reserved for DMs, while official and free-discussion channels stay open.
cp "$scratch/manifest.json" "$scratch/manifest.before-private-channel.json"
python3 - "$scratch/manifest.json" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["channels"][0]["visibility"] = "private"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle)
PY
if python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null; then
  echo "private ordinary channel unexpectedly passed" >&2
  exit 1
fi
mv "$scratch/manifest.before-private-channel.json" "$scratch/manifest.json"

# Every agent must declare a human owner and a file-backed NIP-OA credential.
cp "$scratch/manifest.json" "$scratch/manifest.before-managed-by.json"
python3 - "$scratch/manifest.json" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    manifest = json.load(handle)
del manifest["identities"]["specialist"]["managed_by"]
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle)
PY
if python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null; then
  echo "unmanaged agent unexpectedly passed" >&2
  exit 1
fi
mv "$scratch/manifest.before-managed-by.json" "$scratch/manifest.json"

# The gate reads the actual ACP rule file; a manifest cannot paper over a
# widened rule.
sed -i.bak 's/require_mention = true/require_mention = false/' "$scratch/specialist-acp.toml"
if python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null; then
  echo "widened ACP rule unexpectedly passed" >&2
  exit 1
fi
mv "$scratch/specialist-acp.toml.bak" "$scratch/specialist-acp.toml"

# Respond-to fields are global CLI/env settings in stock v0.5.2. The obsolete
# per-rule shape must not be mistaken for a real author gate.
cp "$scratch/specialist-acp.toml" "$scratch/specialist-acp.before-invented-rule.toml"
printf '\nrespond_to = "allowlist"\n' >>"$scratch/specialist-acp.toml"
if python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null; then
  echo "invented per-rule respond_to schema unexpectedly passed" >&2
  exit 1
fi
mv "$scratch/specialist-acp.before-invented-rule.toml" "$scratch/specialist-acp.toml"

cp "$scratch/specialist-acp.env" "$scratch/specialist-acp.before-widened-env"
sed -i.bak 's/BUZZ_ACP_RESPOND_TO=allowlist/BUZZ_ACP_RESPOND_TO=anyone/' "$scratch/specialist-acp.env"
if python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null; then
  echo "widened global ACP author gate unexpectedly passed" >&2
  exit 1
fi
mv "$scratch/specialist-acp.before-widened-env" "$scratch/specialist-acp.env"
rm "$scratch/specialist-acp.env.bak"

# TOML floats compare equal to Python integers, so the gate must reject a
# numerically equal but type-wrong ACP kind.
python3 - "$scratch/specialist-acp.toml" <<'PY'
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
path.write_text(path.read_text(encoding="utf-8").replace("kinds = [9]", "kinds = [9.0]"), encoding="utf-8")
PY
if python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null; then
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
cp "$scratch/evidence.json" "$scratch/evidence.before-stale.json"
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
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null; then
  echo "stale signed evidence unexpectedly passed" >&2
  exit 1
fi
mv "$scratch/evidence.before-stale.json" "$scratch/evidence.json"

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
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null; then
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
cp "$scratch/manifest.json" "$scratch/manifest.before-widened-policy.json"
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
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null; then
  echo "widened tool policy unexpectedly passed" >&2
  exit 1
fi
mv "$scratch/manifest.before-widened-policy.json" "$scratch/manifest.json"

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
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null; then
  echo "non-dispatcher MCP command unexpectedly passed" >&2
  exit 1
fi
