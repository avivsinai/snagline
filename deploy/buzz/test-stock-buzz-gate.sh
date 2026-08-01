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
"$openssl_bin" genpkey -algorithm ED25519 -out "$scratch/acp-observer.pem"
"$openssl_bin" pkey -in "$scratch/acp-observer.pem" -pubout -outform DER >"$scratch/acp-observer.der"

cp "$root/stock-v0.5.2-acp-rules.fixture.toml" "$scratch/specialist-acp.toml"
cp "$root/stock-v0.5.2-acp-rules.fixture.toml" "$scratch/dispatcher-acp.toml"
runtime_args=(
  --acp-runtime-env "specialist=$scratch/specialist-acp.env"
  --acp-runtime-env "dispatcher=$scratch/dispatcher-acp.env"
)
observer_challenge=5555555555555555555555555555555555555555555555555555555555555555
live_args=(--observer-challenge "$observer_challenge")

# The committed example is intentionally unlaunchable: mutable or placeholder
# image coordinates must never be mistaken for a pinned stock deployment.
if python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" >/dev/null; then
  echo "placeholder image unexpectedly passed" >&2
  exit 1
fi

python3 - "$scratch/manifest.json" "$scratch/evidence.json" "$scratch/attestor.der" "$scratch/attestation-payload.json" \
  "$scratch/acp-observer.der" "$scratch/acp-observer-payload.json" \
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


def signed_event(secret, created_at, kind, tags, content):
    public_key, _ = schnorr_sign(secret, bytes(32))
    serialized = json.dumps(
        [0, public_key, created_at, kind, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    event_id = hashlib.sha256(serialized).digest()
    _, signature = schnorr_sign(secret, event_id)
    return {
        "id": event_id.hex(),
        "pubkey": public_key,
        "created_at": created_at,
        "kind": kind,
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
    observer_key_path,
    observer_payload_path,
    placeholder_manifest_path,
    specialist_env_path,
    dispatcher_env_path,
    specialist_config_path,
    dispatcher_config_path,
) = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["stock_buzz"]["relay_image"] = "registry.example.invalid/block/buzz-relay@sha256:" + "a" * 64
manifest["stock_buzz"]["acp_image"] = "registry.example.invalid/block/buzz-acp@sha256:" + "b" * 64
policy = manifest["external_dispatcher_tool_policy"]
with open(key_path, "rb") as handle:
    attestor_public_key = base64.urlsafe_b64encode(handle.read()[-32:]).rstrip(b"=").decode()
policy["attestor_public_key"] = attestor_public_key
policy["attestor_key_id"] = "test-attestor-2026-07"
with open(observer_key_path, "rb") as handle:
    observer_public_key = base64.urlsafe_b64encode(handle.read()[-32:]).rstrip(b"=").decode()
manifest["external_acp_observer"]["public_key"] = observer_public_key
manifest["external_acp_observer"]["key_id"] = "test-acp-observer-2026-08"
manifest["external_acp_observer"]["specialist_launch_args"] = ["/usr/local/bin/buzz-acp"]
manifest["external_acp_observer"]["specialist_behavior"] = {
    "agent_command": "/opt/pi/bin/pi",
    "agent_args_sha256": "c" * 64,
    "model_config_sha256": "d" * 64,
}
with open(placeholder_manifest_path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, sort_keys=True)
identity_secrets = {}
for name in ("operator", "probe_operator", "projector", "specialist", "dispatcher"):
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
non_allowlisted_secret, non_allowlisted_pubkey = fresh_identity()
probe_auth_tag = nip_oa_auth_tag(
    non_allowlisted_pubkey, identity_secrets["probe_operator"]
)
negative_probe_profile_event = profile_event(
    {
        "pubkey": non_allowlisted_pubkey,
        "profile": {
            "name": "Negative ACP Probe - operated by Example Probe Operator",
            "display_name": "Negative ACP Probe (operated by Example Probe Operator)",
        },
    },
    non_allowlisted_secret,
    profile_created_at - 70,
    probe_auth_tag,
)
negative_trigger_event = signed_event(
    non_allowlisted_secret,
    profile_created_at - 30,
    9,
    [
        ["h", manifest["channels"][0]["id"]],
        ["p", manifest["identities"]["specialist"]["pubkey"]],
    ],
    "negative ACP allowlist probe",
)
positive_trigger_event = signed_event(
    identity_secrets["operator"],
    profile_created_at - 50,
    9,
    [
        ["h", manifest["channels"][0]["id"]],
        ["p", manifest["identities"]["specialist"]["pubkey"]],
    ],
    "positive ACP human-steering control",
)
positive_reply_event = signed_event(
    identity_secrets["specialist"],
    profile_created_at - 49,
    9,
    [
        ["h", manifest["channels"][0]["id"]],
        ["e", positive_trigger_event["id"]],
        ["p", manifest["identities"]["operator"]["pubkey"]],
    ],
    "positive ACP control reply",
)


def observed_time(offset_seconds, microseconds=0):
    return datetime.datetime.fromtimestamp(
        profile_created_at + offset_seconds + microseconds / 1_000_000,
        datetime.timezone.utc,
    ).isoformat().replace("+00:00", "Z")
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
observer_payload = {
    "schema": "snagline.acp-negative-observation-attestation.v1",
    "key_id": manifest["external_acp_observer"]["key_id"],
    "manifest_sha256": hashlib.sha256(canonical).hexdigest(),
    "buzz_relay_image": manifest["stock_buzz"]["relay_image"],
    "buzz_acp_image": manifest["stock_buzz"]["acp_image"],
    "observer_run_id": "123e4567-e89b-42d3-a456-426614174001",
    "probe_nonce": "5" * 64,
    "specialist_process_run_id": "123e4567-e89b-42d3-a456-426614174002",
    "specialist_process_started_at": observed_time(-60),
    "specialist_launch_args": manifest["external_acp_observer"]["specialist_launch_args"],
    "specialist_effective_behavior_env": {
        "acp_subscribe": "config",
        "acp_config_sha256": hashlib.sha256(
            open(specialist_config_path, "rb").read()
        ).hexdigest(),
        "acp_runtime_env_sha256": hashlib.sha256(
            open(specialist_env_path, "rb").read()
        ).hexdigest(),
        "respond_to": "allowlist",
        "respond_to_allowlist": [
            identity["pubkey"]
            for name, identity in manifest["identities"].items()
            if name != "specialist"
        ],
        "auth_tag_owner_pubkey": manifest["identities"]["operator"]["pubkey"],
        "agent_identity_pubkey": manifest["identities"]["specialist"]["pubkey"],
        "private_key_derived_pubkey": manifest["identities"]["specialist"]["pubkey"],
        "agent_command": manifest["external_acp_observer"]["specialist_behavior"]["agent_command"],
        "agent_args_sha256": manifest["external_acp_observer"]["specialist_behavior"]["agent_args_sha256"],
        "model_config_sha256": manifest["external_acp_observer"]["specialist_behavior"]["model_config_sha256"],
        "mcp_command": None,
        "agents": 1,
        "setup_payload_sha256": None,
        "lazy_pool": False,
        "relay_observer": False,
        "relay_url": manifest["relay"]["url"],
        "loaded_buzz_acp_behavior_keys": [
            "BUZZ_ACP_AGENT_ARGS",
            "BUZZ_ACP_AGENT_COMMAND",
            "BUZZ_ACP_CONFIG",
            "BUZZ_ACP_MODEL",
            "BUZZ_ACP_PRIVATE_KEY",
            "BUZZ_ACP_RESPOND_TO",
            "BUZZ_ACP_RESPOND_TO_ALLOWLIST",
            "BUZZ_ACP_SUBSCRIBE",
            "BUZZ_AUTH_TAG",
        ],
        "unexpected_buzz_acp_behavior_keys": [],
    },
    "rust_log": "debug",
    "specialist_identity": "specialist",
    "specialist_pubkey": manifest["identities"]["specialist"]["pubkey"],
    "trigger_event_id": negative_trigger_event["id"],
    "trigger_author_pubkey": non_allowlisted_pubkey,
    "channel": manifest["channels"][0]["id"],
    "relay_accepted_at": observed_time(-30),
    "observation_window_started_at": observed_time(-30),
    "author_gate_rejected_at": observed_time(-29),
    "observation_window_ended_at": observed_time(-10),
    "observation_duration_seconds": 20,
    "post_window_grace_seconds": 10,
    "specialist_acp_config_sha256": hashlib.sha256(
        open(specialist_config_path, "rb").read()
    ).hexdigest(),
    "specialist_acp_runtime_env_sha256": hashlib.sha256(
        open(specialist_env_path, "rb").read()
    ).hexdigest(),
    "author_gate_rejection_observed": True,
    "same_owner_sibling": False,
    "fresh_process_owner_cache": True,
    "probe_was_first_seen_author": True,
    "owner_query_error": False,
    "profile_lookup_capture_basis": "external-supervisor-relay-proxy",
    "profile_lookup_process_run_id": "123e4567-e89b-42d3-a456-426614174002",
    "profile_lookup_request_id": "123e4567-e89b-42d3-a456-426614174005",
    "profile_lookup_filter": {
        "authors": [non_allowlisted_pubkey],
        "kinds": [0],
        "limit": 1,
    },
    "profile_lookup_response_event_ids": [negative_probe_profile_event["id"]],
    "profile_lookup_complete": True,
    "profile_lookup_timeout": False,
    "profile_lookup_error": False,
    "probe_profile_event_id": negative_probe_profile_event["id"],
    "probe_owner_pubkey": manifest["identities"]["probe_operator"]["pubkey"],
    "capture_basis": "observer-correlated-relay-acceptance-and-acp-debug-log",
    "log_capture_complete": True,
    "log_gap_count": 0,
    "relay_lag_events": 0,
    "reconnect_count": 0,
    "process_restart_count": 0,
    "supervisor_capture_basis": "external-specialist-process-supervisor",
    "supervisor_process_run_id": "123e4567-e89b-42d3-a456-426614174002",
    "supervisor_capture_complete": True,
    "negative_window_invocation_ids": [],
    "negative_window_invocation_count": 0,
    "reply_query_complete": True,
    "reply_query_error": False,
    "reply_query_started_at": observed_time(-9),
    "reply_query_completed_at": observed_time(-1),
    "reply_query_filters": [
        {
            "authors": [manifest["identities"]["specialist"]["pubkey"]],
            "kinds": [9],
            "#e": [negative_trigger_event["id"]],
            "since": profile_created_at - 30,
            "until": profile_created_at - 9,
        },
        {
            "authors": [manifest["identities"]["specialist"]["pubkey"]],
            "kinds": [9],
            "#h": [manifest["channels"][0]["id"]],
            "since": profile_created_at - 30,
            "until": profile_created_at - 9,
        },
    ],
    "reply_query_trigger_reference_event_ids": [],
    "reply_query_channel_catchall_event_ids": [],
    "positive_control_trigger_event_id": positive_trigger_event["id"],
    "positive_control_reply_event_id": positive_reply_event["id"],
    "positive_control_same_process_run_id": "123e4567-e89b-42d3-a456-426614174002",
    "positive_control_observed": True,
    "positive_control_relay_accepted_at": observed_time(-50, 250_000),
    "positive_control_invocation_id": "123e4567-e89b-42d3-a456-426614174003",
    "positive_control_turn_triggering_event_ids": [positive_trigger_event["id"]],
    "positive_control_reply_observed_at": observed_time(-49, 500_000),
    "signed_at": observed_at,
    "observed_at": observed_at,
}
with open(observer_payload_path, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(observer_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
with open(observer_payload_path + ".message", "wb") as handle:
    handle.write(
        b"snagline:acp-negative-observation-attestation:v1\x00"
        + json.dumps(
            observer_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    )
evidence = {
    "schema": "snagline.stock-buzz.live-evidence.v3",
    "manifest_sha256": hashlib.sha256(canonical).hexdigest(),
    "observed_at": observed_at,
    "channel_inventory_complete": True,
    "channel_inventory": [
        {"id": channel["id"], "type": channel["type"], "visibility": channel["visibility"]}
        for channel in manifest["channels"]
    ],
    "relay_members": [
        identity["pubkey"]
        for identity in manifest["identities"].values()
        if identity["kind"] == "human"
    ],
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
    "acp_positive_trigger_event": positive_trigger_event,
    "acp_positive_reply_event": positive_reply_event,
    "acp_negative_trigger_event": negative_trigger_event,
    "acp_negative_probe_profile_event": negative_probe_profile_event,
    "acp_negative_observation_attestation": observer_payload,
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

mutated = copy.deepcopy(evidence)
del mutated["acp_negative_observation_attestation"]
write_negative("missing-negative-acp-attestation", mutated)

mutated = copy.deepcopy(evidence)
mutated["acp_negative_observation_attestation"] = {
    "author_gate_rejection_observed": True,
    "harness_turn_ids": [],
    "reply_event_ids": [],
}
write_negative("boolean-only-negative-acp-attestation", mutated)

mutated = copy.deepcopy(evidence)
mutated["acp_negative_trigger_event"]["content"] += " forged"
write_negative("forged-negative-acp-trigger", mutated)

same_owner_auth_tag = nip_oa_auth_tag(
    non_allowlisted_pubkey, identity_secrets["operator"]
)
mutated = copy.deepcopy(evidence)
mutated["acp_negative_probe_profile_event"] = profile_event(
    {
        "pubkey": non_allowlisted_pubkey,
        "profile": {
            "name": "Same-owner probe - operated by Example Operator",
            "display_name": "Same-owner Probe (operated by Example Operator)",
        },
    },
    non_allowlisted_secret,
    profile_created_at - 70,
    same_owner_auth_tag,
)
write_negative("same-owner-probe-profile", mutated)

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
"$openssl_bin" pkeyutl -sign -rawin -inkey "$scratch/acp-observer.pem" -in "$scratch/acp-observer-payload.json.message" -out "$scratch/acp-observer.sig"
python3 - "$scratch/evidence.json" \
  "$scratch/attestation-payload.json" "$scratch/attestation.sig" \
  "$scratch/acp-observer-payload.json" "$scratch/acp-observer.sig" <<'PY'
import base64
import json
import sys
path, payload_path, signature_path, observer_payload_path, observer_signature_path = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    evidence = json.load(handle)
with open(payload_path, encoding="utf-8") as handle:
    attestation = json.load(handle)
with open(signature_path, "rb") as handle:
    signature = base64.urlsafe_b64encode(handle.read()).rstrip(b"=").decode()
attestation["signature"] = signature
evidence["external_dispatcher_policy_attestation"] = attestation
with open(observer_payload_path, encoding="utf-8") as handle:
    observer_attestation = json.load(handle)
with open(observer_signature_path, "rb") as handle:
    observer_signature = base64.urlsafe_b64encode(handle.read()).rstrip(b"=").decode()
observer_attestation["signature"] = observer_signature
evidence["acp_negative_observation_attestation"] = observer_attestation
with open(path, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(evidence, sort_keys=True))
PY
python3 - "$scratch/evidence.json" <<'PY'
import copy
import glob
import json
import sys

base_path = sys.argv[1]
with open(base_path, encoding="utf-8") as handle:
    base = json.load(handle)
for path in glob.glob(base_path + ".*"):
    with open(path, encoding="utf-8") as handle:
        evidence = json.load(handle)
    evidence["external_dispatcher_policy_attestation"] = copy.deepcopy(
        base["external_dispatcher_policy_attestation"]
    )
    if not path.endswith(("missing-negative-acp-attestation", "boolean-only-negative-acp-attestation")):
        evidence["acp_negative_observation_attestation"] = copy.deepcopy(
            base["acp_negative_observation_attestation"]
        )
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, sort_keys=True)
PY

mkdir "$scratch/acp-observer-mutations"
python3 - "$scratch/evidence.json" "$scratch/acp-observer-mutations" <<'PY'
import copy
import datetime
import json
import pathlib
import sys

evidence_path, output_dir = sys.argv[1:]
with open(evidence_path, encoding="utf-8") as handle:
    evidence = json.load(handle)
payload = copy.deepcopy(evidence["acp_negative_observation_attestation"])
del payload["signature"]
mutations = {}


def payload_time(offset_seconds, microseconds=0):
    observed = datetime.datetime.fromisoformat(
        payload["observed_at"].replace("Z", "+00:00")
    )
    return (
        observed
        + datetime.timedelta(seconds=offset_seconds, microseconds=microseconds)
    ).isoformat().replace("+00:00", "Z")

mutated = copy.deepcopy(payload)
mutated["manifest_sha256"] = "0" * 64
mutations["unbound-manifest"] = mutated

mutated = copy.deepcopy(payload)
mutated["buzz_relay_image"] = mutated["buzz_relay_image"].replace("a" * 64, "c" * 64)
mutations["wrong-image"] = mutated

mutated = copy.deepcopy(payload)
mutated["buzz_acp_image"] = mutated["buzz_acp_image"].replace("b" * 64, "c" * 64)
mutations["wrong-acp-image"] = mutated

mutated = copy.deepcopy(payload)
mutated["specialist_acp_config_sha256"] = "0" * 64
mutations["wrong-config"] = mutated

mutated = copy.deepcopy(payload)
mutated["specialist_acp_runtime_env_sha256"] = "0" * 64
mutations["wrong-runtime-env"] = mutated

mutated = copy.deepcopy(payload)
mutated["author_gate_rejection_observed"] = False
mutations["no-author-gate-rejection"] = mutated

mutated = copy.deepcopy(payload)
mutated["same_owner_sibling"] = True
mutations["same-owner-sibling"] = mutated

mutated = copy.deepcopy(payload)
mutated["negative_window_invocation_ids"] = ["123e4567-e89b-42d3-a456-426614174004"]
mutated["negative_window_invocation_count"] = 1
mutations["observed-turn"] = mutated

mutated = copy.deepcopy(payload)
mutated["reply_query_channel_catchall_event_ids"] = ["4" * 64]
mutations["observed-reply"] = mutated

mutated = copy.deepcopy(payload)
mutated["observed_at"] = "2020-01-01T00:00:30Z"
mutated["signed_at"] = "2020-01-01T00:00:30Z"
mutated["observation_window_started_at"] = "2020-01-01T00:00:00Z"
mutated["relay_accepted_at"] = "2020-01-01T00:00:00Z"
mutated["author_gate_rejected_at"] = "2020-01-01T00:00:01Z"
mutated["observation_window_ended_at"] = "2020-01-01T00:00:20Z"
mutations["stale"] = mutated

mutated = copy.deepcopy(payload)
mutated["process_restart_count"] = 1
mutations["process-restarted"] = mutated

mutated = copy.deepcopy(payload)
mutated["log_gap_count"] = 1
mutations["log-gap"] = mutated

mutated = copy.deepcopy(payload)
mutated["reply_query_error"] = True
mutations["reply-query-error"] = mutated

mutated = copy.deepcopy(payload)
mutated["reply_query_started_at"] = payload["observation_window_ended_at"]
mutations["reply-query-start-not-after-window"] = mutated

mutated = copy.deepcopy(payload)
mutated["reply_query_completed_at"] = payload["reply_query_started_at"]
mutated["reply_query_started_at"] = payload["observed_at"]
mutations["reply-query-completed-before-start"] = mutated

mutated = copy.deepcopy(payload)
mutated["positive_control_same_process_run_id"] = "123e4567-e89b-42d3-a456-426614174099"
mutations["positive-other-process"] = mutated

mutated = copy.deepcopy(payload)
mutated["positive_control_turn_triggering_event_ids"] = []
mutations["positive-missing-turn-trigger"] = mutated

mutated = copy.deepcopy(payload)
mutated["specialist_launch_args"] = ["/tmp/not-buzz-acp"]
mutations["wrong-launch"] = mutated

mutated = copy.deepcopy(payload)
mutated["specialist_effective_behavior_env"]["unexpected_buzz_acp_behavior_keys"] = [
    "BUZZ_ACP_NO_MENTION_FILTER"
]
mutations["unexpected-behavior-env"] = mutated

mutated = copy.deepcopy(payload)
mutated["specialist_effective_behavior_env"]["relay_observer"] = True
mutations["stock-relay-observer"] = mutated

mutated = copy.deepcopy(payload)
mutated["profile_lookup_timeout"] = True
mutations["profile-timeout"] = mutated

mutated = copy.deepcopy(payload)
mutated["profile_lookup_filter"]["limit"] = 2
mutations["profile-widened-filter"] = mutated

mutated = copy.deepcopy(payload)
mutated["profile_lookup_process_run_id"] = "123e4567-e89b-42d3-a456-426614174099"
mutations["profile-other-process"] = mutated

mutated = copy.deepcopy(payload)
mutated["supervisor_capture_complete"] = False
mutations["supervisor-incomplete"] = mutated

mutated = copy.deepcopy(payload)
mutated["positive_control_relay_accepted_at"] = payload["relay_accepted_at"]
mutations["positive-accepted-too-late"] = mutated

mutated = copy.deepcopy(payload)
mutated["positive_control_reply_observed_at"] = payload["relay_accepted_at"]
mutations["positive-reply-too-late"] = mutated

mutated = copy.deepcopy(payload)
mutated["positive_control_relay_accepted_at"] = payload_time(-51, 750_000)
mutations["positive-trigger-reversed-lag"] = mutated

mutated = copy.deepcopy(payload)
mutated["positive_control_relay_accepted_at"] = payload_time(-44, 500_000)
mutated["positive_control_reply_observed_at"] = payload_time(-43, 500_000)
mutations["positive-excessive-lag"] = mutated

mutated = copy.deepcopy(payload)
mutated["probe_nonce"] = "not-a-nonce"
mutations["bad-nonce"] = mutated

mutated = copy.deepcopy(payload)
mutated["unexpected"] = True
mutations["widened"] = mutated

root = pathlib.Path(output_dir)
for name, value in mutations.items():
    (root / f"{name}.payload.json").write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
PY
for observer_payload in "$scratch"/acp-observer-mutations/*.payload.json; do
  observer_name=$(basename "$observer_payload" .payload.json)
  observer_signature="$scratch/acp-observer-mutations/$observer_name.sig"
  python3 - "$observer_payload" "$observer_payload.message" <<'PY'
import pathlib
import sys

payload_path, message_path = map(pathlib.Path, sys.argv[1:])
message_path.write_bytes(
    b"snagline:acp-negative-observation-attestation:v1\x00"
    + payload_path.read_bytes()
)
PY
  "$openssl_bin" pkeyutl -sign -rawin -inkey "$scratch/acp-observer.pem" \
    -in "$observer_payload.message" -out "$observer_signature"
  python3 - "$scratch/evidence.json" "$observer_payload" "$observer_signature" \
    "$scratch/evidence.json.observer-$observer_name" <<'PY'
import base64
import json
import sys

evidence_path, payload_path, signature_path, output_path = sys.argv[1:]
with open(evidence_path, encoding="utf-8") as handle:
    evidence = json.load(handle)
with open(payload_path, encoding="utf-8") as handle:
    attestation = json.load(handle)
with open(signature_path, "rb") as handle:
    attestation["signature"] = base64.urlsafe_b64encode(handle.read()).rstrip(b"=").decode()
evidence["acp_negative_observation_attestation"] = attestation
with open(output_path, "w", encoding="utf-8") as handle:
    json.dump(evidence, handle, sort_keys=True)
PY
done
python3 - "$scratch/evidence.json" "$scratch/evidence.json.observer-forged-signature" \
  "$scratch/evidence.json.forged-positive-control" <<'PY'
import json
import sys

input_path, output_path, forged_positive_path = sys.argv[1:]
with open(input_path, encoding="utf-8") as handle:
    evidence = json.load(handle)
evidence["acp_negative_observation_attestation"]["signature"] = "A" * 86
with open(output_path, "w", encoding="utf-8") as handle:
    json.dump(evidence, handle, sort_keys=True)
with open(input_path, encoding="utf-8") as handle:
    evidence = json.load(handle)
evidence["acp_positive_reply_event"]["content"] += " forged"
with open(forged_positive_path, "w", encoding="utf-8") as handle:
    json.dump(evidence, handle, sort_keys=True)
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
mutated = json.loads(json.dumps(manifest))
mutated["external_acp_observer"]["public_key"] = (
    "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
)
(root / "acp-observer.json").write_text(
    json.dumps(mutated, sort_keys=True), encoding="utf-8"
)
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
python3 - "$scratch/manifest.json" "$scratch/manifest.v2.json" \
  "$scratch/manifest.missing-observer.json" "$scratch/manifest.shared-observer.json" \
  "$scratch/manifest.wrong-observer-usage.json" "$scratch/manifest.widened-top.json" <<'PY'
import copy
import json
import sys

source, v2_path, missing_path, shared_path, usage_path, widened_path = sys.argv[1:]
with open(source, encoding="utf-8") as handle:
    manifest = json.load(handle)
mutated = copy.deepcopy(manifest)
mutated["schema"] = "snagline.stock-buzz.deployment.v2"
with open(v2_path, "w", encoding="utf-8") as handle:
    json.dump(mutated, handle)
mutated = copy.deepcopy(manifest)
del mutated["external_acp_observer"]
with open(missing_path, "w", encoding="utf-8") as handle:
    json.dump(mutated, handle)
mutated = copy.deepcopy(manifest)
mutated["external_acp_observer"]["key_id"] = mutated["external_dispatcher_tool_policy"]["attestor_key_id"]
mutated["external_acp_observer"]["public_key"] = mutated["external_dispatcher_tool_policy"]["attestor_public_key"]
with open(shared_path, "w", encoding="utf-8") as handle:
    json.dump(mutated, handle)
mutated = copy.deepcopy(manifest)
mutated["external_acp_observer"]["usage"] = "dispatcher-policy"
with open(usage_path, "w", encoding="utf-8") as handle:
    json.dump(mutated, handle)
mutated = copy.deepcopy(manifest)
mutated["unexpected"] = True
with open(widened_path, "w", encoding="utf-8") as handle:
    json.dump(mutated, handle)
PY
for rejected_manifest in "$scratch/manifest.v2.json" "$scratch/manifest.missing-observer.json" "$scratch/manifest.shared-observer.json" "$scratch/manifest.wrong-observer-usage.json" "$scratch/manifest.widened-top.json"; do
  if python3 "$root/stock-buzz-gate.py" validate --manifest "$rejected_manifest" \
    --acp-config "specialist=$scratch/specialist-acp.toml" \
    --acp-config "dispatcher=$scratch/dispatcher-acp.toml" \
    "${runtime_args[@]}" >/dev/null; then
    echo "obsolete or non-independent observer manifest unexpectedly passed" >&2
    exit 1
  fi
done
ln -s "$scratch/specialist-acp.toml" "$scratch/specialist-acp-link.toml"
if python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp-link.toml" \
  --acp-config "dispatcher=$scratch/dispatcher-acp.toml" \
  "${runtime_args[@]}" >/dev/null; then
  echo "symlink ACP config unexpectedly passed" >&2
  exit 1
fi
mkdir "$scratch/nonregular-acp-env"
if python3 "$root/stock-buzz-gate.py" validate --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" \
  --acp-config "dispatcher=$scratch/dispatcher-acp.toml" \
  --acp-runtime-env "specialist=$scratch/nonregular-acp-env" \
  --acp-runtime-env "dispatcher=$scratch/dispatcher-acp.env" >/dev/null; then
  echo "non-regular ACP runtime environment unexpectedly passed" >&2
  exit 1
fi
if python3 "$root/stock-buzz-gate.py" live --manifest "$scratch/manifest.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" "${live_args[@]}" >/dev/null; then
  echo "live gate unexpectedly passed without live evidence" >&2
  exit 1
fi
python3 "$root/stock-buzz-gate.py" live --manifest "$scratch/manifest.json" --evidence "$scratch/evidence.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" "${live_args[@]}" >/dev/null
if python3 "$root/stock-buzz-gate.py" live --manifest "$scratch/manifest.json" --evidence "$scratch/evidence.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null; then
  echo "live gate unexpectedly passed without a fresh observer challenge" >&2
  exit 1
fi
if python3 "$root/stock-buzz-gate.py" live --manifest "$scratch/manifest.json" --evidence "$scratch/evidence.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" \
  --observer-challenge 6666666666666666666666666666666666666666666666666666666666666666 >/dev/null; then
  echo "live gate unexpectedly passed with a mismatched observer challenge" >&2
  exit 1
fi
python3 - "$scratch/evidence.json" "$scratch/evidence.v2.json" <<'PY'
import json
import sys

source, output = sys.argv[1:]
with open(source, encoding="utf-8") as handle:
    evidence = json.load(handle)
evidence["schema"] = "snagline.stock-buzz.live-evidence.v2"
with open(output, "w", encoding="utf-8") as handle:
    json.dump(evidence, handle)
PY
python3 - "$scratch/manifest.json" "$scratch/manifest.duplicate-key.json" \
  "$scratch/evidence.json" "$scratch/evidence.duplicate-key.json" \
  "$scratch/evidence.widened-top.json" "$scratch/manifest.nested-duplicate-key.json" \
  "$scratch/evidence.nested-duplicate-key.json" <<'PY'
import json
import pathlib
import sys

manifest_path, duplicate_manifest_path, evidence_path, duplicate_evidence_path, widened_path, nested_manifest_path, nested_evidence_path = map(
    pathlib.Path, sys.argv[1:]
)
manifest_text = manifest_path.read_text(encoding="utf-8")
duplicate_manifest_path.write_text(
    manifest_text.replace('"schema":', '"schema":"duplicate","schema":', 1),
    encoding="utf-8",
)
nested_manifest_path.write_text(
    manifest_text.replace(
        '"external_acp_observer": {',
        '"external_acp_observer":{"usage":"duplicate",',
        1,
    ),
    encoding="utf-8",
)
evidence_text = evidence_path.read_text(encoding="utf-8")
duplicate_evidence_path.write_text(
    evidence_text.replace('"schema":', '"schema":"duplicate","schema":', 1),
    encoding="utf-8",
)
nested_evidence_path.write_text(
    evidence_text.replace(
        '"acp_negative_observation_attestation": {',
        '"acp_negative_observation_attestation":{"schema":"duplicate",',
        1,
    ),
    encoding="utf-8",
)
evidence = json.loads(evidence_text)
evidence["unexpected"] = True
widened_path.write_text(json.dumps(evidence), encoding="utf-8")
PY
for duplicate_manifest in "$scratch/manifest.duplicate-key.json" "$scratch/manifest.nested-duplicate-key.json"; do
  if python3 "$root/stock-buzz-gate.py" validate --manifest "$duplicate_manifest" \
    --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" >/dev/null; then
    echo "duplicate-key manifest unexpectedly passed" >&2
    exit 1
  fi
done
for rejected_evidence in "$scratch/evidence.duplicate-key.json" "$scratch/evidence.nested-duplicate-key.json" "$scratch/evidence.widened-top.json"; do
  if python3 "$root/stock-buzz-gate.py" live --manifest "$scratch/manifest.json" --evidence "$rejected_evidence" \
    --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" \
    "${runtime_args[@]}" "${live_args[@]}" >/dev/null; then
    echo "duplicate-key or widened v3 evidence unexpectedly passed" >&2
    exit 1
  fi
done
if python3 "$root/stock-buzz-gate.py" live --manifest "$scratch/manifest.json" --evidence "$scratch/evidence.v2.json" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" "${live_args[@]}" >/dev/null; then
  echo "obsolete v2 live evidence unexpectedly passed" >&2
  exit 1
fi
"$root/run-stock-buzz-live-gate.sh" --manifest "$scratch/manifest.json" --evidence "$scratch/evidence.json" \
  "${live_args[@]}" \
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" \
  "${runtime_args[@]}" >/dev/null

assert_live_rejected() {
  local evidence_path=$1
  local expected_error=$2
  local description=$3
  if python3 "$root/stock-buzz-gate.py" live --manifest "$scratch/manifest.json" --evidence "$evidence_path" \
    --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" "${live_args[@]}" \
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
assert_live_rejected \
  "$scratch/evidence.json.missing-negative-acp-attestation" \
  "v3 live evidence fields are incomplete or widened" \
  "live evidence missing the negative ACP observer attestation"
assert_live_rejected \
  "$scratch/evidence.json.boolean-only-negative-acp-attestation" \
  "ACP negative observation attestation has invalid fields" \
  "boolean-only negative ACP assertion"
assert_live_rejected \
  "$scratch/evidence.json.forged-negative-acp-trigger" \
  "signed negative ACP trigger event id does not match" \
  "forged negative ACP trigger event"
assert_live_rejected \
  "$scratch/evidence.json.same-owner-probe-profile" \
  "negative ACP probe profile owner must be a distinct declared human" \
  "cryptographically valid same-owner negative probe profile"
assert_live_rejected \
  "$scratch/evidence.json.forged-positive-control" \
  "signed positive ACP reply event id does not match" \
  "forged positive ACP control reply"
assert_live_rejected \
  "$scratch/evidence.json.observer-unbound-manifest" \
  "ACP negative observation is not bound to its observer, manifest, or Buzz image" \
  "observer-signed negative ACP observation bound to another manifest"
assert_live_rejected \
  "$scratch/evidence.json.observer-wrong-image" \
  "ACP negative observation is not bound to its observer, manifest, or Buzz image" \
  "observer-signed negative ACP observation bound to another Buzz image"
assert_live_rejected \
  "$scratch/evidence.json.observer-wrong-acp-image" \
  "ACP negative observation is not bound to its observer, manifest, or Buzz image" \
  "observer-signed negative ACP observation bound to another ACP image"
assert_live_rejected \
  "$scratch/evidence.json.observer-wrong-config" \
  "ACP negative observation is not bound to the actual specialist ACP files" \
  "observer-signed negative ACP observation bound to another ACP config"
assert_live_rejected \
  "$scratch/evidence.json.observer-wrong-runtime-env" \
  "ACP negative observation is not bound to the actual specialist ACP files" \
  "observer-signed negative ACP observation bound to another runtime env"
assert_live_rejected \
  "$scratch/evidence.json.observer-no-author-gate-rejection" \
  "ACP negative observer did not attest an author-gate rejection" \
  "negative observation without explicit author-gate rejection"
assert_live_rejected \
  "$scratch/evidence.json.observer-same-owner-sibling" \
  "ACP negative probe author is a same-owner sibling" \
  "same-owner sibling used as negative ACP author"
assert_live_rejected \
  "$scratch/evidence.json.observer-observed-turn" \
  "external supervisor recorded or failed to exclude a negative-window invocation" \
  "negative ACP observation containing a harness turn"
assert_live_rejected \
  "$scratch/evidence.json.observer-observed-reply" \
  "ACP negative observer reply query was incomplete, failed, widened, or found a reply" \
  "negative ACP observation containing a reply"
assert_live_rejected \
  "$scratch/evidence.json.observer-stale" \
  "is outside the bounded evidence age" \
  "stale observer-signed negative ACP observation"
assert_live_rejected \
  "$scratch/evidence.json.observer-process-restarted" \
  "ACP negative observation has a log gap, lag, reconnect, or process restart" \
  "negative ACP observation spanning a specialist restart"
assert_live_rejected \
  "$scratch/evidence.json.observer-log-gap" \
  "ACP negative observation has a log gap, lag, reconnect, or process restart" \
  "negative ACP observation with a debug-log capture gap"
assert_live_rejected \
  "$scratch/evidence.json.observer-reply-query-error" \
  "ACP negative observer reply query was incomplete, failed, widened, or found a reply" \
  "negative ACP observation with a failed reply query"
assert_live_rejected \
  "$scratch/evidence.json.observer-reply-query-start-not-after-window" \
  "ACP negative observation window is not bound to the trigger and evidence timestamp" \
  "reply query starting before the negative window ended"
assert_live_rejected \
  "$scratch/evidence.json.observer-reply-query-completed-before-start" \
  "ACP negative observation window is not bound to the trigger and evidence timestamp" \
  "reply query completing before it started"
assert_live_rejected \
  "$scratch/evidence.json.observer-positive-other-process" \
  "ACP positive control was not observed on the same uninterrupted process" \
  "positive control from another specialist process"
assert_live_rejected \
  "$scratch/evidence.json.observer-positive-missing-turn-trigger" \
  "ACP positive control was not observed on the same uninterrupted process" \
  "positive control invocation missing its triggering event"
assert_live_rejected \
  "$scratch/evidence.json.observer-wrong-launch" \
  "ACP negative observation is not bound to the required secret-free debug launch" \
  "negative ACP observation from different launch arguments"
assert_live_rejected \
  "$scratch/evidence.json.observer-unexpected-behavior-env" \
  "ACP negative observation normalized behavior environment differs or contains unexpected keys" \
  "negative ACP observation with an unexpected behavior-affecting env key"
assert_live_rejected \
  "$scratch/evidence.json.observer-stock-relay-observer" \
  "ACP negative observation normalized behavior environment differs or contains unexpected keys" \
  "negative ACP proof relying on stock relay observer mode"
assert_live_rejected \
  "$scratch/evidence.json.observer-profile-timeout" \
  "ACP negative probe profile lookup was incomplete, failed, or mismatched" \
  "negative ACP profile lookup timeout"
assert_live_rejected \
  "$scratch/evidence.json.observer-profile-widened-filter" \
  "ACP negative probe profile lookup was incomplete, failed, or mismatched" \
  "widened negative ACP profile lookup"
assert_live_rejected \
  "$scratch/evidence.json.observer-profile-other-process" \
  "ACP negative probe profile lookup was incomplete, failed, or mismatched" \
  "profile lookup captured from another specialist process"
assert_live_rejected \
  "$scratch/evidence.json.observer-supervisor-incomplete" \
  "external supervisor recorded or failed to exclude a negative-window invocation" \
  "incomplete external supervisor capture"
assert_live_rejected \
  "$scratch/evidence.json.observer-positive-accepted-too-late" \
  "ACP positive control was not observed on the same uninterrupted process" \
  "positive control accepted after the negative probe began"
assert_live_rejected \
  "$scratch/evidence.json.observer-positive-reply-too-late" \
  "ACP positive control was not observed on the same uninterrupted process" \
  "positive control reply observed after the negative probe began"
assert_live_rejected \
  "$scratch/evidence.json.observer-positive-trigger-reversed-lag" \
  "ACP positive control was not observed on the same uninterrupted process" \
  "positive control relay acceptance before signed trigger creation"
assert_live_rejected \
  "$scratch/evidence.json.observer-positive-excessive-lag" \
  "ACP positive control was not observed on the same uninterrupted process" \
  "positive control with excessive observer lag"
assert_live_rejected \
  "$scratch/evidence.json.observer-bad-nonce" \
  "ACP negative observation must bind distinct run IDs and a canonical nonce" \
  "negative ACP observation with a noncanonical anti-replay nonce"
assert_live_rejected \
  "$scratch/evidence.json.observer-widened" \
  "ACP negative observation attestation has invalid fields" \
  "widened observer-signed negative ACP observation"
assert_live_rejected \
  "$scratch/evidence.json.observer-forged-signature" \
  "ACP negative observation attestation signature does not verify" \
  "forged negative ACP observer signature"

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
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" "${live_args[@]}" >/dev/null; then
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
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" "${live_args[@]}" >/dev/null; then
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
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" "${live_args[@]}" >/dev/null; then
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
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" "${live_args[@]}" >/dev/null; then
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
  --acp-config "specialist=$scratch/specialist-acp.toml" --acp-config "dispatcher=$scratch/dispatcher-acp.toml" "${runtime_args[@]}" "${live_args[@]}" >/dev/null; then
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
