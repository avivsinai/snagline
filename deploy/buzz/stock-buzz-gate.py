#!/usr/bin/env python3
"""Fail-closed deployment and live-acceptance gate for unmodified stock Buzz.

This intentionally validates only an external deployment contract.  It does
not start, patch, vendor, or otherwise change block/buzz.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from urllib.parse import urlparse


SCHEMA = "snagline.stock-buzz.deployment.v2"
EVIDENCE_SCHEMA = "snagline.stock-buzz.live-evidence.v2"
BUZZ_REPOSITORY = "https://github.com/block/buzz"
BUZZ_TAG = "v0.5.2"
BUZZ_COMMIT = "3e48f1b2365d326ee1c9582448d86a99b44ecd5d"
REQUIRED_AGENTS = frozenset(("projector", "specialist", "dispatcher"))
CHANNEL_TYPES = frozenset(("stream", "forum", "dm", "workflow"))
HEX64 = re.compile(r"^[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")
KUBERNETES_SECRET_NAME = re.compile(r"^[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?$")
KUBERNETES_SECRET_KEY = re.compile(r"^[A-Za-z0-9](?:[-A-Za-z0-9._]{0,251}[A-Za-z0-9])?$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
MAX_EVIDENCE_AGE = dt.timedelta(hours=24)
MAX_FUTURE_SKEW = dt.timedelta(minutes=5)
MAX_NIP_OA_AUTH_TAG_BYTES = 1024
ATTESTATION_SCHEMA = "snagline.dispatcher-policy-attestation.v1"
SECP256K1_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_GENERATOR = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
# These public values were previously committed as sample identities derived
# from trivial fixture secrets 1..4. They are permanently non-production even
# after callers replace every other placeholder with valid deployment data.
COMMITTED_SAMPLE_NOSTR_PUBKEYS = frozenset(
    (
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
    )
)
COMMITTED_SAMPLE_ATTESTOR_PUBLIC_KEYS = frozenset(
    ("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",)
)


class GateError(ValueError):
    pass


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def bip340_tagged_hash(tag: str, value: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + value).digest()


def secp256k1_point_add(
    left: tuple[int, int] | None, right: tuple[int, int] | None
) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    if left[0] == right[0] and (left[1] != right[1] or left[1] == 0):
        return None
    if left == right:
        slope = 3 * left[0] * left[0] * pow(2 * left[1], -1, SECP256K1_FIELD)
    else:
        slope = (right[1] - left[1]) * pow(
            right[0] - left[0], -1, SECP256K1_FIELD
        )
    slope %= SECP256K1_FIELD
    x = (slope * slope - left[0] - right[0]) % SECP256K1_FIELD
    return x, (slope * (left[0] - x) - left[1]) % SECP256K1_FIELD


def secp256k1_point_mul(
    scalar: int, point: tuple[int, int]
) -> tuple[int, int] | None:
    result = None
    addend: tuple[int, int] | None = point
    while scalar:
        if scalar & 1:
            result = secp256k1_point_add(result, addend)
        addend = secp256k1_point_add(addend, addend)
        scalar >>= 1
    return result


def secp256k1_lift_x(x: int) -> tuple[int, int] | None:
    if x >= SECP256K1_FIELD:
        return None
    square = (pow(x, 3, SECP256K1_FIELD) + 7) % SECP256K1_FIELD
    y = pow(square, (SECP256K1_FIELD + 1) // 4, SECP256K1_FIELD)
    if pow(y, 2, SECP256K1_FIELD) != square:
        return None
    return x, y if y % 2 == 0 else SECP256K1_FIELD - y


def verify_bip340(public_key: str, message: bytes, signature: object) -> bool:
    if len(message) != 32 or not isinstance(signature, str) or not HEX128.fullmatch(signature):
        return False
    public_raw = bytes.fromhex(public_key)
    signature_raw = bytes.fromhex(signature)
    public_point = secp256k1_lift_x(int.from_bytes(public_raw, "big"))
    r = int.from_bytes(signature_raw[:32], "big")
    s = int.from_bytes(signature_raw[32:], "big")
    if public_point is None or r >= SECP256K1_FIELD or s >= SECP256K1_ORDER:
        return False
    challenge = int.from_bytes(
        bip340_tagged_hash(
            "BIP0340/challenge", signature_raw[:32] + public_raw + message
        ),
        "big",
    ) % SECP256K1_ORDER
    nonce_point = secp256k1_point_add(
        secp256k1_point_mul(s, SECP256K1_GENERATOR),
        secp256k1_point_mul(SECP256K1_ORDER - challenge, public_point),
    )
    return (
        nonce_point is not None
        and nonce_point[1] % 2 == 0
        and nonce_point[0] == r
    )


def validate_nip_oa_conditions(
    conditions: str, event_kind: int | None = None, event_created_at: int | None = None
) -> None:
    if conditions == "":
        return
    for clause in conditions.split("&"):
        if clause.startswith("kind="):
            value, maximum = clause.removeprefix("kind="), 65535
            matches = event_kind is None or event_kind == int(value) if value.isdigit() else False
        elif clause.startswith("created_at<"):
            value, maximum = clause.removeprefix("created_at<"), 4294967295
            matches = event_created_at is None or event_created_at < int(value) if value.isdigit() else False
        elif clause.startswith("created_at>"):
            value, maximum = clause.removeprefix("created_at>"), 4294967295
            matches = event_created_at is None or event_created_at > int(value) if value.isdigit() else False
        else:
            raise GateError("NIP-OA conditions are invalid")
        if (
            not value
            or (len(value) > 1 and value.startswith("0"))
            or not value.isascii()
            or not value.isdigit()
            or int(value) > maximum
        ):
            raise GateError("NIP-OA conditions are invalid")
        if not matches:
            raise GateError("NIP-OA conditions do not authorize the signed profile event")


def validate_nip_oa_auth_tag(raw: object, agent_pubkey: str) -> tuple[str, list[str], str]:
    value = require_string(raw, "evidence.nip_oa_bindings[].auth_tag")
    if not value or len(value.encode()) > MAX_NIP_OA_AUTH_TAG_BYTES:
        raise GateError("live NIP-OA auth tag is invalid")
    try:
        parts = json.loads(value)
    except json.JSONDecodeError as error:
        raise GateError("live NIP-OA auth tag is invalid") from error
    if (
        not isinstance(parts, list)
        or len(parts) != 4
        or not all(isinstance(part, str) for part in parts)
        or json.dumps(parts, separators=(",", ":"), ensure_ascii=False) != value
        or parts[0] != "auth"
    ):
        raise GateError("live NIP-OA auth tag is not canonical")
    owner = require_pubkey(parts[1], "live NIP-OA owner pubkey")
    if owner == agent_pubkey or not HEX128.fullmatch(parts[3]):
        raise GateError("live NIP-OA auth tag is invalid")
    validate_nip_oa_conditions(parts[2])
    message = hashlib.sha256(
        f"nostr:agent-auth:{agent_pubkey}:{parts[2]}".encode()
    ).digest()
    if not verify_bip340(owner, message, parts[3]):
        raise GateError("live NIP-OA owner signature is invalid")
    return owner, parts, parts[2]


def parse_exact_profile_content(content: str) -> dict[str, str]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate profile field")
            result[key] = value
        return result

    try:
        profile = json.loads(content, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, ValueError) as error:
        raise GateError("signed agent profile content is invalid JSON") from error
    if not isinstance(profile, dict) or set(profile) != {"name", "display_name"}:
        raise GateError("signed agent profile must contain exactly name and display_name")
    return {
        "name": require_string(profile.get("name"), "signed agent profile.name"),
        "display_name": require_string(
            profile.get("display_name"), "signed agent profile.display_name"
        ),
    }


def validate_signed_profile_event(
    value: object,
) -> tuple[str, dict[str, str], list[list[str]], int, int]:
    event = require_object(value, "evidence.agent_profile_events[]")
    if set(event) != {"id", "pubkey", "created_at", "kind", "tags", "content", "sig"}:
        raise GateError("signed agent profile event fields are incomplete or widened")
    event_id = require_pubkey(event.get("id"), "signed agent profile event.id")
    public_key = require_pubkey(
        event.get("pubkey"), "signed agent profile event.pubkey"
    )
    created_at = event.get("created_at")
    if type(created_at) is not int or created_at < 0 or created_at > 0xFFFFFFFFFFFFFFFF:
        raise GateError("signed agent profile event.created_at must be an unsigned integer")
    if type(event.get("kind")) is not int or event.get("kind") != 0:
        raise GateError("signed agent profile event.kind must be exactly 0")
    tags = event.get("tags")
    if not isinstance(tags, list) or not all(
        isinstance(tag, list) and all(isinstance(item, str) for item in tag)
        for tag in tags
    ):
        raise GateError("signed agent profile event.tags must be Nostr string arrays")
    content = require_string(event.get("content"), "signed agent profile event.content")
    serialized = json.dumps(
        [0, public_key, created_at, 0, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    computed_id = hashlib.sha256(serialized).digest()
    if computed_id.hex() != event_id:
        raise GateError("signed agent profile event id does not match its exact Nostr serialization")
    if not verify_bip340(public_key, computed_id, event.get("sig")):
        raise GateError("signed agent profile event BIP340 signature is invalid")
    return public_key, parse_exact_profile_content(content), tags, 0, created_at


def load_json(path: str) -> object:
    try:
        with Path(path).open(encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise GateError(f"cannot read JSON: {error}") from error


def require_object(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise GateError(f"{where} must be an object")
    return value


def require_string(value: object, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise GateError(f"{where} must be a non-empty string")
    return value


def require_pubkey(value: object, where: str) -> str:
    pubkey = require_string(value, where)
    if not HEX64.fullmatch(pubkey):
        raise GateError(f"{where} must be 64 lowercase hexadecimal characters")
    return pubkey


def require_production_pubkey(value: object, where: str) -> str:
    pubkey = require_pubkey(value, where)
    if pubkey in COMMITTED_SAMPLE_NOSTR_PUBKEYS:
        raise GateError(f"{where} must not use a committed fixture/sample Nostr pubkey")
    return pubkey


def require_kubernetes_secret_key_ref(value: object, where: str) -> dict[str, str]:
    reference = require_object(value, where)
    if set(reference) != {"name", "key"}:
        raise GateError(f"{where} must be an exact Kubernetes SecretKeySelector")
    name = require_string(reference.get("name"), f"{where}.name")
    key = require_string(reference.get("key"), f"{where}.key")
    if not KUBERNETES_SECRET_NAME.fullmatch(name) or not KUBERNETES_SECRET_KEY.fullmatch(key):
        raise GateError(f"{where} must contain a valid Kubernetes Secret name and key")
    return {"name": name, "key": key}


def validate_relay(manifest: dict[str, object]) -> None:
    stock = require_object(manifest.get("stock_buzz"), "stock_buzz")
    if stock.get("repository") != BUZZ_REPOSITORY:
        raise GateError("stock_buzz.repository must pin block/buzz")
    if stock.get("tag") != BUZZ_TAG or stock.get("commit") != BUZZ_COMMIT:
        raise GateError("stock_buzz must pin v0.5.2 commit 3e48f1b2365d326ee1c9582448d86a99b44ecd5d")
    image = require_string(stock.get("relay_image"), "stock_buzz.relay_image")
    if not IMAGE.fullmatch(image):
        raise GateError("stock_buzz.relay_image must be a real immutable @sha256 digest; placeholders fail closed")

    relay = require_object(manifest.get("relay"), "relay")
    relay_url = require_string(relay.get("url"), "relay.url")
    parsed = urlparse(relay_url)
    if (
        parsed.scheme != "wss"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise GateError("relay.url must be a credential-free wss root")
    if relay.get("require_membership") is not True:
        raise GateError("relay.require_membership must be true")
    if relay.get("require_nip98") is not True:
        raise GateError("relay.require_nip98 must be true")
    if relay.get("allow_nip_oa_auth") is not True:
        raise GateError("relay.allow_nip_oa_auth must be true")
    require_production_pubkey(relay.get("owner_pubkey"), "relay.owner_pubkey")
    require_kubernetes_secret_key_ref(
        relay.get("relay_private_key_secret_key_ref"),
        "relay.relay_private_key_secret_key_ref",
    )


def validate_identities(manifest: dict[str, object]) -> dict[str, str]:
    identities = require_object(manifest.get("identities"), "identities")
    if not REQUIRED_AGENTS.issubset(identities):
        raise GateError("identities must contain projector, specialist, and dispatcher")
    pubkeys: dict[str, str] = {}
    humans: set[str] = set()
    human_display_names: set[str] = set()
    for name, raw in identities.items():
        identity = require_object(raw, f"identities.{name}")
        pubkeys[name] = require_production_pubkey(
            identity.get("pubkey"), f"identities.{name}.pubkey"
        )
        kind = identity.get("kind")
        if kind == "human":
            display_name = require_string(
                identity.get("display_name"), f"identities.{name}.display_name"
            )
            if display_name != display_name.strip() or display_name in human_display_names:
                raise GateError("human display names must be unique without surrounding whitespace")
            human_display_names.add(display_name)
            humans.add(name)
        elif kind == "agent":
            require_kubernetes_secret_key_ref(
                identity.get("private_key_secret_key_ref"),
                f"identities.{name}.private_key_secret_key_ref",
            )
            require_kubernetes_secret_key_ref(
                identity.get("nip_oa_auth_tag_secret_key_ref"),
                f"identities.{name}.nip_oa_auth_tag_secret_key_ref",
            )
        else:
            raise GateError(f"identities.{name}.kind must be human or agent")
    if not humans:
        raise GateError("at least one human identity is required")
    for name, raw in identities.items():
        identity = require_object(raw, f"identities.{name}")
        if identity.get("kind") != "agent":
            continue
        managed_by = require_string(identity.get("managed_by"), f"identities.{name}.managed_by")
        owner_pubkey = require_production_pubkey(
            identity.get("owner_pubkey"), f"identities.{name}.owner_pubkey"
        )
        if managed_by not in humans or owner_pubkey != pubkeys[managed_by]:
            raise GateError(f"identities.{name} must be NIP-OA managed by a declared human owner")
        profile = require_object(identity.get("profile"), f"identities.{name}.profile")
        if set(profile) != {"name", "display_name"}:
            raise GateError(f"identities.{name}.profile must contain exactly name and display_name")
        owner = require_object(identities[managed_by], f"identities.{managed_by}")
        owner_display_name = require_string(
            owner.get("display_name"), f"identities.{managed_by}.display_name"
        )
        for field in ("name", "display_name"):
            profile_value = require_string(profile.get(field), f"identities.{name}.profile.{field}")
            if profile_value != profile_value.strip() or owner_display_name not in profile_value:
                raise GateError(f"identities.{name}.profile.{field} must visibly name its declared human operator")
    for role in REQUIRED_AGENTS:
        if require_object(identities[role], f"identities.{role}").get("kind") != "agent":
            raise GateError(f"identities.{role} must be an agent")
    if len(set(pubkeys.values())) != len(pubkeys):
        raise GateError("all human and agent identities must be distinct")
    return pubkeys


def validate_relay_owner(manifest: dict[str, object], pubkeys: dict[str, str]) -> None:
    identities = require_object(manifest["identities"], "identities")
    human_pubkeys = {
        pubkeys[name]
        for name, identity in identities.items()
        if isinstance(identity, dict) and identity.get("kind") == "human"
    }
    relay = require_object(manifest["relay"], "relay")
    if relay.get("owner_pubkey") not in human_pubkeys:
        raise GateError("relay.owner_pubkey must equal one declared human pubkey")


def validate_channels(manifest: dict[str, object], pubkeys: dict[str, str]) -> None:
    channels = manifest.get("channels")
    if not isinstance(channels, list) or not channels:
        raise GateError("channels must be a non-empty array")
    seen: set[str] = set()
    ordinary: set[str] = set()
    for index, raw in enumerate(channels):
        channel = require_object(raw, f"channels[{index}]")
        channel_id = require_string(channel.get("id"), f"channels[{index}].id")
        if not UUID.fullmatch(channel_id) or channel_id in seen:
            raise GateError(f"channels[{index}].id must be a unique canonical UUID")
        seen.add(channel_id)
        channel_type = require_string(channel.get("type"), f"channels[{index}].type")
        if channel_type not in CHANNEL_TYPES:
            raise GateError(f"channels[{index}].type must be stream, forum, dm, or workflow")
        visibility = channel.get("visibility")
        if channel_type == "dm":
            participants = channel.get("participants")
            if (
                visibility != "private"
                or not isinstance(participants, list)
                or len(participants) != 2
                or len(set(participants)) != 2
                or not set(participants).issubset(pubkeys)
            ):
                raise GateError(f"channels[{index}] DM must be private with two declared identity names")
        else:
            if visibility != "open" or "participants" in channel or "members" in channel:
                raise GateError(f"channels[{index}] ordinary channel must be open without a private membership list")
            ordinary.add(channel_id)
    allowlists = require_object(manifest.get("official_channel_allowlists"), "official_channel_allowlists")
    if set(allowlists) != REQUIRED_AGENTS:
        raise GateError("official_channel_allowlists must contain exactly projector, specialist, and dispatcher")
    for role, raw in allowlists.items():
        if not isinstance(raw, list) or not raw or len(set(raw)) != len(raw) or not set(raw).issubset(ordinary):
            raise GateError(f"official_channel_allowlists.{role} must name unique open ordinary channels")


def validate_acp_and_tools(manifest: dict[str, object], pubkeys: dict[str, str]) -> None:
    identities = require_object(manifest["identities"], "identities")
    projector = require_object(identities["projector"], "identities.projector")
    specialist = require_object(identities["specialist"], "identities.specialist")
    if "mcp_command" in projector or "mcp_command" in specialist:
        raise GateError("only dispatcher may receive an MCP command")
    dispatcher = require_object(identities["dispatcher"], "identities.dispatcher")
    command = require_string(dispatcher.get("mcp_command"), "identities.dispatcher.mcp_command")
    if not command.startswith("/"):
        raise GateError("identities.dispatcher.mcp_command must be an absolute external runtime path")
    policy = require_object(manifest.get("external_dispatcher_tool_policy"), "external_dispatcher_tool_policy")
    tools = policy.get("allowed_tools")
    if tools != ["submit_inert_advice"]:
        raise GateError("external_dispatcher_tool_policy must allow only submit_inert_advice")
    require_string(policy.get("attestor_key_id"), "external_dispatcher_tool_policy.attestor_key_id")
    attestor_public_key = require_string(
        policy.get("attestor_public_key"),
        "external_dispatcher_tool_policy.attestor_public_key",
    )
    if attestor_public_key in COMMITTED_SAMPLE_ATTESTOR_PUBLIC_KEYS:
        raise GateError(
            "external_dispatcher_tool_policy.attestor_public_key must not use "
            "a committed fixture/sample key"
        )
    require_ed25519_public_key(
        attestor_public_key,
        "external_dispatcher_tool_policy.attestor_public_key",
    )


def require_ed25519_public_key(value: object, where: str) -> bytes:
    text = require_string(value, where)
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError as error:
        raise GateError(f"{where} must be base64url Ed25519 public key") from error
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != text:
        raise GateError(f"{where} must be canonical base64url Ed25519 public key")
    return raw


def parse_acp_config_specs(values: list[str]) -> dict[str, Path]:
    configs: dict[str, Path] = {}
    for value in values:
        role, separator, path = value.partition("=")
        candidate = Path(path)
        if (
            separator != "="
            or role not in ("specialist", "dispatcher")
            or role in configs
            or not candidate.is_absolute()
        ):
            raise GateError("--acp-config must be exactly specialist=ABSOLUTE_PATH and dispatcher=ABSOLUTE_PATH")
        configs[role] = candidate
    if set(configs) != {"specialist", "dispatcher"}:
        raise GateError("both actual specialist and dispatcher ACP config files are required")
    return configs


def parse_acp_runtime_env_specs(values: list[str]) -> dict[str, Path]:
    configs: dict[str, Path] = {}
    for value in values:
        role, separator, path = value.partition("=")
        candidate = Path(path)
        if (
            separator != "="
            or role not in ("specialist", "dispatcher")
            or role in configs
            or not candidate.is_absolute()
        ):
            raise GateError("--acp-runtime-env must be exactly specialist=ABSOLUTE_PATH and dispatcher=ABSOLUTE_PATH")
        configs[role] = candidate
    if set(configs) != {"specialist", "dispatcher"}:
        raise GateError("both actual specialist and dispatcher ACP runtime environment files are required")
    return configs


def load_exact_runtime_env(path: Path, role: str) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise GateError(f"actual {role} ACP runtime environment cannot be read") from error
    expected = {
        "BUZZ_ACP_SUBSCRIBE",
        "BUZZ_ACP_CONFIG",
        "BUZZ_ACP_RESPOND_TO",
        "BUZZ_ACP_RESPOND_TO_ALLOWLIST",
    }
    values: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if separator != "=" or key not in expected or key in values or not value or value != value.strip():
            raise GateError(f"actual {role} ACP runtime environment is not an exact unquoted KEY=value file")
        values[key] = value
    if set(values) != expected:
        raise GateError(f"actual {role} ACP runtime environment is incomplete or widened")
    return values


def validate_acp_configs(manifest: dict[str, object], configs: dict[str, Path]) -> None:
    allowlists = require_object(manifest["official_channel_allowlists"], "official_channel_allowlists")
    for role, path in configs.items():
        try:
            parsed = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            raise GateError(f"actual {role} ACP config cannot be parsed") from error
        if not isinstance(parsed, dict) or set(parsed) != {"rules"}:
            raise GateError(f"actual {role} ACP config must contain only stock [[rules]]")
        rules = parsed.get("rules")
        if not isinstance(rules, list) or not rules:
            raise GateError(f"actual {role} ACP config must contain non-empty [[rules]]")
        if len(rules) > 100:
            raise GateError(f"actual {role} ACP config exceeds stock's 100-rule limit")
        expected_channels = set(allowlists[role])
        actual_channels: set[str] = set()
        rule_names: set[str] = set()
        for rule in rules:
            rule = require_object(rule, f"actual {role} ACP rule")
            if set(rule) != {"name", "channels", "kinds", "require_mention"}:
                raise GateError(f"actual {role} ACP rule must use the exact pinned stock rule subset")
            name = require_string(rule.get("name"), f"actual {role} ACP rule.name")
            if name != name.strip() or name in rule_names:
                raise GateError(f"actual {role} ACP rule names must be unique without surrounding whitespace")
            rule_names.add(name)
            channels = rule.get("channels")
            kinds = rule.get("kinds")
            kind_is_private_message = (
                isinstance(kinds, list)
                and len(kinds) == 1
                and type(kinds[0]) is int
                and kinds[0] == 9
            )
            if (
                not isinstance(channels, list)
                or not channels
                or len(channels) != len(set(channels))
                or not all(
                    isinstance(channel, str) and UUID.fullmatch(channel)
                    for channel in channels
                )
            ):
                raise GateError(f"actual {role} ACP rule.channels must be unique canonical UUIDs")
            if (
                rule.get("require_mention") is not True
                or not kind_is_private_message
                or not set(channels).issubset(expected_channels)
                or actual_channels.intersection(channels)
            ):
                raise GateError(f"actual {role} ACP rule is widened beyond official kind-9 mentions")
            actual_channels.update(channels)
        if actual_channels != expected_channels:
            raise GateError(f"actual {role} ACP rules must cover each official channel exactly once")


def validate_acp_runtime_envs(
    pubkeys: dict[str, str],
    configs: dict[str, Path],
    runtime_envs: dict[str, Path],
) -> None:
    for role, path in runtime_envs.items():
        values = load_exact_runtime_env(path, role)
        if values["BUZZ_ACP_SUBSCRIBE"] != "config" or values["BUZZ_ACP_RESPOND_TO"] != "allowlist":
            raise GateError(
                f"actual {role} ACP runtime must select config subscriptions "
                "and the global allowlist author gate"
            )
        if values["BUZZ_ACP_CONFIG"] != str(configs[role]):
            raise GateError(f"actual {role} ACP runtime does not point to the validated config")
        raw_allowlist = values["BUZZ_ACP_RESPOND_TO_ALLOWLIST"]
        allowlist = raw_allowlist.split(",")
        expected = set(pubkeys.values()) - {pubkeys[role]}
        if (
            any(not HEX64.fullmatch(value) for value in allowlist)
            or len(allowlist) != len(set(allowlist))
            or set(allowlist) != expected
        ):
            raise GateError(
                f"actual {role} ACP runtime author allowlist must name every "
                "other declared human and agent exactly once"
            )


def validate_manifest(raw: object) -> dict[str, object]:
    manifest = require_object(raw, "manifest")
    if manifest.get("schema") != SCHEMA:
        raise GateError(f"schema must be {SCHEMA}")
    validate_relay(manifest)
    pubkeys = validate_identities(manifest)
    validate_relay_owner(manifest, pubkeys)
    validate_channels(manifest, pubkeys)
    validate_acp_and_tools(manifest, pubkeys)
    return manifest


def parse_observed_at(value: object, where: str) -> dt.datetime:
    text = require_string(value, where)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise GateError(f"{where} must be RFC3339") from error
    if parsed.tzinfo is None:
        raise GateError(f"{where} must include timezone")
    now = dt.datetime.now(dt.timezone.utc)
    instant = parsed.astimezone(dt.timezone.utc)
    if instant > now + MAX_FUTURE_SKEW or now - instant > MAX_EVIDENCE_AGE:
        raise GateError(f"{where} is outside the bounded evidence age")
    return instant


def verify_attestation(manifest: dict[str, object], value: object, evidence_observed: dt.datetime) -> None:
    attestation = require_object(value, "evidence.external_dispatcher_policy_attestation")
    expected = require_object(manifest["external_dispatcher_tool_policy"], "external_dispatcher_tool_policy")
    payload = {
        key: attestation.get(key)
        for key in (
            "schema",
            "key_id",
            "manifest_sha256",
            "dispatcher_pubkey",
            "allowed_tools",
            "observed_at",
        )
    }
    if set(attestation) != set(payload) | {"signature"} or payload["schema"] != ATTESTATION_SCHEMA:
        raise GateError("dispatcher policy attestation has invalid fields")
    if payload["key_id"] != expected["attestor_key_id"] or payload["manifest_sha256"] != digest(manifest):
        raise GateError("dispatcher policy attestation is not bound to its configured attestor and manifest")
    identities = require_object(manifest["identities"], "identities")
    if (
        payload["dispatcher_pubkey"] != identities["dispatcher"]["pubkey"]
        or payload["allowed_tools"] != expected["allowed_tools"]
    ):
        raise GateError("dispatcher policy attestation identity or exact one-tool policy differs")
    if parse_observed_at(payload["observed_at"], "dispatcher policy attestation.observed_at") != evidence_observed:
        raise GateError("dispatcher policy attestation timestamp must equal evidence.observed_at")
    signature = require_string(attestation.get("signature"), "dispatcher policy attestation.signature")
    try:
        raw_signature = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    except ValueError as error:
        raise GateError("dispatcher policy attestation signature is invalid") from error
    if len(raw_signature) != 64 or base64.urlsafe_b64encode(raw_signature).rstrip(b"=").decode() != signature:
        raise GateError("dispatcher policy attestation signature is invalid")
    raw_key = require_ed25519_public_key(
        expected["attestor_public_key"],
        "external_dispatcher_tool_policy.attestor_public_key",
    )
    der = bytes.fromhex("302a300506032b6570032100") + raw_key
    pem = b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(der) + b"-----END PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory(prefix="snagline-buzz-gate-") as directory:
        root = Path(directory)
        key_path, message_path, signature_path = root / "key.pem", root / "message", root / "signature"
        key_path.write_bytes(pem)
        message_path.write_bytes(canonical_bytes(payload))
        signature_path.write_bytes(raw_signature)
        try:
            openssl = os.environ.get("SNAGLINE_OPENSSL_BIN", "openssl")
            result = subprocess.run(
                [
                    openssl,
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(key_path),
                    "-rawin",
                    "-in",
                    str(message_path),
                    "-sigfile",
                    str(signature_path),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise GateError("dispatcher policy attestation verifier is unavailable") from error
    if result.returncode != 0:
        raise GateError("dispatcher policy attestation signature does not verify")


def validate_evidence(manifest: dict[str, object], raw: object) -> None:
    evidence = require_object(raw, "evidence")
    if evidence.get("schema") != EVIDENCE_SCHEMA:
        raise GateError(f"evidence.schema must be {EVIDENCE_SCHEMA}")
    if evidence.get("manifest_sha256") != digest(manifest):
        raise GateError("evidence is not bound to this exact manifest")
    observed_at = parse_observed_at(evidence.get("observed_at"), "evidence.observed_at")
    identities = require_object(manifest["identities"], "identities")
    channels = {entry["id"]: entry for entry in manifest["channels"] if isinstance(entry, dict)}

    if evidence.get("channel_inventory_complete") is not True:
        raise GateError("live evidence must declare a complete channel inventory")
    observed = evidence.get("channel_inventory")
    if not isinstance(observed, list) or len(observed) != len(channels):
        raise GateError("live evidence must cover every configured channel")
    actual_channels: set[str] = set()
    for entry in observed:
        value = require_object(entry, "evidence.channel_inventory[]")
        channel_id = require_string(value.get("id"), "evidence.channel_inventory[].id")
        if (
            channel_id not in channels
            or value.get("type") != channels[channel_id].get("type")
            or value.get("visibility") != channels[channel_id].get("visibility")
        ):
            raise GateError("live channel inventory differs from the manifest")
        if value.get("type") == "dm":
            if value.get("visibility") != "private":
                raise GateError("live DM channel must be private")
        elif value.get("visibility") != "open":
            raise GateError("live ordinary channel must be open")
        actual_channels.add(channel_id)
    if actual_channels != set(channels):
        raise GateError("live evidence did not cover each channel exactly once")

    human_pubkeys = {
        entry["pubkey"]
        for entry in identities.values()
        if isinstance(entry, dict) and entry.get("kind") == "human"
    }
    relay_members = evidence.get("relay_members")
    if not isinstance(relay_members, list) or set(relay_members) != human_pubkeys:
        raise GateError("live relay membership must contain exactly the declared humans")

    expected_bindings = {
        entry["pubkey"]: identities[entry["managed_by"]]["pubkey"]
        for entry in identities.values()
        if isinstance(entry, dict) and entry.get("kind") == "agent"
    }
    bindings = evidence.get("nip_oa_bindings")
    if not isinstance(bindings, list) or len(bindings) != len(expected_bindings):
        raise GateError("live evidence must cover every agent NIP-OA binding")
    actual_bindings: dict[str, str] = {}
    actual_auth_tags: dict[str, tuple[list[str], str]] = {}
    for entry in bindings:
        value = require_object(entry, "evidence.nip_oa_bindings[]")
        if set(value) != {"agent_pubkey", "auth_tag"}:
            raise GateError("live NIP-OA binding must contain exact raw credential evidence")
        agent = require_pubkey(value.get("agent_pubkey"), "evidence.nip_oa_bindings[].agent_pubkey")
        owner, auth_tag, conditions = validate_nip_oa_auth_tag(value.get("auth_tag"), agent)
        if expected_bindings.get(agent) != owner or agent in actual_bindings:
            raise GateError("live NIP-OA binding differs from the managed-by manifest")
        actual_bindings[agent] = owner
        actual_auth_tags[agent] = auth_tag, conditions
    if actual_bindings != expected_bindings:
        raise GateError("live NIP-OA evidence is incomplete")

    expected_profiles = {
        entry["pubkey"]: {
            "name": entry["profile"]["name"],
            "display_name": entry["profile"]["display_name"],
        }
        for entry in identities.values()
        if isinstance(entry, dict) and entry.get("kind") == "agent"
    }
    profile_events = evidence.get("agent_profile_events")
    if not isinstance(profile_events, list) or len(profile_events) != len(expected_profiles):
        raise GateError(
            "live evidence must include one raw signed kind-0 profile event "
            "for every declared agent"
        )
    actual_profiles: dict[str, dict[str, str]] = {}
    for raw_event in profile_events:
        agent, profile, tags, kind, created_at = validate_signed_profile_event(raw_event)
        auth_tag = actual_auth_tags.get(agent)
        if (
            expected_profiles.get(agent) != profile
            or auth_tag is None
            or tags != [auth_tag[0]]
            or agent in actual_profiles
        ):
            raise GateError(
                "live signed kind-0 agent profile does not match its declared "
                "operator-naming metadata"
            )
        validate_nip_oa_conditions(auth_tag[1], kind, created_at)
        actual_profiles[agent] = profile
    if set(actual_profiles) != set(expected_profiles):
        raise GateError("live agent profile evidence is incomplete")

    acp = require_object(evidence.get("acp_wake_reply"), "evidence.acp_wake_reply")
    if acp.get("identity") != "specialist" or acp.get("woke") is not True or acp.get("replied") is not True:
        raise GateError("live proof must show specialist ACP wake and reply")
    if acp.get("author_pubkey") != identities["specialist"]["pubkey"]:
        raise GateError("ACP reply author does not match specialist identity")
    if acp.get("channel") not in manifest["official_channel_allowlists"]["specialist"]:
        raise GateError("ACP reply was not in a specialist official channel")
    if acp.get("trigger_author_pubkey") not in human_pubkeys:
        raise GateError("ACP wake must prove a declared human can steer the specialist")
    require_pubkey(acp.get("trigger_event_id"), "evidence.acp_wake_reply.trigger_event_id")
    require_pubkey(acp.get("reply_event_id"), "evidence.acp_wake_reply.reply_event_id")

    verify_attestation(manifest, evidence.get("external_dispatcher_policy_attestation"), observed_at)


def emit(ok: bool, checks: list[str], remediation: str | None = None) -> int:
    result: dict[str, object] = {"ok": ok, "checks": checks}
    if remediation:
        result["remediation"] = remediation
    print(json.dumps(result, sort_keys=True))
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "live"))
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--evidence")
    parser.add_argument("--acp-config", action="append", default=[])
    parser.add_argument("--acp-runtime-env", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        manifest = validate_manifest(load_json(args.manifest))
        identities = validate_identities(manifest)
        acp_configs = parse_acp_config_specs(args.acp_config)
        validate_acp_configs(manifest, acp_configs)
        validate_acp_runtime_envs(identities, acp_configs, parse_acp_runtime_env_specs(args.acp_runtime_env))
        checks = [
            "pinned-stock-buzz",
            "closed-relay",
            "human-owned-nip-oa-agents",
            "open-ordinary-channels",
            "dm-only-privacy",
            "official-channel-allowlists",
            "stock-acp-rules",
            "acp-global-author-allowlist",
            "acp-human-steering",
            "dispatcher-tool-boundary",
        ]
        if args.command == "live":
            if not args.evidence:
                raise GateError("--evidence is required for the live gate")
            validate_evidence(manifest, load_json(args.evidence))
            checks.extend(
                (
                    "live-complete-channel-inventory",
                    "live-human-membership",
                    "live-nip-oa-bindings",
                    "live-agent-operator-profiles",
                    "live-human-steer-reply",
                    "live-dispatcher-tool-attestation",
                )
            )
        return emit(True, checks)
    except GateError as error:
        return emit(False, [], str(error))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
