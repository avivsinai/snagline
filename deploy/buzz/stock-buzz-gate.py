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


SCHEMA = "snagline.stock-buzz.deployment.v1"
EVIDENCE_SCHEMA = "snagline.stock-buzz.live-evidence.v1"
BUZZ_REPOSITORY = "https://github.com/block/buzz"
BUZZ_TAG = "v0.5.2"
BUZZ_COMMIT = "3e48f1b2365d326ee1c9582448d86a99b44ecd5d"
ROLES = frozenset(("projector", "specialist", "dispatcher"))
HEX64 = re.compile(r"^[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")
SECRET_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{2,255}$")
MAX_EVIDENCE_AGE = dt.timedelta(hours=24)
MAX_FUTURE_SKEW = dt.timedelta(minutes=5)
ATTESTATION_SCHEMA = "snagline.dispatcher-policy-attestation.v1"


class GateError(ValueError):
    pass


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


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


def require_secret_ref(value: object, where: str) -> str:
    reference = require_string(value, where)
    if not SECRET_REF.fullmatch(reference) or HEX64.fullmatch(reference):
        raise GateError(f"{where} must be a secret reference, never key material")
    return reference


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
    if parsed.scheme != "wss" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise GateError("relay.url must be a credential-free wss root")
    if relay.get("require_membership") is not True:
        raise GateError("relay.require_membership must be true")
    if relay.get("require_nip98") is not True:
        raise GateError("relay.require_nip98 must be true")
    require_pubkey(relay.get("owner_pubkey"), "relay.owner_pubkey")
    require_secret_ref(relay.get("relay_private_key_secret_ref"), "relay.relay_private_key_secret_ref")


def validate_identities(manifest: dict[str, object]) -> dict[str, str]:
    identities = require_object(manifest.get("identities"), "identities")
    if set(identities) != ROLES:
        raise GateError("identities must contain exactly projector, specialist, and dispatcher")
    pubkeys: dict[str, str] = {}
    for role in sorted(ROLES):
        identity = require_object(identities[role], f"identities.{role}")
        pubkeys[role] = require_pubkey(identity.get("pubkey"), f"identities.{role}.pubkey")
        require_secret_ref(identity.get("private_key_secret_ref"), f"identities.{role}.private_key_secret_ref")
    if len(set(pubkeys.values())) != len(pubkeys):
        raise GateError("projector, specialist, and dispatcher must have distinct identities")
    return pubkeys


def validate_channels(manifest: dict[str, object], pubkeys: dict[str, str]) -> None:
    channels = manifest.get("channels")
    if not isinstance(channels, list) or not channels:
        raise GateError("channels must be a non-empty array")
    known = set(pubkeys.values())
    seen: set[str] = set()
    memberships: set[str] = set()
    for index, raw in enumerate(channels):
        channel = require_object(raw, f"channels[{index}]")
        channel_id = require_string(channel.get("id"), f"channels[{index}].id")
        if not UUID.fullmatch(channel_id) or channel_id in seen:
            raise GateError(f"channels[{index}].id must be a unique canonical UUID")
        seen.add(channel_id)
        if channel.get("visibility") != "private":
            raise GateError(f"channels[{index}] must be private")
        members = channel.get("members")
        if not isinstance(members, list) or len(members) < 2 or not all(isinstance(member, str) for member in members):
            raise GateError(f"channels[{index}].members must contain at least two identities")
        if len(set(members)) != len(members) or not set(members).issubset(known):
            raise GateError(f"channels[{index}].members may contain only declared agent identities")
        if pubkeys["projector"] not in members:
            raise GateError(f"channels[{index}].members must include the outbound projector identity")
        memberships.update(members)
    if memberships != known:
        raise GateError("every declared identity must be a member of at least one private channel")


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
    require_ed25519_public_key(policy.get("attestor_public_key"), "external_dispatcher_tool_policy.attestor_public_key")


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
        if separator != "=" or role not in ("specialist", "dispatcher") or role in configs or not candidate.is_absolute():
            raise GateError("--acp-config must be exactly specialist=ABSOLUTE_PATH and dispatcher=ABSOLUTE_PATH")
        configs[role] = candidate
    if set(configs) != {"specialist", "dispatcher"}:
        raise GateError("both actual specialist and dispatcher ACP config files are required")
    return configs


def validate_acp_configs(manifest: dict[str, object], pubkeys: dict[str, str], configs: dict[str, Path]) -> None:
    channels = {entry["id"]: set(entry["members"]) for entry in manifest["channels"] if isinstance(entry, dict)}
    for role, path in configs.items():
        try:
            parsed = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            raise GateError(f"actual {role} ACP config cannot be parsed") from error
        rules = parsed.get("rules") if isinstance(parsed, dict) else None
        if not isinstance(rules, list) or not rules:
            raise GateError(f"actual {role} ACP config must contain non-empty [[rules]]")
        expected_channels = {channel for channel, members in channels.items() if pubkeys[role] in members}
        actual_channels: set[str] = set()
        for rule in rules:
            rule = require_object(rule, f"actual {role} ACP rule")
            channel = require_string(rule.get("channel"), f"actual {role} ACP rule.channel")
            kinds = rule.get("kinds")
            allowlist = rule.get("respond_to_allowlist")
            kind_is_private_message = (
                isinstance(kinds, list)
                and len(kinds) == 1
                and type(kinds[0]) is int
                and kinds[0] == 9
            )
            if channel not in expected_channels or rule.get("require_mention") is not True or rule.get("respond_to") != "allowlist" or not kind_is_private_message or not isinstance(allowlist, list) or set(allowlist) != channels[channel] - {pubkeys[role]}:
                raise GateError(f"actual {role} ACP rule is widened or does not enforce private kind-9 mention allowlist")
            actual_channels.add(channel)
        if actual_channels != expected_channels or len(rules) != len(actual_channels):
            raise GateError(f"actual {role} ACP rules must cover each of its private channels exactly once")


def validate_manifest(raw: object) -> dict[str, object]:
    manifest = require_object(raw, "manifest")
    if manifest.get("schema") != SCHEMA:
        raise GateError(f"schema must be {SCHEMA}")
    validate_relay(manifest)
    pubkeys = validate_identities(manifest)
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
    payload = {key: attestation.get(key) for key in ("schema", "key_id", "manifest_sha256", "dispatcher_pubkey", "allowed_tools", "observed_at")}
    if set(attestation) != set(payload) | {"signature"} or payload["schema"] != ATTESTATION_SCHEMA:
        raise GateError("dispatcher policy attestation has invalid fields")
    if payload["key_id"] != expected["attestor_key_id"] or payload["manifest_sha256"] != digest(manifest):
        raise GateError("dispatcher policy attestation is not bound to its configured attestor and manifest")
    identities = require_object(manifest["identities"], "identities")
    if payload["dispatcher_pubkey"] != identities["dispatcher"]["pubkey"] or payload["allowed_tools"] != expected["allowed_tools"]:
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
    raw_key = require_ed25519_public_key(expected["attestor_public_key"], "external_dispatcher_tool_policy.attestor_public_key")
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
            result = subprocess.run([openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(key_path), "-rawin", "-in", str(message_path), "-sigfile", str(signature_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=5)
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
    channels = {entry["id"]: set(entry["members"]) for entry in manifest["channels"] if isinstance(entry, dict)}

    observed = evidence.get("channel_memberships")
    if not isinstance(observed, list) or len(observed) != len(channels):
        raise GateError("evidence must cover every configured private channel")
    actual_channels: set[str] = set()
    for entry in observed:
        value = require_object(entry, "evidence.channel_memberships[]")
        channel_id = require_string(value.get("channel"), "evidence.channel_memberships[].channel")
        members = value.get("members")
        if channel_id not in channels or not isinstance(members, list) or set(members) != channels[channel_id]:
            raise GateError("live channel membership differs from the agent-only manifest")
        actual_channels.add(channel_id)
    if actual_channels != set(channels):
        raise GateError("live evidence did not cover each configured channel exactly once")

    denial = require_object(evidence.get("nonmember_denial"), "evidence.nonmember_denial")
    require_pubkey(denial.get("pubkey"), "evidence.nonmember_denial.pubkey")
    if denial["pubkey"] in {entry["pubkey"] for entry in identities.values() if isinstance(entry, dict)}:
        raise GateError("nonmember denial must use an identity outside the manifest")
    if denial.get("denied") is not True or denial.get("reason") != "restricted: not a channel member":
        raise GateError("live proof must show stock Buzz denying a nonmember channel read")

    acp = require_object(evidence.get("acp_wake_reply"), "evidence.acp_wake_reply")
    if acp.get("identity") != "specialist" or acp.get("woke") is not True or acp.get("replied") is not True:
        raise GateError("live proof must show specialist ACP wake and reply")
    if acp.get("author_pubkey") != identities["specialist"]["pubkey"]:
        raise GateError("ACP reply author does not match specialist identity")
    if acp.get("channel") not in channels or identities["specialist"]["pubkey"] not in channels[acp["channel"]]:
        raise GateError("ACP reply was not in a specialist private channel")
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
    args = parser.parse_args(argv)
    try:
        manifest = validate_manifest(load_json(args.manifest))
        identities = validate_identities(manifest)
        validate_acp_configs(manifest, identities, parse_acp_config_specs(args.acp_config))
        checks = ["pinned-stock-buzz", "closed-relay", "distinct-agent-identities", "private-agent-only-channels", "acp-author-gates", "dispatcher-tool-boundary"]
        if args.command == "live":
            if not args.evidence:
                raise GateError("--evidence is required for the live gate")
            validate_evidence(manifest, load_json(args.evidence))
            checks.extend(("live-membership", "live-nonmember-denial", "live-acp-wake-reply", "live-dispatcher-tool-attestation"))
        return emit(True, checks)
    except GateError as error:
        return emit(False, [], str(error))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
