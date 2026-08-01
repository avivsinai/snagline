#!/usr/bin/env python3
"""Generate and independently validate the three live SSP v1 vector families."""
import argparse
import base64
import copy
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
SAFE_INTEGER = (1 << 53) - 1
PINNED = "registry-pinned-key-2026-07"
FAMILIES = (("registry-v1", PINNED), ("case-v1", "edge-key-2026-07"), ("advice-v1", "dispatcher-key-2026-07"))
KEY_FILES = {PINNED: "registry-pinned-public-key.txt", "registry-key-2026-07": "registry-public-key.txt", "edge-key-2026-07": "edge-public-key.txt", "dispatcher-key-2026-07": "dispatcher-public-key.txt"}
DERIVED = ("case-v1-tampered-routing-epoch.json", "registry-v1-header-body-revision-mismatch.signed.json", "case-v1-mismatched-registry-revision.signed.json", "advice-v1-mismatched-registry-hash.signed.json")
FILES = tuple(name for family, _ in FAMILIES for name in (f"{family}.signing-input.json", f"{family}.signing-input.jcs", f"{family}.signed.json")) + ("case-v1-duplicate-key.json", *DERIVED, "registry-v1.commitment.txt", *KEY_FILES.values())
VERIFY_AT = dt.datetime(2026, 7, 28, 12, 0, tzinfo=dt.timezone.utc)

def duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value: raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value

def load(path): return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=duplicates)
def quote(value):
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value): raise ValueError("unpaired surrogate")
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
def jcs(value):
    if value is None: return "null"
    if value is True: return "true"
    if value is False: return "false"
    if isinstance(value, str): return quote(value)
    if isinstance(value, int):
        if not -SAFE_INTEGER <= value <= SAFE_INTEGER: raise ValueError("unsafe integer")
        return str(value)
    if isinstance(value, float): raise ValueError("floats are forbidden")
    if isinstance(value, list): return "[" + ",".join(jcs(item) for item in value) + "]"
    if isinstance(value, dict): return "{" + ",".join(quote(key) + ":" + jcs(value[key]) for key in sorted(value, key=lambda key: key.encode("utf-16be"))) + "}"
    raise ValueError("unsupported JSON value")
def signing_bytes(envelope):
    unsigned = dict(envelope); unsigned.pop("signature", None)
    return jcs(unsigned).encode()
def wire(value): return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode() + b"\n"
def text(raw): return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
def private(label): return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(SEED + b"snagline-ssp-v1-vector:" + label.encode()).digest())
def public(key): return text(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
def signed(key, envelope):
    output = dict(envelope); output["signature"] = text(key.sign(signing_bytes(envelope))); return output
def commitment(envelope): return "sha256:" + hashlib.sha256(signing_bytes(envelope)).hexdigest()
def schema(root, family): return Draft202012Validator(load(root.parent / f"{family}.schema.json"), format_checker=FormatChecker())
def validate(root, family, envelope):
    errors = list(schema(root, family).iter_errors(envelope))
    if errors: raise ValueError(f"{family} schema: {errors[0].message}")
def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z", value): raise ValueError("invalid timestamp")
    try: return dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error: raise ValueError("invalid timestamp") from error
def verify(key, envelope):
    raw = envelope["signature"].encode(); signature = base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4)); key.verify(signature, signing_bytes(envelope))

def maps(registry):
    body = registry["body"]
    def index(records, field):
        result = {record[field]: record for record in records}
        if len(result) != len(records): raise ValueError(f"duplicate registry {field}")
        return result
    return {"routes": index(body["domains"], "domain"), "principals": index(body["principals"], "principal_id"), "edges": index(body["edges"], "edge_id"), "keys": index(body["keys"], "key_id")}

def validate_authority(inputs, keys):
    registry, case, advice = (inputs[family] for family, _ in FAMILIES)
    if registry["registry_revision"] != registry["body"]["revision"] or registry["routing_epoch"] != registry["body"]["routing_epoch"]: raise ValueError("registry header/body mismatch")
    previous = registry["body"]["previous_commitment"]
    if previous is not None and (not isinstance(previous, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", previous)): raise ValueError("registry previous commitment mismatch")
    state = maps(registry)
    for item in inputs.values():
        if not timestamp(item["emitted_at"]) <= VERIFY_AT < timestamp(item["expires_at"]): raise ValueError("fixture not live at verification time")
    for item in (case, advice):
        if (item["registry_revision"], item["registry_hash"]) != (registry["registry_revision"], commitment(registry)): raise ValueError("registry binding mismatch")
    edge = state["edges"].get(case["body"]["issuer_edge_id"]); route = state["routes"].get(case["body"]["domain"]); key = state["keys"].get(case["author_key_id"])
    if not edge or not route or not key or edge["generation"] != case["body"]["issuer_edge_generation"] or edge["edge_id"] not in route["issuer_edge_ids"] or "ssp.case.v1" not in route["families"] or key["usage"] != "edge" or key["principal_id"] != edge["principal_id"]: raise ValueError("case authority mismatch")
    advice_key = state["keys"].get(advice["author_key_id"])
    if advice["body"]["case_commitment"] != commitment(case) or not advice_key or advice_key["usage"] != "advice" or advice_key["principal_id"] != route["dispatcher_principal_id"] or "ssp.advice.v1" not in route["families"]: raise ValueError("advice authority mismatch")
    for key_id, item in state["keys"].items():
        if item["public_key"] != public(keys[key_id].public_key()): raise ValueError("registry public key mismatch")

def derived(inputs, keys):
    case = copy.deepcopy(inputs["case-v1"]); case["routing_epoch"] += 1
    mismatch_case = copy.deepcopy(inputs["case-v1"]); mismatch_case["registry_revision"] += 1
    mismatch_advice = copy.deepcopy(inputs["advice-v1"]); mismatch_advice["registry_hash"] = "sha256:" + "f" * 64
    registry = copy.deepcopy(inputs["registry-v1"]); registry["body"]["revision"] += 1
    return {"case-v1-tampered-routing-epoch.json": wire(dict(signed(keys["edge-key-2026-07"], case), signature=inputs["case-v1"].get("signature", ""))), "case-v1-mismatched-registry-revision.signed.json": wire(signed(keys["edge-key-2026-07"], mismatch_case)), "advice-v1-mismatched-registry-hash.signed.json": wire(signed(keys["dispatcher-key-2026-07"], mismatch_advice)), "registry-v1-header-body-revision-mismatch.signed.json": wire(signed(keys[PINNED], registry))}

def manifest(root): return "".join(f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}\n" for name in FILES)
def write(root, keys):
    inputs = {family: load(root / f"{family}.signing-input.json") for family, _ in FAMILIES}
    for family, key_id in FAMILIES:
        (root / f"{family}.signing-input.jcs").write_bytes(signing_bytes(inputs[family]) + b"\n")
        (root / f"{family}.signed.json").write_bytes(wire(signed(keys[key_id], inputs[family])))
    signed_inputs = {family: signed(keys[key_id], inputs[family]) for family, key_id in FAMILIES}
    for name, value in derived(signed_inputs, keys).items(): (root / name).write_bytes(value)
    (root / "registry-v1.commitment.txt").write_text(commitment(signed_inputs["registry-v1"]) + "\n")
    for key_id, filename in KEY_FILES.items(): (root / filename).write_text(public(keys[key_id].public_key()) + "\n")
    (root / "SHA256SUMS").write_text(manifest(root))

def check(root, keys):
    for name in FILES:
        if not (root / name).is_file(): raise ValueError(f"missing fixture: {name}")
    inputs = {}; signed_inputs = {}
    for family, key_id in FAMILIES:
        source = load(root / f"{family}.signing-input.json"); signed_value = signed(keys[key_id], source)
        if (root / f"{family}.signing-input.jcs").read_bytes() != signing_bytes(source) + b"\n": raise ValueError(f"{family} JCS mismatch")
        if (root / f"{family}.signed.json").read_bytes() != wire(signed_value): raise ValueError(f"{family} signed wire mismatch")
        verify(keys[key_id].public_key(), signed_value); validate(root, family, signed_value); inputs[family] = signed_value; signed_inputs[family] = signed_value
    validate_authority(inputs, keys)
    if (root / "registry-v1.commitment.txt").read_text() != commitment(inputs["registry-v1"]) + "\n": raise ValueError("registry commitment mismatch")
    for name, value in derived(signed_inputs, keys).items():
        if (root / name).read_bytes() != value: raise ValueError(f"derived fixture mismatch: {name}")
    duplicate = (root / "case-v1-duplicate-key.json").read_text()
    try: json.loads(duplicate, object_pairs_hook=duplicates)
    except ValueError: pass
    else: raise ValueError("duplicate-key fixture accepted")
    if (root / "SHA256SUMS").read_text() != manifest(root): raise ValueError("SHA256SUMS mismatch")

def main():
    parser = argparse.ArgumentParser(); group = parser.add_mutually_exclusive_group(required=True); group.add_argument("--check", action="store_true"); group.add_argument("--write", action="store_true"); args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent; keys = {key_id: private(key_id) for key_id in KEY_FILES}
    if args.write: write(root, keys); print("SSP vectors regenerated")
    else: check(root, keys); print("independent SSP vector evidence verified")
if __name__ == "__main__":
    try: main()
    except (OSError, ValueError, json.JSONDecodeError, InvalidSignature) as error: print(f"verify-ssp-vectors: {error}", file=sys.stderr); sys.exit(1)
