#!/usr/bin/env python3
"""Check an SSP dependency lock's direct pins and resolver-derived closure."""

import argparse
import re
import subprocess
import tempfile
from pathlib import Path


NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
VERSION = r"[0-9]+(?:\.[0-9]+)*"
SOURCE_REQUIREMENT = re.compile(rf"^({NAME})==({VERSION})$")
MARKER_ATOM = r"[A-Za-z_][A-Za-z0-9_]*\s*(?:==|!=|<=|>=|<|>)\s*'[^']+'"
MARKER = rf"(?:\s*;\s*{MARKER_ATOM}(?:\s+(?:and|or)\s+{MARKER_ATOM})*)?"
LOCK_REQUIREMENT = re.compile(rf"^({NAME})==({VERSION})(?P<marker>{MARKER})\s+\\$")
HASH = re.compile(r"^--hash=sha256:[0-9a-f]{64}(?P<continued>\s+\\)?$")
UV_VERSION = "0.11.10"
UV_VERSION_OUTPUT = re.compile(rf"^uv {re.escape(UV_VERSION)}(?: \([^)]+\))?$")


class LockCheckError(ValueError):
    """The checked-in dependency source and lock disagree."""


def normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def direct_requirements(source_path):
    direct = {}
    for line_number, raw in enumerate(source_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        comment_index = raw.find("#")
        if comment_index >= 0:
            if comment_index == 0 or not raw[comment_index - 1].isspace():
                raise LockCheckError(
                    f"unsupported direct dependency in {source_path}:{line_number}; expected exact immutable name==version pin; exact unconditional direct dependency required"
                )
            line = raw[:comment_index].strip()
        match = SOURCE_REQUIREMENT.fullmatch(line)
        if not match:
            raise LockCheckError(
                f"unsupported direct dependency in {source_path}:{line_number}; expected exact immutable name==version pin; exact unconditional direct dependency required"
            )
        name, version = match.groups()
        key = normalized(name)
        if key in direct:
            raise LockCheckError(f"duplicate direct dependency in {source_path}: {key}")
        direct[key] = version
    return direct


def lock_blocks(lock_path):
    blocks = []
    current = None

    def finish_current():
        nonlocal current
        if current is None:
            return
        validate_lock_block(current, lock_path)
        blocks.append(current)
        current = None

    for line_number, raw in enumerate(lock_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line:
            finish_current()
            continue
        if raw[0].isspace():
            if current is None:
                raise LockCheckError(f"detached lock continuation/comment in {lock_path}:{line_number}")
            if line.startswith("#"):
                current["comment_started"] = True
                current["lines"].append(("comment", line[1:].strip()))
            else:
                if current["comment_started"]:
                    raise LockCheckError(
                        f"lock continuation after provenance/comment in {lock_path}:{line_number}"
                    )
                if not HASH.fullmatch(line):
                    raise LockCheckError(f"malformed hash continuation in lock {lock_path}:{line_number}: {line}")
                current["lines"].append(("continuation", line))
            continue
        if raw.startswith("#"):
            finish_current()
            if line.startswith("# via") or line.startswith("# -r "):
                raise LockCheckError(f"detached provenance comment in {lock_path}:{line_number}")
            continue
        finish_current()
        requirement = LOCK_REQUIREMENT.fullmatch(line)
        if not requirement:
            raise LockCheckError(
                f"unsupported lock requirement header in {lock_path}:{line_number}; expected exact immutable pinned requirement with a continuation backslash: {line}"
            )
        current = {"header": line, "requirement": requirement, "lines": [], "comment_started": False}
    finish_current()
    return blocks


def has_direct_provenance(block, source_reference):
    comments = [line for kind, line in block["lines"] if kind == "comment"]
    single = f"via -r {source_reference}"
    multiline = ("via", f"-r {source_reference}")
    if comments == [single]:
        return True
    if tuple(comments) == multiline:
        return True
    if single in comments or f"-r {source_reference}" in comments:
        raise LockCheckError(f"ambiguous direct provenance for {source_reference}: {comments}")
    return False


def validate_lock_block(block, lock_path):
    continuations = [line for kind, line in block["lines"] if kind == "continuation"]
    if not continuations:
        raise LockCheckError(f"lock requirement in {lock_path} has no hashes")
    for index, continuation in enumerate(continuations):
        match = HASH.fullmatch(continuation)
        if not match:
            raise LockCheckError(
                f"lock requirement in {lock_path} has malformed hash/continuation: {continuation}"
            )
        continued = match.group("continued") is not None
        if index < len(continuations) - 1 and not continued:
            raise LockCheckError(f"lock requirement in {lock_path} intermediate hash must end with a backslash")
        if index == len(continuations) - 1 and continued:
            raise LockCheckError(f"lock requirement in {lock_path} final hash must not end with a backslash")


def direct_lock_requirements(lock_path, source_reference):
    direct = {}
    for block in lock_blocks(lock_path):
        if not has_direct_provenance(block, source_reference):
            continue
        match = block["requirement"]
        if match.group("marker"):
            raise LockCheckError(
                f"direct lock dependency in {lock_path} must be an exact immutable unconditional name==version pin: {block['header']}"
            )
        name = match.group(1)
        version = match.group(2)
        key = normalized(name)
        if key in direct:
            raise LockCheckError(f"duplicate direct dependency in {lock_path}: {key}")
        direct[key] = version
    return direct


def canonical_lock_blocks(lock_path):
    """Return the ordered requirement headers and hashes, excluding comments."""
    return tuple(
        (
            block["header"],
            tuple(line for kind, line in block["lines"] if kind == "continuation"),
        )
        for block in lock_blocks(lock_path)
    )


def require_uv_version(uv_command):
    try:
        completed = subprocess.run(
            [uv_command, "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise LockCheckError(f"required uv {UV_VERSION} is unavailable: {error}") from error
    except subprocess.CalledProcessError as error:
        raise LockCheckError(f"required uv {UV_VERSION} failed to report its version") from error
    output = completed.stdout.strip()
    if not UV_VERSION_OUTPUT.fullmatch(output):
        raise LockCheckError(f"required uv version is {UV_VERSION}; got {output!r}")


def resolver_lock(source_path, lock_path, uv_command):
    require_uv_version(uv_command)
    with tempfile.TemporaryDirectory(prefix="snagline-ssp-lock-") as directory:
        generated_lock = Path(directory) / "requirements.lock"
        try:
            subprocess.run(
                [
                    uv_command,
                    "pip",
                    "compile",
                    "--universal",
                    "--python-version",
                    "3.12",
                    "--generate-hashes",
                    "--no-annotate",
                    "--constraint",
                    str(lock_path),
                    str(source_path),
                    "-o",
                    str(generated_lock),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        except OSError as error:
            raise LockCheckError(f"required uv {UV_VERSION} is unavailable: {error}") from error
        except subprocess.CalledProcessError as error:
            detail = error.stderr.strip() or error.stdout.strip()
            raise LockCheckError(f"uv failed to resolve dependency closure: {detail}") from error
        return canonical_lock_blocks(generated_lock)


def require_matching_closure(checked, generated):
    if checked != generated:
        raise LockCheckError(
            "requirements.lock does not exactly match the pinned uv resolver closure "
            "(ordered requirement headers and hashes)"
        )


def require_resolver_closure(source_path, lock_path, uv_command):
    require_matching_closure(
        canonical_lock_blocks(lock_path),
        resolver_lock(source_path, lock_path, uv_command),
    )


def validate_lock(source_path, lock_path, source_reference=None, uv_command=None):
    source_path = Path(source_path)
    lock_path = Path(lock_path)
    source_reference = source_reference or source_path.name
    source = direct_requirements(source_path)
    locked = direct_lock_requirements(lock_path, source_reference)

    missing = sorted(set(source) - set(locked))
    extra = sorted(set(locked) - set(source))
    version_drift = sorted(
        f"{name}: requirements.txt={source[name]}, requirements.lock={locked[name]}"
        for name in set(source) & set(locked)
        if source[name] != locked[name]
    )
    if missing or extra or version_drift:
        details = []
        if missing:
            details.append("missing from lock: " + ", ".join(missing))
        if extra:
            details.append("absent from source: " + ", ".join(extra))
        details.extend(version_drift)
        raise LockCheckError("requirements source/lock sync failed: " + "; ".join(details))
    if uv_command is not None:
        require_resolver_closure(source_path, lock_path, uv_command)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("lock", type=Path)
    parser.add_argument("--source-reference", required=True)
    parser.add_argument("--uv", default="uv")
    args = parser.parse_args()
    validate_lock(args.source, args.lock, args.source_reference, args.uv)


if __name__ == "__main__":
    try:
        main()
    except (OSError, LockCheckError) as error:
        raise SystemExit(error)
