#!/usr/bin/env python3
"""Build a deterministic, non-authoritative API from verified immutable DOGG Git bytes."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import types
import unicodedata
import uuid


ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "_work"
API = ROOT / "api"
SOURCE_REPOSITORY = "https://github.com/kody-w/dogg.git"
SOURCE_WEB = "https://github.com/kody-w/dogg"
CANONICAL_REF = "refs/remotes/origin/main"
PROFILE = "dogg/0-static-api-provenance/1"
SCHEMA = "dogg/0-static-api"
WINDOW = 1440
MAX_RECORD_BYTES = 1024 * 1024
MAX_EPOCH_SIZE = 288
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
SAFE_PATH = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")
SOURCE_IDENTIFIER = re.compile(r"[A-Za-z0-9]+(?:[_-][A-Za-z0-9]+)*")
MAX_SOURCE_IDENTIFIER_BYTES = 128
WINDOWS_RESERVED_NAMES = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}
PROJECTION_RESERVED_MEMBERS = frozenset(
    {
        "authority",
        "backing_chain",
        "built_utc",
        "chain_path",
        "coverage",
        "deprecated_fields",
        "endpoints",
        "first",
        "frame",
        "frame_hash",
        "full_history",
        "genesis_frame_hash",
        "head_frame_hash",
        "input_fingerprint",
        "kind",
        "last",
        "native_frame_hash",
        "native_genesis_frame_hash",
        "native_seq",
        "native_source",
        "native_stream_id",
        "native_utc",
        "omitted_rows",
        "profile",
        "protocol",
        "raw_bytes",
        "raw_sha256",
        "repository",
        "returned_rows",
        "rows",
        "schema",
        "schema_version",
        "source",
        "spine_head",
        "storage_line",
        "storage_path",
        "tick",
        "tick_frame",
        "tick_source",
        "total_matching_rows",
        "total_recorded",
        "utc",
        "v",
        "verified_inputs",
        "verify",
        "window",
        "window_limit",
        "world",
    }
)
VENDOR = ROOT / "vendor" / "dogg-native-verifier"
VERIFIER_PIN = {
    "schema": "dogg-native-verifier-vendor/1",
    "repository": SOURCE_REPOSITORY,
    "commit": "55f65208b8d940693c54fe795f0390e6c79521cc",
    "tree": "4f9c2281b7b3a33da1a19530e53bfa84eb51f405",
    "files": {
        "LICENSE": {
            "source_path": "LICENSE",
            "bytes": 1087,
            "sha256": "472f5334a3a25473b3ccc1c5f97eac4183d05fd726f9a116cfdd3dfdd4d5dc11",
        },
        "chainio.py": {
            "source_path": "tools/chainio.py",
            "bytes": 4013,
            "sha256": "9f9aec689112fcf0408dcd564ac0af4f974b0f6ce8aca18b0df3ec3ffd41e46d",
        },
        "rapp.py": {
            "source_path": "tools/rapp.py",
            "bytes": 12819,
            "sha256": "c945ee85f01af5cd374490b40721d07f2aca7c8bd6d209e0d2933420f55db284",
        },
        "verify_thread.py": {
            "source_path": "tools/verify_thread.py",
            "bytes": 1359,
            "sha256": "4894ad22fb6df5fe98c6417155368ef7fd3b97bd5f224768b73d442b8e59f513",
        },
    },
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def fingerprint(value):
    return sha256(canonical(value))


def safe_relative(value, label):
    require(
        isinstance(value, str) and SAFE_PATH.fullmatch(value),
        f"unsafe {label}",
    )
    require(
        all(part not in ("", ".", "..") for part in value.split("/")),
        f"unsafe {label}",
    )
    return value


def normalized_identity(value):
    return unicodedata.normalize("NFC", value).casefold()


PROJECTION_RESERVED_IDENTITIES = {
    normalized_identity(member): member for member in PROJECTION_RESERVED_MEMBERS
}


def filesystem_identity(value):
    require(unicodedata.normalize("NFC", value) == value, "non-canonical Unicode path")
    return normalized_identity(value)


def validate_source_identifier(value, identities):
    require(
        isinstance(value, str)
        and value.isascii()
        and 0 < len(value) <= MAX_SOURCE_IDENTIFIER_BYTES
        and SOURCE_IDENTIFIER.fullmatch(value),
        "unsafe world source identifier",
    )
    identity = filesystem_identity(value)
    require(identity not in WINDOWS_RESERVED_NAMES, "reserved world source identifier")
    previous = identities.setdefault(identity, value)
    require(previous == value, f"world source identifier collision: {previous!r} and {value!r}")
    return value


def validate_native_source_data(source, data):
    if not isinstance(data, dict):
        return
    for member in data:
        require(isinstance(member, str), f"native source {source!r} data member must be text")
        identity = normalized_identity(member)
        reserved = PROJECTION_RESERVED_IDENTITIES.get(identity)
        require(
            reserved is None,
            f"native source {source!r} data member collision: "
            f"{member!r} conflicts with reserved projection member {reserved!r}",
        )


def validate_output_relatives(paths):
    identities = {}
    for value in paths:
        safe_relative(value, "API document path")
        identity = filesystem_identity(value)
        previous = identities.setdefault(identity, value)
        require(previous == value, f"API document path collision: {previous!r} and {value!r}")
    for identity, value in identities.items():
        parts = identity.split("/")
        for length in range(1, len(parts)):
            parent = "/".join(parts[:length])
            if parent in identities:
                raise ValueError(
                    f"API document path collision: {identities[parent]!r} contains {value!r}"
                )


def contained_target(root, relative):
    safe_relative(relative, "API document path")
    root = Path(root).absolute()
    candidate = root.joinpath(*relative.split("/"))
    normalized = Path(os.path.normpath(candidate))
    require(normalized == candidate, f"API document target did not normalize exactly: {relative}")
    try:
        resolved_root = root.resolve(strict=False)
        resolved_candidate = candidate.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"API document target could not be resolved: {relative}") from exc
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"API document target escaped output: {relative}") from exc
    require(resolved_candidate != resolved_root, "API document target cannot be the output root")
    return candidate


def output_targets(root, paths):
    validate_output_relatives(paths)
    return {path: contained_target(root, path) for path in paths}


def git_environment():
    ancestry_overrides = ("GIT_REPLACE_REF_BASE", "GIT_GRAFT_FILE", "GIT_SHALLOW_FILE")
    repository_overrides = (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CEILING_DIRECTORIES",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    )
    for name in ancestry_overrides + repository_overrides:
        require(not os.environ.get(name), f"Git override environment is forbidden: {name}")
    env = os.environ.copy()
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    for name in ancestry_overrides + repository_overrides:
        env.pop(name, None)
    env.pop("GIT_CONFIG_COUNT", None)
    for name in tuple(env):
        if name.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
            env.pop(name)
    return env


def run(args, cwd=None, timeout=120):
    result = subprocess.run(
        [os.fspath(arg) for arg in args],
        cwd=os.fspath(cwd) if cwd is not None else None,
        capture_output=True,
        env=git_environment(),
        timeout=timeout,
    )
    if result.returncode:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        raise ValueError(f"{Path(os.fspath(args[0])).name} refused ({result.returncode}): {stderr}")
    return result.stdout


def git(root, *args):
    return run(["git", "--no-replace-objects", *args], cwd=root).decode("utf-8").strip()


def git_path(root, value):
    path = Path(git(root, "rev-parse", "--git-path", value))
    if not path.is_absolute():
        path = Path(root).resolve() / path
    return path.absolute()


def source_repository_root(root):
    root = Path(root).absolute()
    require(root.is_dir() and not root.is_symlink(), "source repository must be a real directory")
    top = Path(git(root, "rev-parse", "--show-toplevel")).absolute()
    require(top.is_dir() and not top.is_symlink(), "Git top-level must be a real directory")
    require(root.resolve() == top.resolve(), "source repository must be the exact Git top-level")
    return top


def check_git_source(root, revision, tree, main_commit):
    root = source_repository_root(root)
    for value, label in (
        (revision, "source commit"),
        (tree, "source tree"),
        (main_commit, "canonical main commit"),
    ):
        require(HEX40.fullmatch(value or ""), f"{label} must be a full lowercase SHA-1")
    require(git(root, "rev-parse", "--is-shallow-repository") == "false", "shallow history is forbidden")
    require(not os.path.lexists(git_path(root, "info/grafts")), "Git graft state is forbidden")
    replacements = git(root, "for-each-ref", "--format=%(refname)", "refs/replace").splitlines()
    require(not replacements, "Git replacement state is forbidden")
    require(git(root, "rev-parse", "--show-object-format") == "sha1", "unsupported Git object format")
    origins = git(root, "config", "--local", "--get-all", "remote.origin.url").splitlines()
    require(origins == [SOURCE_REPOSITORY], "origin URL does not exactly match kody-w/dogg")
    require(
        git(root, "rev-parse", "--verify", f"{revision}^{{commit}}") == revision,
        "source commit is not an immutable commit",
    )
    require(
        git(root, "rev-parse", "--verify", f"{revision}^{{tree}}") == tree,
        "selected source tree does not match source commit",
    )
    require(
        git(root, "rev-parse", "--verify", f"{CANONICAL_REF}^{{commit}}") == main_commit,
        "canonical origin/main does not match the explicitly selected main commit",
    )
    ancestry = subprocess.run(
        ["git", "--no-replace-objects", "merge-base", "--is-ancestor", revision, main_commit],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=git_environment(),
    )
    require(ancestry.returncode == 0, "source commit is not on canonical origin/main ancestry")
    run(["git", "--no-replace-objects", "fsck", "--strict", "--no-dangling", revision], cwd=root)
    return root


def tree_files(root, revision, chain_path):
    safe_relative(chain_path, "chain path")
    raw = run(
        ["git", "--no-replace-objects", "ls-tree", "-rz", "--full-tree", revision, "--", chain_path],
        cwd=root,
    )
    entries = {}
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        metadata, separator, encoded_path = encoded.partition(b"\t")
        require(separator == b"\t", "malformed Git tree entry")
        fields = metadata.split()
        require(len(fields) == 3, "malformed Git tree metadata")
        mode, kind, oid = (field.decode("ascii") for field in fields)
        path = encoded_path.decode("utf-8")
        safe_relative(path, "Git tree entry path")
        require(path == chain_path or path.startswith(chain_path + "/"), "Git path escaped chain")
        require(path not in entries, "duplicate Git tree path")
        entries[path] = {"mode": mode, "kind": kind, "oid": oid}
    return entries


def tree_blob(root, entries, path, maximum=MAX_RECORD_BYTES):
    safe_relative(path, "Git object path")
    entry = entries.get(path)
    require(entry is not None, f"native Git object is absent: {path}")
    require(
        entry["mode"] == "100644" and entry["kind"] == "blob" and HEX40.fullmatch(entry["oid"]),
        f"native Git object is not a regular 100644 blob: {path}",
    )
    size_text = git(root, "cat-file", "-s", entry["oid"])
    require(re.fullmatch(r"[0-9]+", size_text) is not None, f"invalid Git blob size: {path}")
    size = int(size_text)
    require(0 < size <= maximum, f"Git blob size outside 1..{maximum}: {path}")
    raw = run(["git", "--no-replace-objects", "cat-file", "blob", entry["oid"]], cwd=root)
    require(len(raw) == size, f"Git blob size/output mismatch: {path}")
    return raw


def strict_json(raw, label):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, f"duplicate JSON member in {label}")
            value[key] = item
        return value

    def invalid_constant(value):
        raise ValueError(f"invalid JSON constant in {label}: {value}")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=invalid_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"invalid native JSON: {label}") from exc
    require(isinstance(value, dict), f"native JSON must be an object: {label}")
    return value


def load_verifier():
    provenance_raw = (VENDOR / "PROVENANCE.json").read_bytes()
    provenance = strict_json(provenance_raw, "verifier provenance")
    require(provenance == VERIFIER_PIN, "native verifier provenance pin mismatch")
    blobs = {}
    for name, expected in VERIFIER_PIN["files"].items():
        raw = (VENDOR / name).read_bytes()
        require(len(raw) == expected["bytes"], f"native verifier byte count mismatch: {name}")
        require(sha256(raw) == expected["sha256"], f"native verifier SHA-256 mismatch: {name}")
        blobs[name] = raw
    module = types.ModuleType("_dogg_api_native_rapp")
    module.__file__ = str(VENDOR / "rapp.py")
    exec(compile(blobs["rapp.py"], module.__file__, "exec"), module.__dict__)
    return module, blobs


def load_chain(root, revision, chain_path, expected_stream, native_rapp):
    entries = tree_files(root, revision, chain_path)
    head_path = f"{chain_path}/HEAD.json"
    head_raw = tree_blob(root, entries, head_path, 16384)
    meta = strict_json(head_raw, head_path)
    count = meta.get("count")
    epoch_size = meta.get("epoch_size", MAX_EPOCH_SIZE)
    sealed = meta.get("sealed_epochs", 0)
    require(type(count) is int and 0 < count <= 2**53 - 1, f"{chain_path}: invalid HEAD count")
    require(meta.get("stream_id") == expected_stream, f"{chain_path}: unexpected HEAD stream")
    require(HEX64.fullmatch(meta.get("head_frame", "")), f"{chain_path}: invalid HEAD hash")
    require(type(epoch_size) is int and 1 <= epoch_size <= MAX_EPOCH_SIZE, f"{chain_path}: invalid epoch size")
    require(type(sealed) is int and 0 <= sealed and sealed * epoch_size <= count, f"{chain_path}: invalid sealed epochs")

    records = []
    storage = {head_path: head_raw}
    for epoch in range(sealed):
        path = f"{chain_path}/epochs/{epoch}.jsonl"
        raw = tree_blob(root, entries, path, epoch_size * (MAX_RECORD_BYTES + 1))
        require(raw.endswith(b"\n"), f"{path}: sealed epoch lacks final LF")
        lines = raw[:-1].split(b"\n")
        require(len(lines) == epoch_size and all(lines), f"{path}: sealed epoch line count/gap")
        storage[path] = raw
        for line_number, line in enumerate(lines, 1):
            require(len(line) <= MAX_RECORD_BYTES, f"{path}:{line_number}: native record too large")
            records.append(
                {
                    "raw": line,
                    "storage_path": path,
                    "storage_line": line_number,
                    "frame": strict_json(line, f"{path}:{line_number}"),
                }
            )
    for seq in range(sealed * epoch_size, count):
        path = f"{chain_path}/{seq}.json"
        raw = tree_blob(root, entries, path)
        storage[path] = raw
        records.append(
            {
                "raw": raw,
                "storage_path": path,
                "storage_line": None,
                "frame": strict_json(raw, path),
            }
        )
    require(len(records) == count, f"{chain_path}: native storage gap")

    previous = None
    for seq, record in enumerate(records):
        frame = record["frame"]
        require(frame.get("seq") == seq, f"{chain_path}: native sequence gap at {seq}")
        ok, step, reason = native_rapp.verify_frame(
            frame, head=previous, stream_id_of_record=expected_stream
        )
        require(ok, f"native oracle refused {chain_path}/{seq}: {step}: {reason}")
        previous = frame
    require(previous["frame_hash"] == meta["head_frame"], f"{chain_path}: HEAD mismatch")
    return {
        "path": chain_path,
        "meta": meta,
        "head_raw": head_raw,
        "records": records,
        "frames": [record["frame"] for record in records],
        "storage": storage,
        "genesis": records[0]["frame"]["frame_hash"],
    }


def validate_tick(frame, seq):
    require(frame.get("stream_id") == "tick:@kody-w/global", f"tick {seq}: wrong stream")
    require(frame.get("kind") == "tick.anchor", f"tick {seq}: wrong kind")
    payload = frame.get("payload")
    require(
        isinstance(payload, dict) and type(payload.get("tick")) is int and payload["tick"] == seq,
        f"tick {seq}: payload.tick must equal native sequence",
    )
    require("tick_frame" not in payload, f"tick {seq}: anchor unexpectedly references a tick")


def source_tuple(chain, seq, revision):
    frame = chain["frames"][seq]
    record = chain["records"][seq]
    return {
        "repository": SOURCE_REPOSITORY,
        "commit": revision,
        "chain_path": chain["path"],
        "storage_path": record["storage_path"],
        "storage_line": record["storage_line"],
        "raw_sha256": sha256(record["raw"]),
        "raw_bytes": len(record["raw"]),
        "native_stream_id": frame["stream_id"],
        "native_genesis_frame_hash": chain["genesis"],
        "native_seq": frame["seq"],
        "native_frame_hash": frame["frame_hash"],
        "native_utc": frame["utc"],
    }


def verify_world_ticks(world, ticks, revision):
    for seq, tick in enumerate(ticks["frames"]):
        validate_tick(tick, seq)
    joined = []
    for seq, frame in enumerate(world["frames"]):
        require(frame.get("kind") == "world.snapshot", f"world/{seq}: wrong frame kind")
        payload = frame.get("payload")
        require(isinstance(payload, dict), f"world/{seq}: payload must be an object")
        tick = payload.get("tick")
        tick_frame = payload.get("tick_frame")
        require(type(tick) is int and 0 <= tick < len(ticks["frames"]), f"world/{seq}: tick outside verified spine")
        require(HEX64.fullmatch(tick_frame or ""), f"world/{seq}: invalid tick_frame")
        actual = ticks["frames"][tick]
        require(actual["frame_hash"] == tick_frame, f"world/{seq}: wrong or stale tick_frame")
        require(isinstance(payload.get("world"), dict), f"world/{seq}: world data must be an object")
        require(isinstance(payload.get("fetched_utc"), str), f"world/{seq}: missing fetched_utc")
        joined.append(
            {
                "native_source": source_tuple(world, seq, revision),
                "tick_source": source_tuple(ticks, tick, revision),
            }
        )
    return joined


def run_native_oracle(chains, verifier_blobs):
    WORK.mkdir(exist_ok=True)
    scratch = WORK / f"native-oracle-{os.getpid()}-{uuid.uuid4().hex}"
    scratch.mkdir()
    try:
        tools = scratch / "tools"
        tools.mkdir()
        for name in ("chainio.py", "rapp.py", "verify_thread.py"):
            (tools / name).write_bytes(verifier_blobs[name])
        for chain in chains:
            for path, raw in chain["storage"].items():
                target = scratch / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(tools / "verify_thread.py")],
            cwd=scratch,
            capture_output=True,
            text=True,
            timeout=120,
            env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        )
        require(result.returncode == 0, f"pinned native DOGG oracle refused: {result.stdout}{result.stderr}")
        for chain in chains:
            require(f"OK: {chain['path']} " in result.stdout, f"native oracle omitted {chain['path']}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def chain_input(chain, revision):
    records = [
        {
            "seq": seq,
            "frame_hash": record["frame"]["frame_hash"],
            "storage_path": record["storage_path"],
            "storage_line": record["storage_line"],
            "raw_sha256": sha256(record["raw"]),
            "raw_bytes": len(record["raw"]),
        }
        for seq, record in enumerate(chain["records"])
    ]
    return {
        "stream_id": chain["meta"]["stream_id"],
        "count": chain["meta"]["count"],
        "genesis_frame_hash": chain["genesis"],
        "head_frame_hash": chain["meta"]["head_frame"],
        "head_raw_sha256": sha256(chain["head_raw"]),
        "head_raw_bytes": len(chain["head_raw"]),
        "records_fingerprint": fingerprint(records),
        "commit": revision,
    }


def commit_utc(root, revision):
    value = git(root, "show", "-s", "--format=%cI", revision)
    parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def verify_previous_projection(
    path,
    source_repo,
    revision,
    verified_inputs,
    chains,
    native_rapp,
    verifier_blobs,
):
    path = Path(path)
    if not path.exists():
        return
    require(path.is_file() and not path.is_symlink(), "previous API index must be a regular file")
    raw = path.read_bytes()
    require(len(raw) <= 1024 * 1024, "previous API index exceeds byte limit")
    previous = strict_json(raw, "previous API index")
    if previous.get("profile") != PROFILE:
        return
    require(previous.get("schema") == SCHEMA, "previous API schema mismatch")
    prior_inputs = previous.get("verified_inputs")
    require(
        isinstance(prior_inputs, dict)
        and prior_inputs.get("schema") == "dogg/0-static-api-inputs/1"
        and prior_inputs.get("native_verifier") == VERIFIER_PIN
        and previous.get("input_fingerprint") == fingerprint(prior_inputs),
        "previous API input fingerprint mismatch",
    )
    prior_source = prior_inputs.get("source")
    require(
        isinstance(prior_source, dict)
        and prior_source.get("repository") == SOURCE_REPOSITORY
        and prior_source.get("canonical_ref") == CANONICAL_REF
        and HEX40.fullmatch(prior_source.get("commit", ""))
        and HEX40.fullmatch(prior_source.get("tree", ""))
        and HEX40.fullmatch(prior_source.get("canonical_main_commit", "")),
        "previous API source provenance mismatch",
    )
    prior_commit = prior_source["commit"]
    require(
        git(source_repo, "rev-parse", "--verify", f"{prior_commit}^{{commit}}") == prior_commit,
        "previous source commit is unavailable",
    )
    require(
        git(source_repo, "rev-parse", "--verify", f"{prior_commit}^{{tree}}")
        == prior_source["tree"],
        "previous API source tree provenance mismatch",
    )
    prior_main = prior_source["canonical_main_commit"]
    require(
        git(source_repo, "rev-parse", "--verify", f"{prior_main}^{{commit}}") == prior_main,
        "previous canonical main commit is unavailable",
    )
    ancestry = subprocess.run(
        ["git", "--no-replace-objects", "merge-base", "--is-ancestor", prior_commit, revision],
        cwd=source_repo,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=git_environment(),
    )
    require(ancestry.returncode == 0, "source commit rollback or replacement")
    for ancestor, descendant, message in (
        (prior_commit, prior_main, "previous source was not on its canonical main ancestry"),
        (
            prior_main,
            verified_inputs["source"]["canonical_main_commit"],
            "previous canonical main was replaced",
        ),
    ):
        ancestry = subprocess.run(
            ["git", "--no-replace-objects", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=source_repo,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=git_environment(),
        )
        require(ancestry.returncode == 0, message)

    prior_chains = prior_inputs.get("chains")
    require(
        isinstance(prior_chains, dict) and set(prior_chains) == set(chains),
        "previous API chain provenance mismatch",
    )
    specifications = {
        "ticks": ("ticks", "tick:@kody-w/global"),
        "world": ("world", "world:@kody-w/dogg"),
    }
    historical = {
        name: load_chain(source_repo, prior_commit, *specifications[name], native_rapp)
        for name in chains
    }
    run_native_oracle(tuple(historical.values()), verifier_blobs)
    verify_world_ticks(historical["world"], historical["ticks"], prior_commit)

    for name, chain in chains.items():
        prior = prior_chains.get(name)
        require(isinstance(prior, dict), f"previous API omitted {name} provenance")
        expected_prior = chain_input(historical[name], prior_commit)
        require(
            prior == expected_prior,
            f"previous API {name} storage provenance mismatch",
        )
        current = verified_inputs["chains"].get(name)
        require(
            current == chain_input(chain, revision),
            f"current API {name} storage provenance mismatch",
        )
        count = expected_prior["count"]
        require(type(count) is int and 0 < count <= len(chain["frames"]), f"native {name} rollback")
        require(
            expected_prior["genesis_frame_hash"] == chain["genesis"],
            f"native {name} genesis changed",
        )
        require(
            expected_prior["head_frame_hash"] == chain["frames"][count - 1]["frame_hash"],
            f"native {name} fork at previously accepted head",
        )
        for seq in range(count):
            historical_frame = historical[name]["frames"][seq]
            current_frame = chain["frames"][seq]
            historical_bytes = canonical(historical_frame)
            current_bytes = canonical(current_frame)
            require(
                historical_frame["frame_hash"] == current_frame["frame_hash"]
                and sha256(historical_bytes) == sha256(current_bytes)
                and historical_bytes == current_bytes,
                f"native {name} semantic frame changed at previously accepted sequence {seq}",
            )
    if prior_commit == revision:
        require(prior_inputs == verified_inputs, "same-commit native provenance changed")


def coverage(rows, total):
    def edge(row):
        if row is None:
            return None
        return {
            "native_seq": row["native_source"]["native_seq"],
            "frame_hash": row["frame_hash"],
            "tick": row["tick"],
            "tick_frame": row["tick_frame"],
            "utc": row["utc"],
        }

    return {
        "kind": "rolling-world-frames-containing-source",
        "window_limit": WINDOW,
        "returned_rows": len(rows),
        "total_matching_rows": total,
        "omitted_rows": total - len(rows),
        "first": edge(rows[0] if rows else None),
        "last": edge(rows[-1] if rows else None),
    }


def build_documents(source_repo, revision, tree, main_commit, previous_index=None):
    source_repo = check_git_source(source_repo, revision, tree, main_commit)
    native_rapp, verifier_blobs = load_verifier()
    ticks = load_chain(source_repo, revision, "ticks", "tick:@kody-w/global", native_rapp)
    world = load_chain(source_repo, revision, "world", "world:@kody-w/dogg", native_rapp)
    run_native_oracle((ticks, world), verifier_blobs)
    joins = verify_world_ticks(world, ticks, revision)

    verified_inputs = {
        "schema": "dogg/0-static-api-inputs/1",
        "source": {
            "repository": SOURCE_REPOSITORY,
            "commit": revision,
            "tree": tree,
            "canonical_ref": CANONICAL_REF,
            "canonical_main_commit": main_commit,
        },
        "native_verifier": VERIFIER_PIN,
        "chains": {
            "ticks": chain_input(ticks, revision),
            "world": chain_input(world, revision),
        },
    }
    input_fingerprint = fingerprint(verified_inputs)
    if previous_index is not None:
        verify_previous_projection(
            previous_index,
            source_repo,
            revision,
            verified_inputs,
            {"ticks": ticks, "world": world},
            native_rapp,
            verifier_blobs,
        )
    built_utc = commit_utc(source_repo, revision)
    protocol = f"{SOURCE_WEB}/blob/{revision}/PROTOCOL.md"
    base = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "schema_version": 1,
        "input_fingerprint": input_fingerprint,
        "built_utc": built_utc,
        "authority": "non-authoritative convenience projection; verify native DOGG provenance",
    }

    series = {}
    source_identities = {}
    for frame, joined in zip(world["frames"], joins):
        payload = frame["payload"]
        for source, data in payload["world"].items():
            validate_source_identifier(source, source_identities)
            validate_native_source_data(source, data)
            row = {"v": data} if not isinstance(data, dict) else dict(data)
            row.update(
                {
                    "tick": payload["tick"],
                    "tick_frame": payload["tick_frame"],
                    "utc": payload["fetched_utc"],
                    "frame": frame["frame_hash"],
                    "frame_hash": frame["frame_hash"],
                    **joined,
                }
            )
            series.setdefault(source, []).append(row)

    documents = {}
    endpoint_map = {}
    series_coverage = {}
    for source in sorted(series):
        all_rows = series[source]
        rows = all_rows[-WINDOW:]
        item_coverage = coverage(rows, len(all_rows))
        endpoint_map[source] = f"api/series/{source}.json"
        series_coverage[source] = item_coverage
        documents[f"series/{source}.json"] = {
            **base,
            "source": source,
            "rows": rows,
            "window": WINDOW,
            "total_recorded": len(all_rows),
            "coverage": item_coverage,
            "full_history": f"{SOURCE_WEB}/tree/{revision}/world",
            "backing_chain": "world:@kody-w/dogg",
        }

    latest_frame = world["frames"][-1]
    latest_payload = latest_frame["payload"]
    latest_join = joins[-1]
    documents["latest.json"] = {
        **base,
        "tick": latest_payload["tick"],
        "tick_frame": latest_payload["tick_frame"],
        "utc": latest_payload["fetched_utc"],
        "world": latest_payload["world"],
        "frame_hash": latest_frame["frame_hash"],
        "native_source": latest_join["native_source"],
        "tick_source": latest_join["tick_source"],
        "spine_head": latest_join["tick_source"]["native_frame_hash"],
        "deprecated_fields": {
            "spine_head": "Deprecated alias of tick_source.native_frame_hash for the world payload's actual tick; it is not the independently newer ticks HEAD."
        },
        "verified_inputs": verified_inputs,
    }
    documents["index.json"] = {
        **base,
        "endpoints": {"latest": "api/latest.json", "series": endpoint_map},
        "coverage": {
            "world_frames_verified": len(world["frames"]),
            "tick_frames_verified": len(ticks["frames"]),
            "series": series_coverage,
        },
        "verified_inputs": verified_inputs,
        "verify": "Every row binds full native world and exact referenced tick tuples from one verified immutable commit.",
        "protocol": protocol,
    }
    return documents


def render_documents(documents):
    validate_output_relatives(documents)
    rendered = {}
    for path, value in documents.items():
        indent = 1 if path in ("latest.json", "index.json") else None
        rendered[path] = (
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=indent) + "\n"
        ).encode("utf-8")
    return rendered


def existing_documents(output):
    if not output.exists():
        return {}
    require(output.is_dir() and not output.is_symlink(), "API output must be a real directory")
    result = {}
    for path in sorted(output.rglob("*")):
        require(not path.is_symlink(), "API output symlinks are forbidden")
        if path.is_file():
            result[path.relative_to(output).as_posix()] = path.read_bytes()
    return result


def regenerate(output, documents):
    output = Path(output).absolute()
    rendered = render_documents(documents)
    final_targets = output_targets(output, rendered)
    if existing_documents(output) == rendered:
        return "unchanged"
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = output.parent / f".{output.name}.build-{os.getpid()}-{uuid.uuid4().hex}"
    backup = output.parent / f".{output.name}.old-{os.getpid()}-{uuid.uuid4().hex}"
    staging.mkdir()
    try:
        staging_targets = output_targets(staging, rendered)
        for path, raw in rendered.items():
            target = staging_targets[path]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        for path in rendered:
            contained_target(output, path)
            require(
                final_targets[path].relative_to(output) == staging_targets[path].relative_to(staging),
                f"staging/final target mismatch: {path}",
            )
        if output.exists():
            require(not output.is_symlink(), "API output symlink is forbidden")
            os.replace(output, backup)
        os.replace(staging, output)
        if backup.exists():
            shutil.rmtree(backup)
    except BaseException:
        if not output.exists() and backup.exists():
            os.replace(backup, output)
        raise
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        if backup.exists():
            shutil.rmtree(backup)
    return "updated"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--source-main-commit", required=True)
    parser.add_argument("--output", type=Path, default=API)
    args = parser.parse_args(argv)
    try:
        documents = build_documents(
            args.source_repo,
            args.source_commit,
            args.source_tree,
            args.source_main_commit,
            args.output / "index.json",
        )
        state = regenerate(args.output, documents)
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as exc:
        print(f"api build refused: {exc}", file=sys.stderr)
        return 1
    latest = documents["latest.json"]
    print(
        f"api {state}: {len(documents) - 2} series, "
        f"{documents['index.json']['coverage']['world_frames_verified']} world frames, "
        f"latest tick {latest['tick']}, source {args.source_commit}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
