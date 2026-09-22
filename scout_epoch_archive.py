"""Offline, fail-closed builder for ``flop-scout-epoch-archive/v1``.

All paths are caller supplied.  The module has no production defaults and
never publishes an archive; it only atomically materializes an explicit local
directory from held, descriptor-verified inputs.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import uuid
from pathlib import Path

from scout_epoch_source_evidence import SCHEMA as SOURCE_SCHEMA, validate as validate_source
from scout_legacy_a1_recovery import MAX_JSON_BYTES, MAX_SQLITE_BYTES, canonical
from scout_epoch_v2 import commitment as epoch_commitment


MANIFEST_SCHEMA = "flop-scout-epoch-archive/v1"
MANIFEST_DOMAIN = b"flop-scout/epoch-archive-manifest/v1\0"
RECOVERY_SCHEMA = "scout-legacy-a1-provenance-recovery/v1"
_ROLES = (("bridge_projection_sqlite", "members/bridge-projection.sqlite", "scout-router-projection/v2"),
          ("legacy_recovery_json", "members/legacy-recovery.json", RECOVERY_SCHEMA),
          ("source_evidence_sqlite", "members/source-evidence.sqlite", SOURCE_SCHEMA))
_HEX = set("0123456789abcdef")


class ArchiveError(ValueError):
    def __init__(self, code, message): self.code = code; super().__init__(message)


def _fail(code, message): raise ArchiveError(code, message)


def _ascii(value):
    if isinstance(value, str):
        if not value.isascii(): _fail("ARCHIVE_CANONICAL", "committed JSON contains non-ASCII text")
    elif isinstance(value, list):
        for item in value: _ascii(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii(): _fail("ARCHIVE_CANONICAL", "committed JSON key is invalid")
            _ascii(item)
    elif value is not None and type(value) not in (bool, int): _fail("ARCHIVE_CANONICAL", "committed JSON has unsupported value")


def _bytes(value):
    _ascii(value)
    return canonical(value)


def _sha(data): return hashlib.sha256(data).hexdigest()


def _hex(value): return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


def recovery_bytes(recovery):
    """Return the canonical redacted recovery member, with no source text."""
    keys = ("descriptor", "validated_records", "closure_count", "closure", "reason_counts", "commitment")
    if not isinstance(recovery, dict) or set(recovery) != set(keys) or not _hex(recovery.get("commitment")):
        _fail("ARCHIVE_RECOVERY", "recovery result is incomplete")
    value = {"schema": RECOVERY_SCHEMA, **{key: recovery[key] for key in keys}}
    raw = _bytes(value)
    # Closure entries are bounded IDs/hashes/reasons; 50k entries remain below
    # this explicit 32 MiB archive-member limit without admitting source text.
    if len(raw) > 32 * 1024 * 1024 or b'"raw_text":' in raw or b'"envelope":' in raw:
        _fail("ARCHIVE_RECOVERY", "recovery member is unsafe or oversized")
    return raw


def _path(value, output=False):
    path = Path(value)
    if not path.is_absolute(): _fail("ARCHIVE_PATH", "all paths must be explicit absolute paths")
    if output:
        if path.exists() or path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
            _fail("ARCHIVE_PATH", "archive destination must be a nonexistent child of a regular directory")
        return path
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_SQLITE_BYTES:
        _fail("ARCHIVE_PATH", "archive member input must be a bounded regular file")
    return path.resolve(strict=True)


def _held_copy(source, destination):
    """Copy from a descriptor-held regular file while hashing and detecting TOCTOU."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(source, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_SQLITE_BYTES: _fail("ARCHIVE_MEMBER_IO", "member is not a bounded regular file")
        out = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        digest = hashlib.sha256(); size = 0
        try:
            while True:
                block = os.read(fd, 1024 * 1024)
                if not block: break
                os.write(out, block); digest.update(block); size += len(block)
            os.fsync(out)
        finally: os.close(out)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or size != before.st_size:
            _fail("ARCHIVE_MEMBER_IO", "member changed while descriptor was held")
        return {"sha256": digest.hexdigest(), "size_bytes": size}
    finally: os.close(fd)


def _read_held(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_SQLITE_BYTES: _fail("ARCHIVE_MEMBER_IO", "member is not a bounded regular file")
        chunks = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block: break
            chunks.append(block)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns): _fail("ARCHIVE_MEMBER_IO", "member changed while held")
        return b"".join(chunks)
    finally: os.close(fd)


def _fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def _manifest(context, spec, members, recovery):
    required = {"accepted_anchor", "bridge_predecessor", "source_checkpoint", "previous_bridge_binding_sha256"}
    if not isinstance(context, dict) or set(context) != required or not _hex(context["previous_bridge_binding_sha256"]): _fail("ARCHIVE_DESCRIPTOR", "archive context is incomplete")
    checkpoint = context["source_checkpoint"]
    if not isinstance(checkpoint, dict) or set(checkpoint) != {"source_id", "source_epoch", "source_cut"} or not isinstance(checkpoint["source_id"], str) or not isinstance(checkpoint["source_epoch"], str) or type(checkpoint["source_cut"]) is not int or checkpoint["source_cut"] < 0:
        _fail("ARCHIVE_DESCRIPTOR", "archive source checkpoint is not canonical")
    try:
        binding = epoch_commitment("a1-bridge-binding", {"accepted_anchor": context["accepted_anchor"], "bridge_predecessor": context["bridge_predecessor"]})
    except Exception as exc:
        raise ArchiveError("ARCHIVE_DESCRIPTOR", "archive bridge descriptors are not canonical V2 descriptors") from exc
    if context["previous_bridge_binding_sha256"] != binding:
        _fail("ARCHIVE_DESCRIPTOR", "archive bridge binding is not the V2 wire binding")
    required_spec = {"archive_id", "previous_epoch_id", "previous_manifest_sha256", "locator"}
    if not isinstance(spec, dict) or set(spec) != required_spec or not _hex(spec["previous_manifest_sha256"]): _fail("ARCHIVE_DESCRIPTOR", "archive specification is incomplete")
    if not isinstance(spec["locator"], str) or spec["locator"].startswith("/") or ".." in spec["locator"].split("/"):
        _fail("ARCHIVE_DESCRIPTOR", "archive locator is unsafe")
    result = {"schema": MANIFEST_SCHEMA, "archive_id": spec["archive_id"], "accepted_anchor": context["accepted_anchor"],
              "bridge_predecessor": context["bridge_predecessor"], "previous_bridge_binding_sha256": context["previous_bridge_binding_sha256"],
              "source_checkpoint": context["source_checkpoint"],
              "legacy_recovery": {"schema": RECOVERY_SCHEMA, "commitment_sha256": recovery["commitment"], "validated_records": recovery["validated_records"], "closure_count": recovery["closure_count"]},
              "retention": "IMMUTABLE_INDEFINITE_FIRST_TRANSITION", "members": sorted(members, key=lambda v: (v["role"], v["locator"]))}
    commitment = _sha(MANIFEST_DOMAIN + _bytes(result))
    return {"manifest_commitment_sha256": commitment, **result}


def _descriptor(spec, context, manifest):
    manifest_bytes = _bytes(manifest)
    value = {"schema": MANIFEST_SCHEMA, "archive_id": spec["archive_id"], "artifact_sha256": _sha(manifest_bytes), "size_bytes": len(manifest_bytes),
             "database_schema_version": "flop-scout-epoch-archive-manifest/v1", "locator": spec["locator"], "previous_epoch_id": spec["previous_epoch_id"],
             "previous_manifest_sha256": spec["previous_manifest_sha256"], "previous_bridge_binding_sha256": context["previous_bridge_binding_sha256"], "preservation": "IMMUTABLE_RETAINED"}
    value["archive_commitment_sha256"] = epoch_commitment("archive-descriptor", value)
    return value


def build(bridge_path, source_evidence_path, projection_path, authorized_descriptor, observed_descriptor, context, spec, destination):
    """Build a secure three-member archive to a new explicit directory."""
    bridge_path, source_evidence_path, projection_path = _path(bridge_path), _path(source_evidence_path), _path(projection_path)
    destination = _path(destination, True)
    recovery_check = validate_source(source_evidence_path, projection_path, authorized_descriptor, observed_descriptor, context,
                                     {"schema": SOURCE_SCHEMA, "size_bytes": source_evidence_path.stat().st_size, "sha256": _sha(_read_held(source_evidence_path))})
    recovery = recovery_check["recovery"]
    if _sha(_read_held(bridge_path)) != authorized_descriptor.get("artifact_sha256") or bridge_path.stat().st_size != authorized_descriptor.get("artifact_size"):
        _fail("ARCHIVE_BRIDGE_MEMBER", "bridge bytes do not equal authorized descriptor")
    stage = destination.parent / ("." + destination.name + ".staging-" + uuid.uuid4().hex)
    os.mkdir(stage, 0o700); members_dir = stage / "members"; os.mkdir(members_dir, 0o700)
    try:
        bridge_meta = _held_copy(bridge_path, members_dir / "bridge-projection.sqlite")
        source_meta = _held_copy(source_evidence_path, members_dir / "source-evidence.sqlite")
        raw_recovery = recovery_bytes(recovery); recovery_path = members_dir / "legacy-recovery.json"
        fd = os.open(recovery_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try: os.write(fd, raw_recovery); os.fsync(fd)
        finally: os.close(fd)
        member_meta = {"bridge_projection_sqlite": bridge_meta,
                       "source_evidence_sqlite": {"sha256": source_meta["sha256"], "size_bytes": source_meta["size_bytes"]},
                       "legacy_recovery_json": {"sha256": _sha(raw_recovery), "size_bytes": len(raw_recovery)}}
        members = [{"role": role, "locator": locator, "schema": schema, **member_meta[role]} for role, locator, schema in _ROLES]
        manifest = _manifest(context, spec, members, recovery)
        manifest_path = stage / "manifest.json"; raw_manifest = _bytes(manifest)
        fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try: os.write(fd, raw_manifest); os.fsync(fd)
        finally: os.close(fd)
        _fsync_dir(members_dir); _fsync_dir(stage)
        descriptor = _descriptor(spec, context, manifest)
        validate(stage, projection_path, authorized_descriptor, observed_descriptor, context, descriptor)
        os.rename(stage, destination); _fsync_dir(destination.parent)
        return {"root": str(destination), "descriptor": descriptor, "manifest": manifest, "recovery": recovery,
                "members": members}
    except Exception:
        if stage.exists(): shutil.rmtree(stage)
        raise


def validate(root, projection_path, authorized_descriptor, observed_descriptor, context, descriptor):
    root = _path(root) if Path(root).is_file() else Path(root)
    if not root.is_absolute() or not root.is_dir() or root.is_symlink(): _fail("ARCHIVE_PATH", "archive root is invalid")
    manifest_path = root / "manifest.json"
    raw = _read_held(manifest_path)
    if len(raw) > MAX_JSON_BYTES: _fail("ARCHIVE_MANIFEST_HASH", "manifest is oversized")
    try: manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc: raise ArchiveError("ARCHIVE_MANIFEST_HASH", "manifest is invalid") from exc
    if _bytes(manifest) != raw or descriptor.get("artifact_sha256") != _sha(raw) or descriptor.get("size_bytes") != len(raw): _fail("ARCHIVE_MANIFEST_HASH", "manifest bytes differ from descriptor")
    if manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("archive_id") != descriptor.get("archive_id"): _fail("ARCHIVE_DESCRIPTOR", "manifest identity differs")
    proof = dict(manifest); commit = proof.pop("manifest_commitment_sha256", None)
    if commit != _sha(MANIFEST_DOMAIN + _bytes(proof)): _fail("ARCHIVE_MANIFEST_HASH", "manifest commitment differs")
    members = manifest.get("members")
    if not isinstance(members, list) or [(v.get("role"),v.get("locator")) for v in members] != sorted((v.get("role"),v.get("locator")) for v in members): _fail("ARCHIVE_MEMBER_ROLE", "members are not sorted")
    expected = {role: (locator, schema) for role, locator, schema in _ROLES}
    if {v.get("role") for v in members} != set(expected) or len(members) != 3: _fail("ARCHIVE_MEMBER_ROLE", "member roles are incomplete or duplicate")
    members_dir = root / "members"
    if not members_dir.is_dir() or members_dir.is_symlink(): _fail("ARCHIVE_MEMBER_IO", "members directory is unsafe")
    held = {}
    for member in members:
        locator, schema = expected[member["role"]]
        if member.get("locator") != locator or member.get("schema") != schema: _fail("ARCHIVE_MEMBER_ROLE", "member schema or locator differs")
        path = root / locator
        if path.parent != members_dir or path.is_symlink(): _fail("ARCHIVE_MEMBER_IO", "member escapes archive root")
        raw_member = _read_held(path)
        if member.get("sha256") != _sha(raw_member) or member.get("size_bytes") != len(raw_member): _fail("ARCHIVE_MEMBER_IO", "member descriptor differs from bytes")
        held[member["role"]] = raw_member
    if _sha(held["bridge_projection_sqlite"]) != authorized_descriptor.get("artifact_sha256") or len(held["bridge_projection_sqlite"]) != authorized_descriptor.get("artifact_size"):
        _fail("ARCHIVE_BRIDGE_MEMBER", "bridge member differs from descriptor")
    try: recovery = json.loads(held["legacy_recovery_json"].decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc: raise ArchiveError("ARCHIVE_RECOVERY", "recovery member is invalid") from exc
    if recovery_bytes({key: recovery.get(key) for key in ("descriptor","validated_records","closure_count","closure","reason_counts","commitment")}) != held["legacy_recovery_json"]:
        _fail("ARCHIVE_RECOVERY", "recovery bytes are not canonical")
    if recovery.get("commitment") != manifest.get("legacy_recovery",{}).get("commitment_sha256"): _fail("ARCHIVE_RECOVERY", "recovery commitment differs")
    validate_source(root / "members/source-evidence.sqlite", projection_path, authorized_descriptor, observed_descriptor, context,
                    {"schema": SOURCE_SCHEMA, "size_bytes": len(held["source_evidence_sqlite"]), "sha256": _sha(held["source_evidence_sqlite"])})
    return {"manifest": manifest, "descriptor": descriptor, "recovery": recovery}
