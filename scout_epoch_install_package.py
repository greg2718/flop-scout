#!/usr/bin/env python3
"""Offline, fail-closed installer for a Scout A1-to-Epoch-V2 package.

This module deliberately has no production defaults.  Every root is an
operator supplied absolute path, and the only state it writes is beneath the
three supplied destination roots.  It is intentionally separate from the A1
refresh command: installing an epoch package can never be an incidental side
effect of a normal refresh.
"""
from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
import shutil
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from scout_epoch_v2 import (V2ValidationError, canonical_json, commitment,
                            parse_json, validate_active_set_plan_bytes,
                            validate_transition, validate_v2_manifest)

SCHEMA = "flop-scout-epoch-install-package/v1"
MAX_PACKAGE_BYTES = 2 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 128 * 1024
MIN_RESERVE_BYTES = 256 * 1024 * 1024
JOURNAL = ".epoch-v2-install-journal.json"
LOCK = ".epoch-v2-install.lock"

ROLES = (
    "candidate_pointer", "candidate_manifest", "candidate_transition",
    "candidate_plan", "candidate_artifact", "bridge_pointer",
    "bridge_manifest", "bridge_artifact", "archive_manifest",
    "archive_bridge_member", "archive_source_evidence_member",
    "archive_recovery_member",
)

# Public only for exhaustive test enumeration.  The CLI never accepts these.
INSTALL_CHECKPOINTS = (
    "journal:before_write", "journal:before_fsync", "journal:after_fsync", "journal:before_rename", "journal:after_rename", "journal:directory:before_fsync", "journal:directory:after_fsync",
    "archive:archive_manifest:before_fsync", "archive:archive_manifest:after_fsync", "archive:archive_bridge_member:before_fsync", "archive:archive_bridge_member:after_fsync", "archive:archive_source_evidence_member:before_fsync", "archive:archive_source_evidence_member:after_fsync", "archive:archive_recovery_member:before_fsync", "archive:archive_recovery_member:after_fsync", "archive:stage:before_fsync", "archive:stage:after_fsync", "archive:before_rename", "archive:after_rename", "archive:parent:before_fsync", "archive:parent:after_fsync",
    "bridge:bridge_pointer:before_fsync", "bridge:bridge_pointer:after_fsync", "bridge:bridge_manifest:before_fsync", "bridge:bridge_manifest:after_fsync", "bridge:bridge_artifact:before_fsync", "bridge:bridge_artifact:after_fsync", "bridge:stage:before_fsync", "bridge:stage:after_fsync", "bridge:before_rename", "bridge:after_rename", "bridge:parent:before_fsync", "bridge:parent:after_fsync",
    "publication:candidate_manifest:before_fsync", "publication:candidate_manifest:after_fsync", "publication:candidate_transition:before_fsync", "publication:candidate_transition:after_fsync", "publication:candidate_plan:before_fsync", "publication:candidate_plan:after_fsync", "publication:candidate_artifact:before_fsync", "publication:candidate_artifact:after_fsync", "publication:before_fsync", "publication:after_fsync",
    "pointer-journal:before_write", "pointer-journal:before_fsync", "pointer-journal:after_fsync", "pointer-journal:before_rename", "pointer-journal:after_rename", "pointer-journal:directory:before_fsync", "pointer-journal:directory:after_fsync",
    "pointer:before_write", "pointer:before_fsync", "pointer:after_fsync", "pointer:before_rename", "pointer:after_rename", "pointer:directory:before_fsync", "pointer:directory:after_fsync",
    "commit-journal:before_write", "commit-journal:before_fsync", "commit-journal:after_fsync", "commit-journal:before_rename", "commit-journal:after_rename", "commit-journal:directory:before_fsync", "commit-journal:directory:after_fsync",
    "journal-cleanup:before_unlink", "journal-cleanup:before_fsync", "journal-cleanup:after_fsync",
)
assert len(INSTALL_CHECKPOINTS) == 67 and len(set(INSTALL_CHECKPOINTS)) == 67


def _checkpoint_classification(name):
    """Return the recovery class and operation for the closed fault surface."""
    if name not in INSTALL_CHECKPOINTS:
        _fail("EPOCH_PACKAGE_CHECKPOINT", "unexported transaction checkpoint")
    if name.startswith("journal-cleanup:"):
        return "post-pointer", "cleanup"
    if name.startswith("pointer:"):
        return ("pointer-commit" if name == "pointer:after_rename" else
                ("post-pointer" if name.startswith("pointer:directory") else "pre-pointer")), "pointer"
    if name.startswith("commit-journal:"):
        return "post-pointer", "journal"
    if name.startswith("pointer-journal:"):
        return "pre-pointer", "journal"
    if name.startswith("journal:"):
        return "pre-pointer", "journal"
    if name.startswith("archive:"):
        return "pre-pointer", "archive"
    if name.startswith("bridge:"):
        return "pre-pointer", "bridge"
    if name.startswith("publication:"):
        return "pre-pointer", "publication member"
    _fail("EPOCH_PACKAGE_CHECKPOINT", "checkpoint has no recovery class")


INSTALL_CHECKPOINT_CLASSES = tuple((name,) + _checkpoint_classification(name)
                                   for name in INSTALL_CHECKPOINTS)

# This is deliberately process-local and identity based.  A serialized or
# reconstructed object cannot become an installation authority.
_LIVE_CAPABILITIES = set()


@dataclass(frozen=True)
class VerifiedInstallPackage:
    _root: Path
    _commitment: str
    _files: tuple
    _summary: tuple
    _token: object

    def __reduce__(self):
        raise TypeError("VerifiedInstallPackage is session-bound")


def _capability_summary(capability):
    return dict(capability._summary)


class PackageError(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def _fail(code, message):
    raise PackageError(code, message)


def _checkpoint(fault, label):
    """Test-only crash boundary.  The CLI never supplies this callback.

    A callback may raise ``BaseException`` to model abrupt process death.  A
    legacy string is retained only for existing disposable rehearsal scripts.
    """
    if fault is None:
        return
    if label not in INSTALL_CHECKPOINTS:
        _fail("EPOCH_PACKAGE_CHECKPOINT", "unexported transaction checkpoint")
    if callable(fault):
        fault(label)
    elif fault == label:
        raise PackageError("EPOCH_PACKAGE_INTERRUPTED", "test interruption")


def _absolute(path, output=False):
    path = Path(path)
    if not path.is_absolute():
        _fail("EPOCH_PACKAGE_PATH", "all paths must be absolute")
    if output:
        if path.exists() or path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
            _fail("EPOCH_PACKAGE_PATH", "output must be a new child of a regular directory")
        return path
    if not path.is_dir() or path.is_symlink():
        _fail("EPOCH_PACKAGE_PATH", "root must be a regular directory")
    return path.resolve(strict=True)


def _safe_rel(value):
    if type(value) is not str or not value or len(value) > 512:
        _fail("EPOCH_PACKAGE_LOCATOR", "invalid relative locator")
    bits = value.split("/")
    if value.startswith("/") or "\\" in value or any(x in ("", ".", "..") for x in bits):
        _fail("EPOCH_PACKAGE_LOCATOR", "unsafe relative locator")
    return value


def _hex(value, code="EPOCH_PACKAGE_HASH"):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        _fail(code, "expected lower-case SHA-256")
    return value


def _held_open(root, relative):
    """Open a regular child using dir-fds and O_NOFOLLOW for every component."""
    relative = _safe_rel(relative)
    fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = relative.split("/")
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = next_fd
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        st = os.fstat(leaf)
        if not stat.S_ISREG(st.st_mode):
            os.close(leaf); _fail("EPOCH_PACKAGE_FILE", "input is not a regular file")
        return fd, leaf, st
    except Exception:
        os.close(fd)
        raise


def _read(root, relative, maximum=MAX_PACKAGE_BYTES):
    parent, fd, before = _held_open(root, relative)
    try:
        if before.st_size > maximum: _fail("EPOCH_PACKAGE_BOUNDS", "input exceeds package bound")
        chunks = []
        while True:
            chunk = os.read(fd, min(1024 * 1024, maximum + 1))
            if not chunk: break
            chunks.append(chunk)
            if sum(map(len, chunks)) > maximum: _fail("EPOCH_PACKAGE_BOUNDS", "input exceeds package bound")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            _fail("EPOCH_PACKAGE_RACE", "input changed while read")
        return b"".join(chunks), before
    finally:
        os.close(fd); os.close(parent)


def _digest(root, relative):
    parent, fd, before = _held_open(root, relative)
    try:
        if before.st_size > MAX_PACKAGE_BYTES: _fail("EPOCH_PACKAGE_BOUNDS", "input exceeds package bound")
        digest = hashlib.sha256(); total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk: break
            total += len(chunk)
            if total > MAX_PACKAGE_BYTES: _fail("EPOCH_PACKAGE_BOUNDS", "input exceeds package bound")
            digest.update(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            _fail("EPOCH_PACKAGE_RACE", "input changed while hashed")
        return digest.hexdigest(), total
    finally:
        os.close(fd); os.close(parent)


def _json(root, relative, maximum=MAX_MANIFEST_BYTES):
    raw, _ = _read(root, relative, maximum)
    try:
        return parse_json(raw), raw
    except V2ValidationError as exc:
        raise PackageError("EPOCH_PACKAGE_JSON", "invalid bounded package JSON") from exc


def _pointer(root):
    value, raw = _json(root, "current.json")
    if type(value) is not dict or set(value) != {"schema", "manifest", "manifest_sha256", "published_at"} or value["schema"] != "flop-scout-router-current/v2":
        _fail("EPOCH_PACKAGE_POINTER", "pointer shape is unsupported")
    _safe_rel(value["manifest"]); _hex(value["manifest_sha256"])
    digest, _ = _digest(root, value["manifest"])
    if digest != value["manifest_sha256"]: _fail("EPOCH_PACKAGE_POINTER", "pointer manifest hash differs")
    return value, raw


def _publication_identity(root, pointer):
    manifest, _ = _json(root, pointer["manifest"])
    def number(value):
        if type(value) is int and value >= 1: return value
        if type(value) is str and value.isdecimal() and (value == "0" or not value.startswith("0")) and int(value) >= 1: return int(value)
        _fail("EPOCH_PACKAGE_MANIFEST", "manifest publication identity is invalid")
    if type(manifest) is not dict:
        _fail("EPOCH_PACKAGE_MANIFEST", "manifest publication identity is invalid")
    return manifest, (number(manifest.get("snapshot_id")), number(manifest.get("database_content_id")))


def _file(role, locator, root):
    locator = _safe_rel(locator); digest, size = _digest(root, locator)
    return {"role": role, "locator": locator, "sha256": digest, "size_bytes": size}


def _files_index(files):
    if type(files) is not list or len(files) != len(ROLES): _fail("EPOCH_PACKAGE_FILES", "package roles are incomplete")
    result = {}
    seen_roles = []
    for item in files:
        if type(item) is not dict or set(item) != {"role", "locator", "sha256", "size_bytes"}:
            _fail("EPOCH_PACKAGE_FILES", "package file entry is malformed")
        role = item["role"]
        if role not in ROLES or role in result: _fail("EPOCH_PACKAGE_FILES", "duplicate or unsupported package role")
        _safe_rel(item["locator"]); _hex(item["sha256"])
        if type(item["size_bytes"]) is not int or not 0 < item["size_bytes"] <= MAX_PACKAGE_BYTES:
            _fail("EPOCH_PACKAGE_FILES", "package file size is invalid")
        result[role] = item
        seen_roles.append(role)
    if tuple(seen_roles) != ROLES:
        _fail("EPOCH_PACKAGE_FILES", "package roles are not in canonical order")
    return result


def _package_manifest(value):
    fields = {"schema", "accepted_anchor", "bridge_predecessor", "bridge_binding_sha256", "target", "files", "package_commitment_sha256"}
    if type(value) is not dict or set(value) != fields or value["schema"] != SCHEMA:
        _fail("EPOCH_PACKAGE_SCHEMA", "unsupported package schema")
    _hex(value["bridge_binding_sha256"]); _hex(value["package_commitment_sha256"])
    if value["package_commitment_sha256"] != commitment("install-package", {k: v for k, v in value.items() if k != "package_commitment_sha256"}):
        _fail("EPOCH_PACKAGE_COMMITMENT", "package commitment differs")
    if type(value["target"]) is not dict or set(value["target"]) != {"publication_id", "content_id", "epoch_id"}:
        _fail("EPOCH_PACKAGE_TARGET", "target identity is malformed")
    if type(value["target"]["publication_id"]) is not int or type(value["target"]["content_id"]) is not int or type(value["target"]["epoch_id"]) is not str:
        _fail("EPOCH_PACKAGE_TARGET", "target identity is malformed")
    _files_index(value["files"])
    return value


def _copy_held(source_root, locator, target, fault=None, label=None):
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(target.parent, 0o700)
    parent, fd, before = _held_open(source_root, locator)
    try:
        out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk: break
                os.write(out, chunk)
            _checkpoint(fault, (label or "copy") + ":before_fsync")
            os.fsync(out)
            _checkpoint(fault, (label or "copy") + ":after_fsync")
        finally: os.close(out)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            _fail("EPOCH_PACKAGE_RACE", "input changed while copied")
    finally:
        os.close(fd); os.close(parent)


def _fsync_dir(path, fault=None, label=None):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        _checkpoint(fault, (label or "directory") + ":before_fsync")
        os.fsync(fd)
        _checkpoint(fault, (label or "directory") + ":after_fsync")
    finally: os.close(fd)


def _archive_members(archive_root, manifest):
    members = manifest.get("members") if type(manifest) is dict else None
    if type(members) is not list or len(members) != 3: _fail("EPOCH_PACKAGE_ARCHIVE", "archive member list is invalid")
    out = {}
    for member in members:
        if type(member) is not dict: _fail("EPOCH_PACKAGE_ARCHIVE", "archive member is invalid")
        role = member.get("role")
        if role not in {"bridge_projection_sqlite", "source_evidence_sqlite", "legacy_recovery_json"} or role in out:
            _fail("EPOCH_PACKAGE_ARCHIVE", "archive roles are invalid")
        locator = member.get("locator"); digest = member.get("sha256"); size = member.get("size_bytes")
        _safe_rel(locator); _hex(digest)
        actual, actual_size = _digest(archive_root, locator)
        if (actual, actual_size) != (digest, size): _fail("EPOCH_PACKAGE_ARCHIVE", "archive member differs")
        out[role] = locator
    return out


def prepare(candidate_root, archive_root, bridge_root, package_root, disk_budget):
    """Create a complete package below a new explicit package root."""
    candidate_root = _absolute(candidate_root); archive_root = _absolute(archive_root); bridge_root = _absolute(bridge_root)
    package_root = _absolute(package_root, output=True)
    if type(disk_budget) is not int or disk_budget < MIN_RESERVE_BYTES: _fail("EPOCH_PACKAGE_DISK", "disk budget is too small")
    pointer, pointer_raw = _pointer(candidate_root)
    manifest, _ = _json(candidate_root, pointer["manifest"])
    transition_ref = manifest.get("epoch_transition") if type(manifest) is dict else None
    if type(transition_ref) is not dict: _fail("EPOCH_PACKAGE_CANDIDATE", "candidate lacks epoch transition")
    transition_raw, _ = _read(candidate_root, transition_ref.get("locator", ""), MAX_MANIFEST_BYTES)
    transition = parse_json(transition_raw)
    validate_transition(transition, transition["accepted_anchor"], 0, True)
    validate_v2_manifest(manifest, transition)
    if pointer["manifest_sha256"] != hashlib.sha256(_read(candidate_root, pointer["manifest"], MAX_MANIFEST_BYTES)[0]).hexdigest():
        _fail("EPOCH_PACKAGE_CANDIDATE", "candidate pointer differs from manifest")
    plan_locator = transition["active_set_plan"]["locator"]
    plan_raw, _ = _read(candidate_root, plan_locator, 16 * 1024 * 1024)
    validate_active_set_plan_bytes(plan_raw, transition)
    for locator, digest, size in ((manifest["database"], manifest["sha256"], manifest["size_bytes"]), (transition_ref["locator"], transition_ref["sha256"], transition_ref["size_bytes"])):
        actual, actual_size = _digest(candidate_root, locator)
        if (actual, actual_size) != (digest, size): _fail("EPOCH_PACKAGE_CANDIDATE", "candidate descriptor differs")
    bridge_pointer, _ = _pointer(bridge_root)
    bridge_manifest, bridge_identity = _publication_identity(bridge_root, bridge_pointer)
    bridge = transition["bridge_predecessor"]
    if bridge_identity != (bridge["publication_sequence"], bridge["content_id"]): _fail("EPOCH_PACKAGE_BRIDGE", "bridge pointer identity differs")
    if bridge_pointer["manifest_sha256"] != bridge["manifest_sha256"]: _fail("EPOCH_PACKAGE_BRIDGE", "bridge manifest differs")
    if bridge_manifest.get("sha256") != bridge["artifact_sha256"] or bridge_manifest.get("size_bytes") != bridge["artifact_size"]:
        _fail("EPOCH_PACKAGE_BRIDGE", "bridge artifact differs")
    archive_manifest, _ = _json(archive_root, "manifest.json")
    members = _archive_members(archive_root, archive_manifest)
    archive = transition["archive"]
    archive_digest, archive_size = _digest(archive_root, "manifest.json")
    if (archive_digest, archive_size) != (archive.get("artifact_sha256"), archive.get("size_bytes")):
        _fail("EPOCH_PACKAGE_ARCHIVE", "archive manifest identity differs")
    archive_body = {k: v for k, v in archive.items() if k != "archive_commitment_sha256"}
    if archive.get("archive_commitment_sha256") != commitment("archive-descriptor", archive_body):
        _fail("EPOCH_PACKAGE_ARCHIVE", "archive descriptor commitment differs")
    entries = [
        ("candidate_pointer", "publication/current.json", candidate_root, "current.json"),
        ("candidate_manifest", "publication/" + pointer["manifest"], candidate_root, pointer["manifest"]),
        ("candidate_transition", "publication/" + transition_ref["locator"], candidate_root, transition_ref["locator"]),
        ("candidate_plan", "publication/" + plan_locator, candidate_root, plan_locator),
        ("candidate_artifact", "publication/" + manifest["database"], candidate_root, manifest["database"]),
        ("bridge_pointer", "bridge/current.json", bridge_root, "current.json"),
        ("bridge_manifest", "bridge/" + bridge_pointer["manifest"], bridge_root, bridge_pointer["manifest"]),
        ("bridge_artifact", "bridge/" + bridge_manifest["database"], bridge_root, bridge_manifest["database"]),
        ("archive_manifest", "archive/manifest.json", archive_root, "manifest.json"),
        ("archive_bridge_member", "archive/" + members["bridge_projection_sqlite"], archive_root, members["bridge_projection_sqlite"]),
        ("archive_source_evidence_member", "archive/" + members["source_evidence_sqlite"], archive_root, members["source_evidence_sqlite"]),
        ("archive_recovery_member", "archive/" + members["legacy_recovery_json"], archive_root, members["legacy_recovery_json"]),
    ]
    package_root.mkdir(mode=0o700); os.chmod(package_root, 0o700)
    files = []
    try:
        for role, packaged, src_root, src_locator in entries:
            _copy_held(src_root, src_locator, package_root / packaged)
            files.append(_file(role, packaged, package_root))
        value = {"schema": SCHEMA, "accepted_anchor": transition["accepted_anchor"], "bridge_predecessor": bridge,
                 "bridge_binding_sha256": transition["bridge_binding_sha256"],
                 "target": {"publication_id": manifest["snapshot_id"], "content_id": manifest["database_content_id"], "epoch_id": transition["epoch_id"]}, "files": files}
        value["package_commitment_sha256"] = commitment("install-package", value)
        raw = canonical_json(value)
        fd = os.open(package_root / "package.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try: os.write(fd, raw); os.fsync(fd)
        finally: os.close(fd)
        _fsync_dir(package_root)
        return verify(package_root)
    except Exception:
        # Package has not been published anywhere; preserve only a diagnostic-free failed root.
        shutil.rmtree(package_root, ignore_errors=True)
        raise


def verify_install_package(package_root):
    """Perform mandatory semantic validation and mint a live install capability."""
    package_root = _absolute(package_root)
    value, _ = _json(package_root, "package.json")
    _package_manifest(value); files = _files_index(value["files"])
    total = 0
    for item in files.values():
        digest, size = _digest(package_root, item["locator"])
        if (digest, size) != (item["sha256"], item["size_bytes"]): _fail("EPOCH_PACKAGE_FILE", "packaged file differs")
        total += size
    if total > MAX_PACKAGE_BYTES: _fail("EPOCH_PACKAGE_BOUNDS", "package exceeds bounded size")
    # Re-use the package-local paths through a tiny read-only structural root.
    candidate = package_root / "publication"; bridge = package_root / "bridge"; archive = package_root / "archive"
    pointer, _ = _pointer(candidate); manifest, _ = _json(candidate, pointer["manifest"])
    transition_raw, _ = _read(candidate, manifest["epoch_transition"]["locator"], MAX_MANIFEST_BYTES)
    transition = parse_json(transition_raw); validate_transition(transition, value["accepted_anchor"], 0, True); validate_v2_manifest(manifest, transition)
    plan_raw, _ = _read(candidate, transition["active_set_plan"]["locator"], 16 * 1024 * 1024); validate_active_set_plan_bytes(plan_raw, transition)
    if value["bridge_predecessor"] != transition["bridge_predecessor"] or value["bridge_binding_sha256"] != transition["bridge_binding_sha256"]:
        _fail("EPOCH_PACKAGE_BINDING", "package bridge binding differs")
    bridge_pointer, _ = _pointer(bridge); _, bridge_identity = _publication_identity(bridge, bridge_pointer)
    if bridge_identity != (transition["bridge_predecessor"]["publication_sequence"], transition["bridge_predecessor"]["content_id"]): _fail("EPOCH_PACKAGE_BRIDGE", "packaged bridge differs")
    archive_manifest, _ = _json(archive, "manifest.json"); _archive_members(archive, archive_manifest)
    archive_digest, archive_size = _digest(archive, "manifest.json")
    if (archive_digest, archive_size) != (transition["archive"]["artifact_sha256"], transition["archive"]["size_bytes"]):
        _fail("EPOCH_PACKAGE_ARCHIVE", "packaged archive differs")
    inventory = tuple((item["role"], item["locator"], item["sha256"], item["size_bytes"])
                      for item in files.values())
    summary = {"schema": SCHEMA, "package_commitment_sha256": value["package_commitment_sha256"], "package_bytes": total, "target": value["target"]}
    token = object(); _LIVE_CAPABILITIES.add(token)
    return VerifiedInstallPackage(package_root, value["package_commitment_sha256"], inventory,
                                  tuple(summary.items()), token)


def verify(package_root):
    return _capability_summary(verify_install_package(package_root))


def _atomic_write(path, raw, fault=None, label="write"):
    stage = path.parent / ("." + path.name + ".stage-" + next(tempfile._get_candidate_names()))
    fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        _checkpoint(fault, label + ":before_write")
        os.write(fd, raw)
        _checkpoint(fault, label + ":before_fsync")
        os.fsync(fd)
        _checkpoint(fault, label + ":after_fsync")
    finally: os.close(fd)
    _checkpoint(fault, label + ":before_rename")
    os.replace(stage, path)
    _checkpoint(fault, label + ":after_rename")
    _fsync_dir(path.parent, fault, label + ":directory")


def _same_or_missing(path, source_root, locator):
    if not path.exists(): return False
    if path.is_symlink() or not path.is_file(): _fail("EPOCH_PACKAGE_CONFLICT", "existing target is not a regular file")
    digest, size = _digest(source_root, locator)
    # Keep this compatible with the supported Python 3.9 runtime; file_digest
    # was only added in later Python releases.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode): _fail("EPOCH_PACKAGE_CONFLICT", "existing target is not a regular file")
        hasher = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk: break
            hasher.update(chunk)
        actual = hasher.hexdigest()
    finally:
        os.close(fd)
    if path.stat().st_size != size or actual != digest: _fail("EPOCH_PACKAGE_CONFLICT", "existing target conflicts")
    return True


def _install_tree(package_root, target_root, prefix, files, fault=None, label="tree"):
    if target_root.exists():
        if target_root.is_symlink() or not target_root.is_dir(): _fail("EPOCH_PACKAGE_CONFLICT", "destination root conflicts")
        for item in files:
            relative = item["locator"][len(prefix):]
            _same_or_missing(target_root / relative, package_root, item["locator"])
        return
    stage = target_root.parent / ("." + target_root.name + ".stage-" + next(tempfile._get_candidate_names()))
    stage.mkdir(mode=0o700)
    try:
        for item in files:
            relative = item["locator"][len(prefix):]
            _copy_held(package_root, item["locator"], stage / relative, fault, label + ":" + item["role"])
        _fsync_dir(stage, fault, label + ":stage")
        _checkpoint(fault, label + ":before_rename")
        os.rename(stage, target_root)
        _checkpoint(fault, label + ":after_rename")
        _fsync_dir(target_root.parent, fault, label + ":parent")
    except Exception:
        shutil.rmtree(stage, ignore_errors=True); raise


def install(package_root, publication_root, archive_root, bridge_root, disk_budget, reserve_bytes=MIN_RESERVE_BYTES, fault=None):
    """Install package content atomically; the publication pointer is always last.

    ``fault`` is a test-only named interruption hook.  It is intentionally not
    exposed by the CLI.
    """
    capability = verify_install_package(package_root)
    return _install_verified_package(capability, publication_root, archive_root, bridge_root,
                                     disk_budget, reserve_bytes, fault)


def _install_verified_package(capability, publication_root, archive_root, bridge_root, disk_budget, reserve_bytes=MIN_RESERVE_BYTES, fault=None):
    """Transaction stage: only a currently-live verified capability is accepted."""
    if type(capability) is not VerifiedInstallPackage or capability._token not in _LIVE_CAPABILITIES:
        _fail("EPOCH_PACKAGE_CAPABILITY", "install requires a live verified package")
    package_root = _absolute(capability._root); publication_root = _absolute(publication_root)
    archive_root = _absolute(archive_root, output=not Path(archive_root).exists()) if not Path(archive_root).exists() else _absolute(archive_root)
    bridge_root = _absolute(bridge_root, output=not Path(bridge_root).exists()) if not Path(bridge_root).exists() else _absolute(bridge_root)
    # Re-verify inventory immediately before any write.  A changed package
    # invalidates the session capability rather than becoming a TOCTOU input.
    current = verify_install_package(package_root)
    if current._commitment != capability._commitment or current._files != capability._files:
        _fail("EPOCH_PACKAGE_CAPABILITY", "package changed after verification")
    summary = _capability_summary(capability); value, _ = _json(package_root, "package.json"); files = _files_index(value["files"])
    if type(disk_budget) is not int or type(reserve_bytes) is not int or reserve_bytes < MIN_RESERVE_BYTES or disk_budget < summary["package_bytes"] + reserve_bytes:
        _fail("EPOCH_PACKAGE_DISK", "configured disk budget is insufficient")
    if shutil.disk_usage(publication_root).free < summary["package_bytes"] + reserve_bytes: _fail("EPOCH_PACKAGE_DISK", "available disk space is insufficient")
    lock_path = publication_root / LOCK
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try: fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: _fail("EPOCH_PACKAGE_LOCK", "another installation holds the lock")
        journal = publication_root / JOURNAL
        if journal.exists(): _fail("EPOCH_PACKAGE_JOURNAL", "interrupted installation requires recover")
        old_pointer, old_raw = _pointer(publication_root); _, old_identity = _publication_identity(publication_root, old_pointer)
        bridge = value["bridge_predecessor"]
        if (*old_identity, old_pointer["manifest_sha256"]) != (bridge["publication_sequence"], bridge["content_id"], bridge["manifest_sha256"]):
            _fail("EPOCH_PACKAGE_ANCHOR", "current publication is not package bridge")
        state = {"schema": SCHEMA + "-journal", "state": "precommit", "old_pointer_sha256": hashlib.sha256(old_raw).hexdigest(), "target": value["target"]}
        _atomic_write(journal, canonical_json(state), fault, "journal")
        _install_tree(package_root, archive_root, "archive/", [files[x] for x in ("archive_manifest", "archive_bridge_member", "archive_source_evidence_member", "archive_recovery_member")], fault, "archive")
        _install_tree(package_root, bridge_root, "bridge/", [files[x] for x in ("bridge_pointer", "bridge_manifest", "bridge_artifact")], fault, "bridge")
        for name in ("candidate_manifest", "candidate_transition", "candidate_plan", "candidate_artifact"):
            item = files[name]; relative = item["locator"][len("publication/"):]; target = publication_root / relative
            if not _same_or_missing(target, package_root, item["locator"]): _copy_held(package_root, item["locator"], target, fault, "publication:" + name)
        _fsync_dir(publication_root, fault, "publication")
        pointer_item = files["candidate_pointer"]
        candidate_raw, _ = _read(package_root, pointer_item["locator"], MAX_MANIFEST_BYTES)
        state["state"] = "pointer_pending"; _atomic_write(journal, canonical_json(state), fault, "pointer-journal")
        _atomic_write(publication_root / "current.json", candidate_raw, fault, "pointer")
        state["state"] = "pointer_committed"; _atomic_write(journal, canonical_json(state), fault, "commit-journal")
        now, _ = _pointer(publication_root)
        if now != _pointer(package_root / "publication")[0]: _fail("EPOCH_PACKAGE_COMMIT", "pointer failed post-commit validation")
        _checkpoint(fault, "journal-cleanup:before_unlink")
        journal.unlink()
        _fsync_dir(publication_root, fault, "journal-cleanup")
        return summary
    finally:
        try: fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
            _LIVE_CAPABILITIES.discard(capability._token)


def close_verified_install_package(capability):
    """Explicitly retire a capability without performing any install."""
    if type(capability) is not VerifiedInstallPackage:
        _fail("EPOCH_PACKAGE_CAPABILITY", "invalid package capability")
    _LIVE_CAPABILITIES.discard(capability._token)


def recover(publication_root):
    publication_root = _absolute(publication_root)
    journal = publication_root / JOURNAL
    if not journal.exists(): return {"state": "no-journal"}
    value, _ = _json(publication_root, JOURNAL)
    if type(value) is not dict or set(value) != {"schema", "state", "old_pointer_sha256", "target"} or value.get("schema") != SCHEMA + "-journal" or value.get("state") not in {"precommit", "pointer_pending", "pointer_committed"}:
        _fail("EPOCH_PACKAGE_JOURNAL", "journal is unsupported")
    _hex(value["old_pointer_sha256"], "EPOCH_PACKAGE_JOURNAL")
    if type(value["target"]) is not dict or set(value["target"]) != {"publication_id", "content_id", "epoch_id"}:
        _fail("EPOCH_PACKAGE_JOURNAL", "journal target is unsupported")
    if value["state"] == "pointer_committed":
        pointer, _ = _pointer(publication_root); _, pointer_identity = _publication_identity(publication_root, pointer)
        target = value.get("target", {})
        if pointer_identity != (target.get("publication_id"), target.get("content_id")):
            _fail("EPOCH_PACKAGE_JOURNAL", "committed pointer differs from journal target")
        journal.unlink(); _fsync_dir(publication_root); return {"state": "committed"}
    # Before pointer commit, the current pointer was never replaced.  Immutable
    # archive/bridge directories intentionally remain retained; no cleanup may prune them.
    journal.unlink(); _fsync_dir(publication_root); return {"state": "precommit-abandoned"}


def status(package_root=None, publication_root=None):
    result = {}
    if package_root is not None: result["package"] = verify(package_root)
    if publication_root is not None:
        root = _absolute(publication_root); pointer, raw = _pointer(root); _, identity = _publication_identity(root, pointer)
        result["publication"] = {"publication_id": identity[0], "content_id": identity[1], "pointer_sha256": hashlib.sha256(raw).hexdigest(), "journal": (root / JOURNAL).exists()}
    return result


def _main(argv=None):
    parser = argparse.ArgumentParser(description="Prepare, verify and atomically install a Scout Epoch V2 package.")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare"); p.add_argument("--candidate-root", required=True); p.add_argument("--archive-root", required=True); p.add_argument("--bridge-root", required=True); p.add_argument("--package-root", required=True); p.add_argument("--disk-budget", required=True, type=int)
    p = sub.add_parser("verify"); p.add_argument("--package-root", required=True)
    p = sub.add_parser("install"); p.add_argument("--package-root", required=True); p.add_argument("--publication-root", required=True); p.add_argument("--archive-root", required=True); p.add_argument("--bridge-root", required=True); p.add_argument("--disk-budget", required=True, type=int); p.add_argument("--reserve-bytes", type=int, default=MIN_RESERVE_BYTES)
    p = sub.add_parser("recover"); p.add_argument("--publication-root", required=True)
    p = sub.add_parser("status"); p.add_argument("--package-root"); p.add_argument("--publication-root")
    ns = parser.parse_args(argv)
    if ns.command == "prepare": value = prepare(ns.candidate_root, ns.archive_root, ns.bridge_root, ns.package_root, ns.disk_budget)
    elif ns.command == "verify": value = verify(ns.package_root)
    elif ns.command == "install": value = install(ns.package_root, ns.publication_root, ns.archive_root, ns.bridge_root, ns.disk_budget, ns.reserve_bytes)
    elif ns.command == "recover": value = recover(ns.publication_root)
    else: value = status(ns.package_root, ns.publication_root)
    print(canonical_json(value).decode("ascii"))


if __name__ == "__main__":
    try: _main()
    except PackageError as exc:
        raise SystemExit("%s: %s" % (exc.code, exc))
