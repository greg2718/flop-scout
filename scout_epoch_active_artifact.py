"""V2-only, descriptor-bound construction of a bounded active projection.

This module never chooses records, publishes, or consults a production path.
It receives every input explicitly, rederives the approved plan from read-only
evidence, and atomically creates one new local SQLite artifact.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import uuid
from pathlib import Path

from scout_epoch_active_set_adapter import ActiveSetError, build_plan
from scout_epoch_active_set_plan import ActiveSetPlanError, read as read_active_set_plan
from scout_projection_contract import REVISIONS, digest, instant, policy_for, sql_for
from scout_projection_publish import validate_database


MAX_PLAN_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 50000
_PLAN_CORE = frozenset((
    "selection_policy_version", "source_cut", "predecessor_epoch_id", "archive_commitment",
    "mandatory_record_ids", "optional_record_ids", "selected_record_ids", "omitted_record_ids",
    "mandatory_reasons", "counts_by_domain", "retained_floor_proposal", "capacity", "plan_sha256",
    "eligible_count", "selected", "omitted", "recovery_commitment", "archive_manifest_sha256",
    "retained_floor_commitment_sha256", "omission_commitment_sha256",
))


class ActiveArtifactError(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def _fail(code, message):
    raise ActiveArtifactError(code, message)


def _path(value, label, output=False):
    path = Path(value)
    if not path.is_absolute():
        _fail("ACTIVE_ARTIFACT_PATH", label + " must be absolute")
    if output:
        if path.exists() or path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
            _fail("ACTIVE_ARTIFACT_PATH", "output must be a nonexistent child of a regular directory")
        return path
    if not path.is_file() or path.is_symlink():
        _fail("ACTIVE_ARTIFACT_PATH", label + " must be a regular file")
    return path.resolve(strict=True)


def _strict_plan(path):
    path = _path(path, "plan")
    if path.stat().st_size > MAX_PLAN_BYTES:
        _fail("ACTIVE_ARTIFACT_PLAN", "approved plan exceeds the bounded input limit")
    raw = path.read_bytes()
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _fail("ACTIVE_ARTIFACT_PLAN", "approved plan has duplicate JSON keys")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _value: _fail("ACTIVE_ARTIFACT_PLAN", "non-finite plan value"))
    except ActiveArtifactError:
        raise
    except (UnicodeDecodeError, ValueError) as exc:
        raise ActiveArtifactError("ACTIVE_ARTIFACT_PLAN", "approved plan is invalid JSON") from exc
    if not isinstance(value, dict) or not _PLAN_CORE <= set(value):
        _fail("ACTIVE_ARTIFACT_PLAN", "approved plan is incomplete")
    if len(value["selected_record_ids"]) > MAX_RECORDS or len(value["omitted_record_ids"]) > MAX_RECORDS:
        _fail("ACTIVE_ARTIFACT_PLAN", "approved plan exceeds active-set capacity")
    return value


def _same_plan(approved, derived):
    return all(approved.get(key) == derived.get(key) for key in _PLAN_CORE)


def _same_sidecar(sidecar, derived):
    """Compare exact redacted row identities; SQLite bytes remain A1-compatible."""
    def rows(items):
        return {(row["projection_row_id"], row["raw_record_id"], row["raw_text_sha256"], str(row["scout_event_id"]))
                for row in items}
    if sidecar["counts"] != {"selected": len(derived["selected"]), "omitted": len(derived["omitted"]), "eligible": derived["eligible_count"]}:
        return False
    return (rows(sidecar["selected"]) == rows(derived["selected"]) and
            rows(sidecar["omitted"]) == rows(derived["omitted"]) and
            sidecar["recovery_commitment_sha256"] == derived["recovery_commitment"] and
            sidecar["retained_floor_commitment_sha256"] == derived["retained_floor_commitment_sha256"] and
            sidecar["omission_commitment_sha256"] == derived["omission_commitment_sha256"])


def _input_hash(path):
    digest_ = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest_.update(block)
    info = path.stat()
    return {"sha256": digest_.hexdigest(), "size_bytes": info.st_size, "mtime_ns": info.st_mtime_ns}


def _archive_inputs(root):
    root = Path(root)
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        _fail("ACTIVE_ARTIFACT_PATH", "archive root must be an explicit regular directory")
    paths = (root / "manifest.json", root / "members/bridge-projection.sqlite",
             root / "members/source-evidence.sqlite", root / "members/legacy-recovery.json")
    if any(not path.is_file() or path.is_symlink() for path in paths):
        _fail("ACTIVE_ARTIFACT_PATH", "archive inputs are incomplete or unsafe")
    return tuple(path.resolve(strict=True) for path in paths)


def _create(path, contract_revision):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(sql_for(contract_revision))
    return conn


def _copy_selected(out, bridge, selected_rows):
    """Copy only plan-selected message families in plan order, with bounded batches."""
    ids_in_order = [row["projection_row_id"] for row in selected_rows]
    hashes = {row["projection_row_id"]: row["raw_text_sha256"] for row in selected_rows}
    for offset in range(0, len(ids_in_order), 200):
        ids = ids_in_order[offset:offset + 200]
        found = {row["projection_row_id"]: row for row in bridge.execute(
            "SELECT * FROM messages WHERE projection_row_id IN (" + ",".join("?" for _ in ids) + ")", ids)}
        if set(found) != set(ids):
            _fail("ACTIVE_ARTIFACT_SELECTION", "selected message is missing from bridge projection")
        for key in ids:
            row = found[key]
            out.execute("INSERT INTO messages VALUES(" + ",".join("?" for _ in row) + ")", tuple(row))
    for table in ("selection_membership", "source_provenance"):
        for offset in range(0, len(ids_in_order), 200):
            ids = ids_in_order[offset:offset + 200]
            found = {row["projection_row_id"]: row for row in bridge.execute(
                "SELECT * FROM " + table + " WHERE entity_type='message' AND projection_row_id IN (" + ",".join("?" for _ in ids) + ")", ids)}
            if set(found) != set(ids):
                _fail("ACTIVE_ARTIFACT_SELECTION", "selected membership or provenance is missing")
            for key in ids:
                row = dict(found[key])
                if table == "source_provenance":
                    row["raw_record_sha256"] = hashes[key]
                out.execute("INSERT INTO " + table + " VALUES(" + ",".join("?" for _ in row) + ")", tuple(row.values()))


def _copy_full(out, bridge, table, order):
    rows = bridge.execute("SELECT * FROM " + table + " ORDER BY " + order)
    for row in rows:
        out.execute("INSERT INTO " + table + " VALUES(" + ",".join("?" for _ in row) + ")", tuple(row))


def _watermarks(out):
    rows = list(out.execute("SELECT room,generation,count(*) AS record_count,min(seq) AS min_seq,max(seq) AS max_seq FROM messages GROUP BY room,generation ORDER BY room,generation"))
    for row in rows:
        out.execute("INSERT INTO watermarks VALUES(?,?,?,?,?)", tuple(row))
    return [dict(row) for row in rows]


def _validate_plan_rows(path, bridge_path, plan):
    """Check exact plan membership and all retained closure facts without text output."""
    conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    old = sqlite3.connect(bridge_path.as_uri() + "?mode=ro", uri=True)
    conn.row_factory = old.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA query_only=ON"); old.execute("PRAGMA query_only=ON")
        selected = {row["projection_row_id"]: row for row in plan["selected"]}
        omitted = {row["projection_row_id"] for row in plan["omitted"]}
        if (len(selected) != plan["capacity"].get("selected_count") or
                len(omitted) != plan.get("eligible_count", -1) - len(selected) or set(selected) & omitted):
            _fail("ACTIVE_ARTIFACT_PLAN", "approved plan does not have the configured cardinalities")
        for table in ("messages", "selection_membership", "source_provenance"):
            ids = {row[0] for row in conn.execute("SELECT projection_row_id FROM " + table + " WHERE entity_type='message'" if table != "messages" else "SELECT projection_row_id FROM messages")}
            if ids != set(selected) or ids & omitted:
                _fail("ACTIVE_ARTIFACT_SELECTION", "artifact selected/omitted rows differ from plan")
        for row in conn.execute("SELECT projection_row_id,raw_record_id,raw_record_sha256,scout_event_id FROM source_provenance WHERE entity_type='message'"):
            expected = selected[row["projection_row_id"]]
            if (row["raw_record_id"] != expected["raw_record_id"] or row["raw_record_sha256"] != expected["raw_text_sha256"] or
                    row["raw_record_sha256"] is None or str(row["scout_event_id"]) != expected["scout_event_id"]):
                _fail("ACTIVE_ARTIFACT_PROVENANCE", "selected recovered provenance differs from plan")
        for table, key, payload in (("durable_qualifications", "qualification_id", "record_json"),
                                    ("qualification_events", "event_id", "event_json"),
                                    ("coverage_history", "room || char(0) || generation", "max_ever_projected_seq || char(0) || witness_source_locator || char(0) || witness_record_sha256")):
            before = [tuple(row) for row in old.execute("SELECT " + key + "," + payload + " FROM " + table + " ORDER BY 1")]
            after = [tuple(row) for row in conn.execute("SELECT " + key + "," + payload + " FROM " + table + " ORDER BY 1")]
            if before != after:
                _fail("ACTIVE_ARTIFACT_DEPENDENCY", "required durable or coverage data changed")
        for row in conn.execute("SELECT witness_source_locator FROM coverage_history"):
            if "sm1:" + row[0] not in selected:
                _fail("ACTIVE_ARTIFACT_COVERAGE", "coverage witness was not selected")
        if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
            _fail("ACTIVE_ARTIFACT_FOREIGN_KEY", "candidate foreign keys are invalid")
    finally:
        old.close(); conn.close()


def build(projection_path, source_evidence_path, archive_root, plan_path, authorized_descriptor,
          observed_descriptor, archive_context, archive_descriptor, expected_manifest_sha256,
          candidate_content_id, candidate_source_cut, created_at, contract_revision, output_path,
          sidecar_path=None, sidecar_descriptor=None):
    """Atomically build one V2-only local active artifact from explicit inputs."""
    projection_path = _path(projection_path, "bridge projection")
    source_evidence_path = _path(source_evidence_path, "source evidence")
    output_path = _path(output_path, "output", output=True)
    if projection_path == source_evidence_path:
        _fail("ACTIVE_ARTIFACT_PATH", "bridge projection and source evidence must differ")
    if type(candidate_content_id) is not int or candidate_content_id < 0:
        _fail("ACTIVE_ARTIFACT_CONTENT", "candidate content ID is invalid")
    if contract_revision not in REVISIONS:
        _fail("ACTIVE_ARTIFACT_SCHEMA", "candidate contract revision is unsupported")
    if type(candidate_source_cut) is not int or candidate_source_cut < 0 or candidate_source_cut != authorized_descriptor.get("source_cut"):
        _fail("ACTIVE_ARTIFACT_SOURCE_CUT", "candidate source cut must equal the authorized bridge cut")
    try:
        instant(created_at)
    except Exception as exc:
        raise ActiveArtifactError("ACTIVE_ARTIFACT_CREATED_AT", "created_at must be caller-supplied canonical UTC") from exc
    approved = _strict_plan(plan_path)
    sidecar = None
    if sidecar_path is not None or sidecar_descriptor is not None:
        if sidecar_path is None or not isinstance(sidecar_descriptor, dict):
            _fail("ACTIVE_ARTIFACT_PLAN", "canonical plan sidecar path and descriptor are both required")
        try:
            sidecar = read_active_set_plan(sidecar_path, sidecar_descriptor)
        except ActiveSetPlanError as exc:
            raise ActiveArtifactError("ACTIVE_ARTIFACT_PLAN", "canonical plan sidecar failed validation: " + exc.code) from exc
    protected_inputs = (projection_path, source_evidence_path, _path(plan_path, "plan"), *_archive_inputs(archive_root))
    before = {str(path): _input_hash(path) for path in protected_inputs}
    try:
        derived = build_plan(projection_path, source_evidence_path, archive_root, authorized_descriptor,
                             observed_descriptor, archive_context, archive_descriptor,
                             expected_manifest_sha256)
    except ActiveSetError as exc:
        raise ActiveArtifactError("ACTIVE_ARTIFACT_INPUT", "archive, recovery, or plan derivation failed: " + exc.code) from exc
    if not _same_plan(approved, derived):
        _fail("ACTIVE_ARTIFACT_PLAN", "approved plan differs from independently derived plan")
    if sidecar is not None and not _same_sidecar(sidecar, derived):
        _fail("ACTIVE_ARTIFACT_PLAN", "canonical sidecar differs from independently derived plan")
    if candidate_source_cut != int(approved["source_cut"]) or approved["archive_manifest_sha256"] != expected_manifest_sha256:
        _fail("ACTIVE_ARTIFACT_PLAN", "candidate cut or archive binding differs from approved plan")
    if (approved["eligible_count"], len(approved["selected"]), len(approved["omitted"]),
            approved["capacity"].get("target")) != (49808, 43840, 5968, 43840):
        _fail("ACTIVE_ARTIFACT_PLAN", "approved plan is not the configured bounded active set")
    if list(approved["selected_record_ids"]) != [row["projection_row_id"] for row in approved["selected"]]:
        _fail("ACTIVE_ARTIFACT_PLAN", "selected record order or hashes are inconsistent")
    stage = output_path.parent / ("." + output_path.name + ".staging-" + uuid.uuid4().hex)
    bridge = sqlite3.connect(projection_path.as_uri() + "?mode=ro", uri=True)
    bridge.row_factory = sqlite3.Row
    bridge.execute("PRAGMA query_only=ON")
    try:
        out = _create(stage, contract_revision)
        try:
            with out:
                out.execute("INSERT INTO snapshot_meta VALUES(?,?,?,?,?)", (1, "scout-router-projection/v2", str(candidate_content_id), created_at, digest(policy_for(contract_revision))))
                _copy_selected(out, bridge, approved["selected"])
                _copy_full(out, bridge, "interactions", "projection_row_id")
                _copy_full(out, bridge, "coverage_history", "room,generation")
                _copy_full(out, bridge, "durable_qualifications", "qualification_id")
                _copy_full(out, bridge, "qualification_events", "qualification_id,sequence")
                _watermarks(out)
            out.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            out.close()
        os.chmod(stage, 0o600)
        try:
            validation = validate_database(stage, contract_revision=contract_revision)
        except Exception as exc:
            raise ActiveArtifactError("ACTIVE_ARTIFACT_SEMANTIC", "existing A1 database validation failed") from exc
        _validate_plan_rows(stage, projection_path, approved)
        fd = os.open(stage, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                _fail("ACTIVE_ARTIFACT_OUTPUT", "staged artifact is not regular")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.link(stage, output_path)
        stage.unlink()
        directory = os.open(output_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        after = {str(path): _input_hash(path) for path in protected_inputs}
        if before != after:
            output_path.unlink()
            _fail("ACTIVE_ARTIFACT_INPUT", "a read-only input changed during construction")
        return {"path": str(output_path), "sha256": _input_hash(output_path)["sha256"], "size_bytes": output_path.stat().st_size,
                "content_id": candidate_content_id, "source_cut": candidate_source_cut,
                "row_counts": validation["row_counts"],
                "inputs_unchanged": True}
    except Exception:
        if stage.exists():
            stage.unlink()
        raise
    finally:
        bridge.close()
