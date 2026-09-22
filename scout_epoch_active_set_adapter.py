"""Read-only, descriptor-bound V2 active-set planning for a legacy-A1 bridge.

This is deliberately an adapter, not an artifact builder.  It validates the
caller-supplied archive and source-evidence member before converting the exact
bridge projection into the normalized inputs accepted by ``scout_epoch_planner``.
No path has a production default and the returned plan contains identifiers and
hashes only--never message text or envelopes.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from scout_epoch_archive import ArchiveError, recovery_bytes, validate as validate_archive
from scout_epoch_planner import HARD_MAX, PlanError, plan
from scout_epoch_source_evidence import SourceEvidenceError, validate as validate_source


HEADROOM = 5904
RESERVE = 256
TARGET = 43840
POLICY_VERSION = "epoch-v2-policy/1"
_HEX = set("0123456789abcdef")


class ActiveSetError(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def _fail(code, message):
    raise ActiveSetError(code, message)


def _sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _set_commitment(domain, entries):
    """Hash a bounded sequence without constructing one giant canonical JSON array."""
    if not isinstance(domain, str) or not domain.isascii():
        _fail("ACTIVE_SET_COMMITMENT", "commitment domain is invalid")
    digest = hashlib.sha256((domain + "\0").encode("ascii"))
    for entry in entries:
        try:
            raw = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                             allow_nan=False).encode("ascii")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ActiveSetError("ACTIVE_SET_COMMITMENT", "commitment entry is invalid") from exc
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def _path(value, label):
    path = Path(value)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        _fail("ACTIVE_SET_PATH", label + " must be an explicit regular file")
    return path.resolve(strict=True)


def _ro(path):
    conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def _hex(value, code):
    if not isinstance(value, str) or len(value) != 64 or set(value) - _HEX:
        _fail(code, "expected lower-case SHA-256")
    return value


def _same_recovery(left, right):
    keys = ("descriptor", "validated_records", "closure_count", "closure", "reason_counts", "commitment")
    try:
        return recovery_bytes({key: left[key] for key in keys}) == recovery_bytes({key: right[key] for key in keys})
    except (KeyError, ArchiveError):
        return False


def _member(manifest, role):
    matches = [item for item in manifest.get("members", []) if item.get("role") == role]
    if len(matches) != 1:
        _fail("ACTIVE_SET_ARCHIVE", "archive member role is missing or ambiguous")
    return matches[0]


def _records(projection_path, source_evidence_path, recovery, expected_count):
    projection, source = _ro(projection_path), _ro(source_evidence_path)
    try:
        required_projection = {"source_provenance", "selection_membership", "messages", "coverage_history"}
        tables = {row[0] for row in projection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not required_projection <= tables:
            _fail("ACTIVE_SET_SCHEMA", "bridge projection schema is incomplete")
        source_tables = {row[0] for row in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"raw_records", "observed_event_witnesses"} <= source_tables:
            _fail("ACTIVE_SET_SCHEMA", "source-evidence schema is incomplete")
        rows = projection.execute(
            "SELECT p.projection_row_id,p.raw_record_id,p.raw_record_sha256,p.scout_event_id,"
            "m.room,m.generation,m.seq,s.retention_class,s.retain_until,s.pin_roots_json "
            "FROM source_provenance p "
            "JOIN messages m ON m.projection_row_id=p.projection_row_id "
            "JOIN selection_membership s ON s.entity_type='message' AND s.projection_row_id=p.projection_row_id "
            "WHERE p.entity_type='message' ORDER BY p.projection_row_id"
        ).fetchall()
        if len(rows) != expected_count or not 1 <= expected_count <= HARD_MAX:
            _fail("ACTIVE_SET_ELIGIBLE_COUNT", "eligible projection count differs from the caller-approved count")
        closure = {item["projection_row_id"]: item for item in recovery.get("closure", [])}
        if len(closure) != recovery.get("closure_count") or len(closure) > TARGET:
            _fail("ACTIVE_SET_CLOSURE", "recovered mandatory closure is invalid or exceeds target")
        coverage = {(row["room"], row["generation"]): row["max_ever_projected_seq"]
                    for row in projection.execute("SELECT room,generation,max_ever_projected_seq FROM coverage_history")}
        if len(coverage) != projection.execute("SELECT count(*) FROM coverage_history").fetchone()[0]:
            _fail("ACTIVE_SET_COVERAGE", "coverage keys are ambiguous")
        result = []
        raw_ids = set()
        for row in rows:
            item = dict(row)
            raw_id = item["raw_record_id"]
            raw = source.execute("SELECT raw_text_sha256 FROM raw_records WHERE raw_record_id=?", (raw_id,)).fetchall()
            event = source.execute("SELECT event_id FROM observed_event_witnesses WHERE raw_record_id=?", (raw_id,)).fetchall()
            if len(raw) != 1 or len(event) != 1:
                _fail("ACTIVE_SET_PROVENANCE", "source-evidence provenance is missing or ambiguous")
            item["raw_text_sha256"] = raw[0]["raw_text_sha256"]
            item["event_id"] = event[0]["event_id"]
            if (not isinstance(raw_id, str) or len(raw_id) != 64 or item["projection_row_id"] != "sm1:" + raw_id or
                    item["raw_record_sha256"] is not None or item["raw_text_sha256"] is None or
                    str(item["scout_event_id"]) != str(item["event_id"])):
                _fail("ACTIVE_SET_PROVENANCE", "eligible provenance is incomplete or inconsistent")
            _hex(raw_id, "ACTIVE_SET_PROVENANCE")
            _hex(item["raw_text_sha256"], "ACTIVE_SET_PROVENANCE")
            if raw_id in raw_ids:
                _fail("ACTIVE_SET_DUPLICATE", "duplicate eligible raw record")
            raw_ids.add(raw_id)
            mandatory = closure.get(item["projection_row_id"])
            if mandatory is not None and (mandatory.get("raw_record_id") != raw_id or
                                          mandatory.get("raw_text_sha256") != item["raw_text_sha256"] or
                                          str(mandatory.get("scout_event_id")) != str(item["event_id"])):
                _fail("ACTIVE_SET_CLOSURE", "recovered closure lost a dependency")
            result.append({
                "record_id": item["projection_row_id"], "content_sha256": item["raw_text_sha256"],
                "source_position": item["event_id"], "room": item["room"], "generation": item["generation"],
                "domain": "messages", "observation_class": item["retention_class"], "recency": item["event_id"],
                "mandatory_reasons": sorted(mandatory["reasons"]) if mandatory else [], "dependencies": [],
                "archive_required": True, "retained_floor": coverage.get((item["room"], item["generation"])),
            })
        if set(closure) - {row["record_id"] for row in result}:
            _fail("ACTIVE_SET_CLOSURE", "mandatory recovery root is absent from eligible projection")
        if any(key not in {(row["room"], row["generation"]) for row in result} for key in coverage):
            _fail("ACTIVE_SET_COVERAGE", "coverage witness has no eligible record")
        return result
    finally:
        projection.close()
        source.close()


def build_plan(projection_path, source_evidence_path, archive_root, authorized_descriptor,
               observed_descriptor, archive_context, archive_descriptor,
               expected_manifest_sha256, expected_eligible_count=49808):
    """Return a deterministic V2 advisory active-set plan from explicit read-only inputs."""
    projection_path = _path(projection_path, "projection path")
    source_evidence_path = _path(source_evidence_path, "source-evidence path")
    if projection_path == source_evidence_path:
        _fail("ACTIVE_SET_PATH", "projection and source-evidence paths must differ")
    _hex(expected_manifest_sha256, "ACTIVE_SET_ARCHIVE")
    if (projection_path.stat().st_size != authorized_descriptor.get("artifact_size") or
            _sha(projection_path) != authorized_descriptor.get("artifact_sha256")):
        _fail("ACTIVE_SET_PROJECTION", "caller-supplied projection differs from authorized descriptor")
    try:
        archived = validate_archive(archive_root, projection_path, authorized_descriptor,
                                   observed_descriptor, archive_context, archive_descriptor)
        manifest = archived["manifest"]
        if archive_descriptor.get("artifact_sha256") != expected_manifest_sha256:
            _fail("ACTIVE_SET_ARCHIVE", "archive descriptor does not bind the approved manifest")
        member = _member(manifest, "source_evidence_sqlite")
        if _sha(source_evidence_path) != member.get("sha256") or source_evidence_path.stat().st_size != member.get("size_bytes"):
            _fail("ACTIVE_SET_ARCHIVE", "external source-evidence bytes differ from archive member")
        independent = validate_source(source_evidence_path, projection_path, authorized_descriptor,
                                      observed_descriptor, archive_context, member)
        if not _same_recovery(independent["recovery"], archived["recovery"]):
            _fail("ACTIVE_SET_RECOVERY", "archive and independently validated recovery differ")
    except (ArchiveError, SourceEvidenceError) as exc:
        _fail("ACTIVE_SET_VALIDATION", "archive or source evidence validation failed: " + exc.code)
    records = _records(projection_path, source_evidence_path, independent["recovery"], expected_eligible_count)
    policy = {"target": TARGET, "headroom": HEADROOM, "reserve": RESERVE, "hard_max": HARD_MAX,
              "selection_policy_version": POLICY_VERSION,
              "source_cut": str(authorized_descriptor["source_cut"]),
              "predecessor_epoch_id": archive_descriptor["previous_epoch_id"],
              "archive_commitment": expected_manifest_sha256, "prior_floors": {}}
    try:
        result = plan(records, policy)
    except PlanError as exc:
        _fail("ACTIVE_SET_PLAN_" + exc.code, "advisory planner rejected validated records")
    index = {row["record_id"]: row for row in records}
    def redacted(ids):
        return [{"projection_row_id": key, "raw_record_id": key[4:], "raw_text_sha256": index[key]["content_sha256"],
                 "scout_event_id": str(index[key]["source_position"])} for key in ids]
    omissions = [{**entry, "archive_manifest_sha256": expected_manifest_sha256,
                  "reason_class": "DETERMINISTIC_OPTIONAL_OMISSION"} for entry in redacted(result["omitted_record_ids"])]
    floors = {"entries": [{"key": key, "retained_floor": value} for key, value in sorted(result["retained_floor_proposal"].items())],
              "selection_policy_version": POLICY_VERSION}
    result.update({"eligible_count": len(records), "selected": redacted(result["selected_record_ids"]),
                   "omitted": omissions, "recovery_commitment": independent["recovery"]["commitment"],
                   "archive_manifest_sha256": expected_manifest_sha256,
                   "retained_floor_commitment_sha256": _set_commitment("scout/epoch-v2/retained-floor-plan/v1", floors["entries"]),
                   "omission_commitment_sha256": _set_commitment("scout/epoch-v2/omitted-history-plan/v1", omissions)})
    return result
