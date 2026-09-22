"""Canonical, redacted V2 active-set plan sidecar.

This module receives a previously descriptor-verified, deterministic planner
result.  It neither opens a production path nor builds a transition, manifest,
or pointer.
"""
from __future__ import annotations

import hashlib
import os
import stat
import uuid
from pathlib import Path

from scout_epoch_v2 import (MAX_PLAN_BYTES, MAX_PLAN_RECORDS, V2ValidationError,
                            active_set_plan_commitment, parse_active_set_plan)
import json


SCHEMA = "flop-scout-epoch-active-set-plan/v1"


class ActiveSetPlanError(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def _fail(code, message):
    raise ActiveSetPlanError(code, message)


def _path(value, output=False):
    path = Path(value)
    if not path.is_absolute(): _fail("ACTIVE_SET_PLAN_PATH", "path must be absolute")
    if output:
        if path.exists() or path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
            _fail("ACTIVE_SET_PLAN_PATH", "output must be a new child of a regular directory")
        return path
    if not path.is_file() or path.is_symlink(): _fail("ACTIVE_SET_PLAN_PATH", "input must be a regular file")
    return path.resolve(strict=True)


def _locator(value):
    if not isinstance(value, str) or not value or len(value) > 256 or value.startswith("/") or ":" in value or "\\" in value or "." in value.split("/") or ".." in value.split("/"):
        _fail("ACTIVE_SET_PLAN_LOCATOR", "locator is not a safe relative identifier")
    return value


def _hex(value, code="ACTIVE_SET_PLAN_HASH"):
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        _fail(code, "expected lower-case SHA-256")
    return value


def _candidate(value):
    if not isinstance(value, dict) or set(value) != {"source_binding", "source_cut"}:
        _fail("ACTIVE_SET_PLAN_SOURCE", "candidate source is incomplete")
    return value


def _records(rows, reasons):
    out = []
    for row in rows:
        try:
            record = {"projection_row_id": row["projection_row_id"], "raw_record_id": row["raw_record_id"],
                      "raw_text_sha256": row["raw_text_sha256"], "scout_event_id": str(row["scout_event_id"]),
                      "reasons": sorted(set(reasons(row)))}
        except (KeyError, TypeError):
            _fail("ACTIVE_SET_PLAN_RECORD", "planner record is incomplete")
        out.append(record)
    return sorted(out, key=lambda row: row["raw_record_id"])


def from_approved(approved, candidate_source, archive_descriptor_sha256):
    """Convert a verified planner result into the only allowed sidecar shape."""
    _candidate(candidate_source); _hex(archive_descriptor_sha256)
    if not isinstance(approved, dict): _fail("ACTIVE_SET_PLAN_INPUT", "approved plan is invalid")
    capacity = approved.get("capacity")
    if not isinstance(capacity, dict): _fail("ACTIVE_SET_PLAN_CAPACITY", "planner capacity is missing")
    compact_capacity = {"target": capacity.get("target"), "headroom": capacity.get("headroom"),
                        "reserve": capacity.get("reserve"), "hard_max": capacity.get("hard_max"),
                        "mandatory_closure_count": capacity.get("mandatory_count")}
    mandatory = approved.get("mandatory_reasons", {})
    selected = _records(approved.get("selected", []), lambda row: mandatory.get(row["projection_row_id"], ["optional_selection"]))
    omitted = _records(approved.get("omitted", []), lambda _row: ["deterministic_optional_omission"])
    value = {"schema": SCHEMA, "selection_policy_version": approved.get("selection_policy_version"),
             "candidate_source": candidate_source, "archive_descriptor_sha256": archive_descriptor_sha256,
             "recovery_commitment_sha256": approved.get("recovery_commitment"),
             "retained_floor_commitment_sha256": approved.get("retained_floor_commitment_sha256"),
             "omission_commitment_sha256": approved.get("omission_commitment_sha256"),
             "capacity": compact_capacity, "selected": selected, "omitted": omitted,
             "counts": {"selected": len(selected), "omitted": len(omitted), "eligible": len(selected) + len(omitted)}}
    value["plan_commitment_sha256"] = active_set_plan_commitment(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(raw) > MAX_PLAN_BYTES or len(selected) != 43840 or len(omitted) != 5968:
        _fail("ACTIVE_SET_PLAN_BOUNDS", "approved plan does not meet the bounded V2 cardinalities")
    return value, raw


def descriptor(value, raw, locator):
    _locator(locator)
    try:
        parsed = parse_active_set_plan(raw)
        if parsed != value or value["plan_commitment_sha256"] != active_set_plan_commitment({k: v for k, v in value.items() if k != "plan_commitment_sha256"}):
            _fail("ACTIVE_SET_PLAN_VALIDATION", "canonical plan commitment differs")
    except V2ValidationError as exc:
        raise ActiveSetPlanError("ACTIVE_SET_PLAN_VALIDATION", "canonical plan failed validation") from exc
    return {"schema": SCHEMA, "locator": locator, "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw),
            "plan_commitment_sha256": value["plan_commitment_sha256"], "recovery_commitment_sha256": value["recovery_commitment_sha256"]}


def write(approved, candidate_source, archive_descriptor_sha256, locator, output_path):
    output = _path(output_path, True)
    value, raw = from_approved(approved, candidate_source, archive_descriptor_sha256)
    result = descriptor(value, raw, locator)
    stage = output.parent / ("." + output.name + ".staging-" + uuid.uuid4().hex)
    try:
        fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, raw); os.fsync(fd)
        finally: os.close(fd)
        os.link(stage, output); stage.unlink()
        directory = os.open(output.parent, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    except Exception:
        if stage.exists(): stage.unlink()
        raise
    return {"path": str(output), "descriptor": result, "plan": value}


def read(path, descriptor_value):
    path = _path(path)
    raw = path.read_bytes()
    if len(raw) != descriptor_value.get("size_bytes") or hashlib.sha256(raw).hexdigest() != descriptor_value.get("sha256"):
        _fail("ACTIVE_SET_PLAN_BYTES", "plan bytes differ from descriptor")
    try: value = parse_active_set_plan(raw)
    except V2ValidationError as exc: raise ActiveSetPlanError("ACTIVE_SET_PLAN_VALIDATION", "plan is malformed") from exc
    if value.get("plan_commitment_sha256") != descriptor_value.get("plan_commitment_sha256") or value.get("recovery_commitment_sha256") != descriptor_value.get("recovery_commitment_sha256"):
        _fail("ACTIVE_SET_PLAN_BINDING", "plan logical binding differs")
    return value
