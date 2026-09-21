"""Pure fail-closed recovery of omitted legacy-A1 raw provenance hashes.

This module has no filesystem or SQLite access.  The SQLite adapter supplies
normalized rows after opening caller-provided paths read-only.
"""
from __future__ import annotations

import hashlib
import json
import re


DOMAIN = "scout/legacy-a1-provenance-recovery-closure/v1"
MAX_RECORDS = 50000
MAX_SQLITE_BYTES = 1024 * 1024 * 1024
MAX_JSON_BYTES = 64 * 1024
MAX_TEXT_BYTES = 64 * 1024
MAX_COMMITMENT_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 16
MAX_LIST_ITEMS = 256
MAX_MAP_ITEMS = 64
_HEX = re.compile(r"^[0-9a-f]{64}$")
_DESCRIPTOR = (
    "content_id", "manifest_sha256", "artifact_sha256", "artifact_size",
    "source_kind", "source_id", "source_epoch", "source_cut",
)
_CACHE_TABLES = ("messages", "evidence_records", "tclk_frames", "kibble_events")


class RecoveryError(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def _fail(code, message):
    raise RecoveryError(code, message)


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise RecoveryError("RECOVERY_CANONICAL", "value is not canonical JSON") from exc


def _bounded(value, depth=0):
    if depth > MAX_DEPTH:
        _fail("RECOVERY_BOUNDS", "JSON nesting exceeds the recovery limit")
    if value is None or type(value) in (bool, int):
        return
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_TEXT_BYTES:
            _fail("RECOVERY_BOUNDS", "string exceeds the recovery limit")
        return
    if isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS:
            _fail("RECOVERY_BOUNDS", "list exceeds the recovery limit")
        for item in value:
            _bounded(item, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > MAX_MAP_ITEMS or any(not isinstance(key, str) for key in value):
            _fail("RECOVERY_BOUNDS", "object exceeds the recovery limit")
        for key, item in value.items():
            _bounded(key, depth + 1); _bounded(item, depth + 1)
        return
    _fail("RECOVERY_BOUNDS", "unsupported JSON value")


def parse_json(value, code):
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_JSON_BYTES:
        _fail(code, "JSON input exceeds the recovery limit")
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                _fail(code, "duplicate JSON key")
            result[key] = item
        return result
    try:
        parsed = json.loads(value, object_pairs_hook=pairs,
                            parse_constant=lambda _value: _fail(code, "non-finite JSON"))
    except RecoveryError:
        raise
    except (TypeError, ValueError, UnicodeError) as exc:
        raise RecoveryError(code, "JSON input is invalid") from exc
    _bounded(parsed)
    return parsed


def _hash(value):
    return hashlib.sha256(value).hexdigest()


def raw_record_id(source, room, generation, reported_generation, envelope):
    """The immutable legacy source identity, matching scout_evidence.raw_identity."""
    if not isinstance(source, str) or not isinstance(room, str):
        _fail("RECOVERY_RAW_ID", "raw identity source or room is invalid")
    _bounded(envelope)
    try:
        body = json.dumps([source, room, generation, reported_generation, envelope],
                          sort_keys=True, ensure_ascii=True, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise RecoveryError("RECOVERY_RAW_ID", "raw identity envelope is invalid") from exc
    return _hash(body)


def _hex(value, code):
    if not isinstance(value, str) or not _HEX.fullmatch(value):
        _fail(code, "expected lower-case SHA-256")
    return value


def _identifier(value, code):
    if not isinstance(value, str) or not value or len(value) > 256:
        _fail(code, "expected bounded non-empty identifier")
    return value


def validate_descriptor(authorized, observed):
    """Require the caller-authorized descriptor to exactly equal acquisition data."""
    for value in (authorized, observed):
        if not isinstance(value, dict) or tuple(sorted(value)) != tuple(sorted(_DESCRIPTOR)):
            _fail("RECOVERY_DESCRIPTOR", "descriptor fields are not exact")
        _identifier(str(value["content_id"]), "RECOVERY_DESCRIPTOR")
        _hex(value["manifest_sha256"], "RECOVERY_DESCRIPTOR")
        _hex(value["artifact_sha256"], "RECOVERY_DESCRIPTOR")
        if type(value["artifact_size"]) is not int or value["artifact_size"] < 1:
            _fail("RECOVERY_DESCRIPTOR", "artifact size is invalid")
        for key in ("source_kind", "source_id", "source_epoch"):
            _identifier(value[key], "RECOVERY_DESCRIPTOR")
        if type(value["source_cut"]) is not int or value["source_cut"] < 0:
            _fail("RECOVERY_DESCRIPTOR", "source cut is invalid")
    if authorized != observed:
        _fail("RECOVERY_DESCRIPTOR", "observed descriptor is not authorized")
    return dict(authorized)


def _record(provenance, raw, event, cache_rows, descriptor):
    if not isinstance(provenance, dict) or provenance.get("entity_type") != "message":
        _fail("RECOVERY_PROVENANCE", "message provenance is missing")
    rid = _hex(provenance.get("raw_record_id"), "RECOVERY_PROVENANCE")
    if provenance.get("source_record_locator") != rid or provenance.get("projection_row_id") != "sm1:" + rid:
        _fail("RECOVERY_PROVENANCE", "legacy provenance identity is inconsistent")
    if provenance.get("raw_record_sha256") is not None:
        _fail("RECOVERY_PROVENANCE", "recovery only accepts omitted legacy hashes")
    if not isinstance(raw, dict) or raw.get("raw_record_id") != rid:
        _fail("RECOVERY_RAW", "exact raw source row is missing")
    if raw.get("source") != provenance.get("source_namespace"):
        _fail("RECOVERY_PROVENANCE", "raw source namespace differs from provenance")
    expected = raw_record_id(raw.get("source"), raw.get("room"), raw.get("generation"),
                             raw.get("reported_generation"), raw.get("envelope"))
    if expected != rid:
        _fail("RECOVERY_RAW_ID", "canonical raw identity differs")
    text = raw.get("raw_text")
    if not isinstance(text, str) or not isinstance(raw.get("envelope"), dict) or raw["envelope"].get("text") != text:
        _fail("RECOVERY_RAW_TEXT", "envelope text differs from stored raw text")
    text_sha = _hash(text.encode("utf-8"))
    if text_sha != raw.get("raw_text_sha256"):
        _fail("RECOVERY_RAW_HASH", "stored raw text hash differs")
    if not isinstance(event, list) or len(event) != 1:
        _fail("RECOVERY_EVENT", "observed-event witness is missing or ambiguous")
    witness = event[0]
    if not isinstance(witness, dict) or witness.get("raw_text_sha256") != text_sha:
        _fail("RECOVERY_EVENT", "observed-event hash differs")
    if str(witness.get("event_id")) != str(provenance.get("scout_event_id")):
        _fail("RECOVERY_EVENT", "observed-event ID differs from provenance")
    if type(witness.get("event_id")) is not int or not 0 <= witness["event_id"] <= descriptor["source_cut"]:
        _fail("RECOVERY_SOURCE_CUT", "observed event exceeds the authorized source cut")
    if not isinstance(cache_rows, dict) or set(cache_rows) != set(_CACHE_TABLES):
        _fail("RECOVERY_CACHE", "cache witnesses are incomplete")
    for table in _CACHE_TABLES:
        rows = cache_rows[table]
        if not isinstance(rows, list) or len(rows) > 1:
            _fail("RECOVERY_CACHE", "compatibility cache witness is ambiguous")
        if rows:
            item = rows[0]
            if not isinstance(item, dict) or item.get("raw_text_sha256") != text_sha:
                _fail("RECOVERY_CACHE", "compatibility cache hash differs")
    return {
        "projection_row_id": provenance["projection_row_id"],
        "raw_record_id": rid,
        "raw_text_sha256": text_sha,
        "scout_event_id": str(witness["event_id"]),
    }


def _strict_json(value, code):
    return parse_json(value, code)


def _closure(records, membership, qualifications, coverage):
    by_projection = {row["projection_row_id"]: row for row in records}
    by_raw = {row["raw_record_id"]: row for row in records}
    reasons = {key: set() for key in by_projection}
    for row in membership:
        pid = row.get("projection_row_id")
        if pid not in by_projection:
            _fail("RECOVERY_CLOSURE", "membership has no recovered provenance")
        pins = _strict_json(row.get("pin_roots_json"), "RECOVERY_CLOSURE")
        if not isinstance(pins, list):
            _fail("RECOVERY_CLOSURE", "pin roots are invalid")
        if row.get("retain_until") is None or pins:
            reasons[pid].add("permanent_or_pinned")
        if row.get("retention_class") in ("TCLK_LIFECYCLE", "WORK_LIFECYCLE"):
            reasons[pid].add("tclk_or_work_lifecycle")
    for value in qualifications:
        item = _strict_json(value, "RECOVERY_QUALIFICATION")
        ref = item.get("source_ref") if isinstance(item, dict) else None
        if not isinstance(ref, dict) or ref.get("kind") != "PROJECTED_MESSAGE" or not isinstance(ref.get("id"), str):
            _fail("RECOVERY_QUALIFICATION", "durable qualification source reference is invalid")
        if ref["id"] not in by_projection:
            _fail("RECOVERY_CLOSURE", "qualification has no recovered provenance")
        reasons[ref["id"]].add("durable_qualification")
    for row in coverage:
        raw_id = row.get("witness_source_locator")
        evidence = by_raw.get(raw_id)
        if evidence is None:
            _fail("RECOVERY_CLOSURE", "coverage witness has no recovered provenance")
        message = row.get("message")
        if not isinstance(message, dict) or message.get("projection_row_id") != evidence["projection_row_id"]:
            _fail("RECOVERY_CLOSURE", "coverage witness message is missing")
        if (message.get("room"), message.get("generation"), message.get("seq")) != (row.get("room"), row.get("generation"), row.get("max_ever_projected_seq")):
            _fail("RECOVERY_COVERAGE", "coverage witness does not match its watermark")
        if row.get("witness_record_sha256") != _hash(canonical(message)):
            _fail("RECOVERY_COVERAGE", "coverage witness hash differs")
        reasons[evidence["projection_row_id"]].add("coverage_witness")
    closure = []
    for record in records:
        item_reasons = sorted(reasons[record["projection_row_id"]])
        if item_reasons:
            closure.append({**record, "reasons": item_reasons})
    return closure


def resolve(authorized_descriptor, observed_descriptor, rows, membership, qualifications, coverage):
    """Validate normalized SQLite data and return only recovery-safe fields."""
    descriptor = validate_descriptor(authorized_descriptor, observed_descriptor)
    if not all(isinstance(value, list) for value in (rows, membership, qualifications, coverage)):
        _fail("RECOVERY_BOUNDS", "recovery inputs must be bounded lists")
    if len(rows) > MAX_RECORDS or len(membership) > MAX_RECORDS or len(qualifications) > MAX_RECORDS or len(coverage) > MAX_MAP_ITEMS:
        _fail("RECOVERY_BOUNDS", "recovery input count exceeds the hard limit")
    records = [_record(row["provenance"], row["raw"], row["event"], row["cache_rows"], descriptor)
               for row in rows]
    if len({item["projection_row_id"] for item in records}) != len(records) or len({item["raw_record_id"] for item in records}) != len(records):
        _fail("RECOVERY_PROVENANCE", "duplicate projection provenance")
    closure = _closure(records, membership, qualifications, coverage)
    proof = [{key: item[key] for key in ("raw_record_id", "raw_text_sha256", "scout_event_id")}
             for item in sorted(closure, key=lambda item: item["raw_record_id"])]
    content = {
        "content_id": str(descriptor["content_id"]),
        "manifest_sha256": descriptor["manifest_sha256"],
        "artifact_sha256": descriptor["artifact_sha256"],
        "source_id": descriptor["source_id"],
        "source_epoch": descriptor["source_epoch"],
        "committed_event_id": str(descriptor["source_cut"]),
    }
    payload = canonical({"domain": DOMAIN, "content": content, "records": proof})
    if len(payload) > MAX_COMMITMENT_BYTES:
        _fail("RECOVERY_BOUNDS", "recovery commitment exceeds the hard limit")
    commitment = _hash(payload)
    reason_counts = {}
    for record in closure:
        for reason in record["reasons"]:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
    return {
        "descriptor": content,
        "validated_records": len(records),
        "closure_count": len(closure),
        "closure": sorted(closure, key=lambda item: item["raw_record_id"]),
        "reason_counts": dict(sorted(reason_counts.items())),
        "commitment": commitment,
    }
