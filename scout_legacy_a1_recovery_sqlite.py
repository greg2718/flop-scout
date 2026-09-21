"""Read-only SQLite adapter for legacy-A1 provenance recovery."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from scout_legacy_a1_recovery import (MAX_JSON_BYTES, MAX_RECORDS, MAX_SQLITE_BYTES,
                                      MAX_TEXT_BYTES, RecoveryError, parse_json,
                                      resolve, validate_descriptor)
from scout_projection_source import exact_cache
from scout_projection_contract import REVISION


_TABLES = ("messages", "evidence_records", "tclk_frames", "kibble_events")


def _fail(code, message):
    raise RecoveryError(code, message)


def _path(value, label):
    path = Path(value)
    if not path.is_absolute() or not path.is_file() or path.stat().st_size > MAX_SQLITE_BYTES:
        _fail("RECOVERY_PATH", label + " must be an explicit regular file")
    return path.resolve(strict=True)


def _read_only(path):
    conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def _file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _schema(conn, required, label):
    found = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not set(required) <= found:
        _fail("RECOVERY_SCHEMA", label + " schema is incomplete")


def _count(conn, query, args=()):
    value = conn.execute(query, args).fetchone()[0]
    if type(value) is not int or value > MAX_RECORDS:
        _fail("RECOVERY_BOUNDS", "SQLite row count exceeds the hard limit")
    return value


def _cache_rows(conn, raw):
    result = {}
    for table in _TABLES:
        count = conn.execute("SELECT count(*) FROM compatibility_evidence_links WHERE raw_record_id=? AND cache_table=?", (raw["raw_record_id"], table)).fetchone()[0]
        if count > 1:
            _fail("RECOVERY_CACHE", "compatibility cache witness is ambiguous")
        links = conn.execute("SELECT cache_rowid,raw_text_sha256 FROM compatibility_evidence_links WHERE raw_record_id=? AND cache_table=? LIMIT 2", (raw["raw_record_id"], table)).fetchall()
        for link in links:
            if conn.execute("SELECT 1 FROM " + table + " WHERE rowid=?", (link["cache_rowid"],)).fetchone() is None:
                _fail("RECOVERY_CACHE", "compatibility cache link is orphaned")
            text_column = {"messages": "text", "evidence_records": "text", "tclk_frames": "raw_text", "kibble_events": "exact_text"}[table]
            size = conn.execute("SELECT length(" + text_column + ") FROM " + table + " WHERE rowid=?", (link["cache_rowid"],)).fetchone()[0]
            if size is None or size > MAX_TEXT_BYTES:
                _fail("RECOVERY_BOUNDS", "compatibility cache text exceeds the recovery limit")
        try:
            exact_cache(conn, table, raw, REVISION)
        except Exception as exc:
            raise RecoveryError("RECOVERY_CACHE", "compatibility cache witness failed exact validation") from exc
        result[table] = [dict(raw_text_sha256=row["raw_text_sha256"]) for row in links]
    return result


def recover(projection_path, source_path, authorized_descriptor, observed_descriptor):
    """Resolve only caller-supplied artifacts; neither path has a default."""
    # Validate caller input before inspecting either supplied file.
    validate_descriptor(authorized_descriptor, observed_descriptor)
    projection_path = _path(projection_path, "projection path")
    source_path = _path(source_path, "source path")
    if projection_path == source_path:
        _fail("RECOVERY_PATH", "projection and source paths must differ")
    if observed_descriptor.get("artifact_size") != projection_path.stat().st_size or observed_descriptor.get("artifact_sha256") != _file_hash(projection_path):
        _fail("RECOVERY_DESCRIPTOR", "projection artifact differs from observed descriptor")
    projection = _read_only(projection_path)
    source = _read_only(source_path)
    try:
        _schema(projection, ("source_provenance", "selection_membership", "durable_qualifications", "coverage_history", "messages"), "projection")
        _schema(source, ("raw_network_records", "observed_events", "compatibility_evidence_links", *_TABLES), "source")
        provenance_count = _count(projection, "SELECT count(*) FROM source_provenance WHERE entity_type='message'")
        membership_count = _count(projection, "SELECT count(*) FROM selection_membership WHERE entity_type='message'")
        qualification_count = _count(projection, "SELECT count(*) FROM durable_qualifications")
        _count(source, "SELECT count(*) FROM raw_network_records")
        _count(source, "SELECT count(*) FROM observed_events")
        if projection.execute("SELECT 1 FROM source_provenance WHERE entity_type='message' AND length(annotations_json)>? LIMIT 1", (MAX_JSON_BYTES,)).fetchone() is not None:
            _fail("RECOVERY_BOUNDS", "provenance JSON exceeds the recovery limit")
        if projection.execute("SELECT 1 FROM selection_membership WHERE entity_type='message' AND length(pin_roots_json)>? LIMIT 1", (MAX_JSON_BYTES,)).fetchone() is not None:
            _fail("RECOVERY_BOUNDS", "pin-root JSON exceeds the recovery limit")
        if projection.execute("SELECT 1 FROM durable_qualifications WHERE length(record_json)>? LIMIT 1", (MAX_JSON_BYTES,)).fetchone() is not None:
            _fail("RECOVERY_BOUNDS", "qualification JSON exceeds the recovery limit")
        if projection.execute("SELECT count(*) FROM coverage_history").fetchone()[0] > 64:
            _fail("RECOVERY_BOUNDS", "coverage row count exceeds the recovery limit")
        rows = []
        for provenance_row in projection.execute("SELECT * FROM source_provenance WHERE entity_type='message' AND length(annotations_json)<=? ORDER BY projection_row_id", (MAX_JSON_BYTES,)):
            provenance = dict(provenance_row)
            raw_row = source.execute("SELECT * FROM raw_network_records WHERE raw_record_id=? AND length(raw_record_json)<=? AND length(raw_text)<=?", (provenance["raw_record_id"], MAX_JSON_BYTES, MAX_TEXT_BYTES)).fetchone()
            if raw_row is None:
                _fail("RECOVERY_RAW", "exact raw source row is missing")
            raw = dict(raw_row)
            try:
                raw["envelope"] = parse_json(raw.pop("raw_record_json"), "RECOVERY_RAW_ID")
            except (KeyError, RecoveryError) as exc:
                raise RecoveryError("RECOVERY_RAW_ID", "raw envelope is invalid") from exc
            events = [dict(row) for row in source.execute("SELECT event_id,raw_text_sha256 FROM observed_events WHERE raw_record_id=? LIMIT 2", (raw["raw_record_id"],))]
            rows.append(dict(provenance=provenance, raw=raw, event=events, cache_rows=_cache_rows(source, raw)))
        if len(rows) != provenance_count:
            _fail("RECOVERY_BOUNDS", "provenance rows changed during recovery")
        membership = [dict(row) for row in projection.execute("SELECT * FROM selection_membership WHERE entity_type='message' AND length(pin_roots_json)<=?", (MAX_JSON_BYTES,))]
        qualifications = [row[0] for row in projection.execute("SELECT record_json FROM durable_qualifications WHERE length(record_json)<=? ORDER BY qualification_id", (MAX_JSON_BYTES,))]
        if len(membership) != membership_count or len(qualifications) != qualification_count:
            _fail("RECOVERY_BOUNDS", "projection rows changed during recovery")
        coverage = []
        for row in projection.execute("SELECT * FROM coverage_history ORDER BY room,generation"):
            item = dict(row)
            message = projection.execute("SELECT * FROM messages WHERE projection_row_id=? AND length(text)<=?", ("sm1:" + item["witness_source_locator"], MAX_TEXT_BYTES)).fetchone()
            if message is None:
                _fail("RECOVERY_CLOSURE", "coverage witness message is missing")
            item["message"] = dict(message)
            coverage.append(item)
        return resolve(authorized_descriptor, observed_descriptor, rows, membership, qualifications, coverage)
    finally:
        projection.close()
        source.close()
