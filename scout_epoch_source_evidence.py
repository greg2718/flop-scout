"""Bounded, read-only source-evidence member for legacy-A1 recovery.

This is deliberately an offline builder/validator.  It has no production
paths, no implicit descriptor, and never mutates either input database.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from pathlib import Path

from scout_legacy_a1_recovery import (MAX_JSON_BYTES, MAX_RECORDS,
    MAX_SQLITE_BYTES, MAX_TEXT_BYTES, RecoveryError, canonical, parse_json,
    raw_record_id, resolve, validate_descriptor)


SCHEMA = "flop-scout-epoch-source-evidence/v1"
REVISION = "legacy-a1-recovery/1"
DDL_DOMAIN = b"flop-scout/epoch-source-evidence-ddl/v1\0"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_CACHE = ("messages", "evidence_records", "tclk_frames", "kibble_events")
MAX_CACHE_LINKS = MAX_RECORDS * len(_CACHE)
_TEXT = {"messages": "text", "evidence_records": "text",
         "tclk_frames": "raw_text", "kibble_events": "exact_text"}


class SourceEvidenceError(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def _fail(code, message):
    raise SourceEvidenceError(code, message)


# The order and SQL below are the normative closed object set.  Do not accept
# application-defined additions merely because SQLite can parse them.
_DDL = {
"source_evidence_metadata": """CREATE TABLE source_evidence_metadata(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 schema TEXT NOT NULL CHECK(schema='flop-scout-epoch-source-evidence/v1'),
 revision TEXT NOT NULL CHECK(revision='legacy-a1-recovery/1'),
 canonical_ddl_sha256 TEXT NOT NULL CHECK(length(canonical_ddl_sha256)=64),
 accepted_anchor_json TEXT NOT NULL, bridge_predecessor_json TEXT NOT NULL,
 source_checkpoint_json TEXT NOT NULL,
 previous_bridge_binding_sha256 TEXT NOT NULL CHECK(length(previous_bridge_binding_sha256)=64),
 recovery_commitment_sha256 TEXT NOT NULL CHECK(length(recovery_commitment_sha256)=64),
 raw_record_count INTEGER NOT NULL CHECK(raw_record_count>=0 AND raw_record_count<=50000),
 observed_event_count INTEGER NOT NULL CHECK(observed_event_count>=0 AND observed_event_count<=50000),
 cache_link_count INTEGER NOT NULL CHECK(cache_link_count>=0 AND cache_link_count<=200000))""",
"raw_records": """CREATE TABLE raw_records(
 raw_record_id TEXT PRIMARY KEY CHECK(length(raw_record_id)=64), source TEXT NOT NULL,
 room TEXT NOT NULL, generation TEXT, reported_generation TEXT, seq INTEGER NOT NULL CHECK(seq>=0),
 sender_did TEXT, signature TEXT, nonce TEXT, raw_text TEXT NOT NULL CHECK(length(raw_text)<=65536),
 raw_text_sha256 TEXT NOT NULL CHECK(length(raw_text_sha256)=64),
 raw_record_json TEXT NOT NULL CHECK(length(raw_record_json)<=65536),
 UNIQUE(raw_record_id,raw_text_sha256))""",
"observed_event_witnesses": """CREATE TABLE observed_event_witnesses(
 event_id INTEGER PRIMARY KEY, raw_record_id TEXT NOT NULL UNIQUE, raw_text_sha256 TEXT NOT NULL,
 FOREIGN KEY(raw_record_id,raw_text_sha256) REFERENCES raw_records(raw_record_id,raw_text_sha256))""",
"compatibility_links": """CREATE TABLE compatibility_links(
 cache_table TEXT NOT NULL CHECK(cache_table IN ('messages','evidence_records','tclk_frames','kibble_events')),
 cache_rowid INTEGER NOT NULL, raw_record_id TEXT NOT NULL, raw_text_sha256 TEXT NOT NULL,
 PRIMARY KEY(cache_table,cache_rowid),
 FOREIGN KEY(raw_record_id,raw_text_sha256) REFERENCES raw_records(raw_record_id,raw_text_sha256))""",
"messages": """CREATE TABLE messages(cache_rowid INTEGER PRIMARY KEY, room TEXT NOT NULL,
 seq INTEGER NOT NULL, text TEXT NOT NULL CHECK(length(text)<=65536), sender TEXT)""",
"evidence_records": """CREATE TABLE evidence_records(cache_rowid INTEGER PRIMARY KEY, room TEXT NOT NULL,
 generation TEXT, seq INTEGER NOT NULL, text TEXT NOT NULL CHECK(length(text)<=65536), did TEXT,
 sig TEXT, nonce INTEGER)""",
"tclk_frames": """CREATE TABLE tclk_frames(cache_rowid INTEGER PRIMARY KEY, room TEXT NOT NULL,
 generation TEXT, seq INTEGER NOT NULL, raw_text TEXT NOT NULL CHECK(length(raw_text)<=65536), transport_did TEXT)""",
"kibble_events": """CREATE TABLE kibble_events(cache_rowid INTEGER PRIMARY KEY, room TEXT NOT NULL,
 generation TEXT, seq INTEGER NOT NULL, exact_text TEXT NOT NULL CHECK(length(exact_text)<=65536), sender_did TEXT)""",
"compatibility_links_by_raw": "CREATE INDEX compatibility_links_by_raw ON compatibility_links(raw_record_id,cache_table)",
}
_TABLES = tuple(k for k in _DDL if k != "compatibility_links_by_raw")


def _tokens(sql):
    """Strict SQLite DDL lexer; comments and quoted identifiers are forbidden."""
    out, pos = [], 0
    while pos < len(sql):
        ch = sql[pos]
        if ch.isspace(): pos += 1; continue
        if sql.startswith("--", pos) or sql.startswith("/*", pos) or ch in '"[`':
            _fail("SOURCE_EVIDENCE_DDL", "DDL contains a forbidden token")
        if ch == "'":
            end, value = pos + 1, ""
            while end < len(sql):
                if sql[end] == "'":
                    if end + 1 < len(sql) and sql[end + 1] == "'": value += "'"; end += 2; continue
                    break
                value += sql[end]; end += 1
            if end >= len(sql): _fail("SOURCE_EVIDENCE_DDL", "DDL string is unterminated")
            out.append(("string", value)); pos = end + 1; continue
        match = re.match(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+|>=|<=|<>|!=|[(),=*<>;]", sql[pos:])
        if not match: _fail("SOURCE_EVIDENCE_DDL", "DDL contains an unsupported token")
        token = match.group(0)
        out.append(("word", token.upper() if token.upper() in {
            "CREATE","TABLE","INDEX","ON","PRIMARY","KEY","CHECK","NOT","NULL","UNIQUE","FOREIGN","REFERENCES","INTEGER","TEXT","AND","IN"} else token.lower()))
        pos += len(token)
    while out and out[-1] == ("word", ";"): out.pop()
    return out


def normalized_ddl_hash(conn):
    objects = {}
    for name in _DDL:
        row = conn.execute("SELECT type,sql FROM sqlite_master WHERE name=?", (name,)).fetchone()
        if row is None or not row[1]: _fail("SOURCE_EVIDENCE_DDL", "required schema object is missing")
        objects[name] = {"type": row[0], "tokens": _tokens(row[1])}
    return hashlib.sha256(DDL_DOMAIN + canonical(objects)).hexdigest()


def validate_schema(conn):
    found = {r[0]: (r[1], r[2]) for r in conn.execute(
        "SELECT name,type,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
    if set(found) != set(_DDL): _fail("SOURCE_EVIDENCE_SCHEMA", "SQLite object set is not canonical")
    for name, expected in _DDL.items():
        kind = "index" if name == "compatibility_links_by_raw" else "table"
        if found[name][0] != kind or _tokens(found[name][1]) != _tokens(expected):
            _fail("SOURCE_EVIDENCE_DDL", "SQLite DDL does not match the approved schema")
    return normalized_ddl_hash(conn)


def _path(value, label, output=False):
    path = Path(value)
    if not path.is_absolute(): _fail("SOURCE_EVIDENCE_PATH", label + " must be absolute")
    if output:
        if path.exists() or path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
            _fail("SOURCE_EVIDENCE_PATH", label + " must be a new file beneath a regular directory")
        return path
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_SQLITE_BYTES:
        _fail("SOURCE_EVIDENCE_PATH", label + " must be a bounded regular file")
    return path.resolve(strict=True)


def _ro(path):
    conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row; conn.execute("PRAGMA query_only=ON")
    return conn


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""): h.update(block)
    return h.hexdigest()


def _json(value, code="SOURCE_EVIDENCE_METADATA"):
    if not isinstance(value, dict): _fail(code, "metadata descriptor is invalid")
    return canonical(value).decode("utf-8")


def _context(context, descriptor, recovery):
    required = {"accepted_anchor", "bridge_predecessor", "source_checkpoint", "previous_bridge_binding_sha256"}
    if not isinstance(context, dict) or set(context) != required: _fail("SOURCE_EVIDENCE_METADATA", "archive context is incomplete")
    for key in ("accepted_anchor", "bridge_predecessor", "source_checkpoint"):
        _json(context[key])
    if not isinstance(context["previous_bridge_binding_sha256"], str) or not _HEX.fullmatch(context["previous_bridge_binding_sha256"]):
        _fail("SOURCE_EVIDENCE_METADATA", "previous bridge binding is invalid")
    checkpoint = context["source_checkpoint"]
    for key, value in (("source_id", descriptor["source_id"]), ("source_epoch", descriptor["source_epoch"]), ("source_cut", descriptor["source_cut"])):
        if checkpoint.get(key) != value: _fail("SOURCE_EVIDENCE_METADATA", "source checkpoint does not bind recovery descriptor")
    recovery_descriptor = {"content_id": str(descriptor["content_id"]),
                           "manifest_sha256": descriptor["manifest_sha256"],
                           "artifact_sha256": descriptor["artifact_sha256"],
                           "source_id": descriptor["source_id"],
                           "source_epoch": descriptor["source_epoch"],
                           "committed_event_id": str(descriptor["source_cut"])}
    if recovery.get("descriptor") != recovery_descriptor:
        _fail("SOURCE_EVIDENCE_METADATA", "recovery descriptor is not exact")


def _required(conn, tables, code="SOURCE_EVIDENCE_SCHEMA"):
    got = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not set(tables) <= got: _fail(code, "required input table is missing")


def _read_projection(projection):
    _required(projection, ("source_provenance", "selection_membership", "durable_qualifications", "coverage_history", "messages"))
    p = [dict(r) for r in projection.execute("SELECT * FROM source_provenance WHERE entity_type='message' ORDER BY projection_row_id")]
    if not p or len(p) > MAX_RECORDS or len({r.get("raw_record_id") for r in p}) != len(p): _fail("SOURCE_EVIDENCE_RAW_SET", "projection provenance is invalid")
    return p


def _source_rows(source, provenance):
    _required(source, ("raw_network_records", "observed_events", "compatibility_evidence_links", *_CACHE))
    result, links, caches = [], [], {name: [] for name in _CACHE}
    for p in provenance:
        raw = source.execute("SELECT * FROM raw_network_records WHERE raw_record_id=?", (p["raw_record_id"],)).fetchone()
        if raw is None: _fail("SOURCE_EVIDENCE_RAW_SET", "projected raw evidence is absent")
        raw = dict(raw)
        if len(raw.get("raw_text", "").encode()) > MAX_TEXT_BYTES or len(raw.get("raw_record_json", "").encode()) > MAX_JSON_BYTES:
            _fail("SOURCE_EVIDENCE_BOUNDS", "source record exceeds limit")
        event = source.execute("SELECT event_id,raw_record_id,raw_text_sha256 FROM observed_events WHERE raw_record_id=?", (raw["raw_record_id"],)).fetchall()
        if len(event) != 1: _fail("SOURCE_EVIDENCE_REFERENCES", "observed event is missing or ambiguous")
        result.append(raw)
        for link in source.execute("SELECT cache_table,cache_rowid,raw_record_id,raw_text_sha256 FROM compatibility_evidence_links WHERE raw_record_id=?", (raw["raw_record_id"],)):
            link = dict(link)
            if link["cache_table"] not in _CACHE: _fail("SOURCE_EVIDENCE_CACHE_TABLE", "unsupported cache table")
            row = source.execute("SELECT rowid AS cache_rowid,* FROM " + link["cache_table"] + " WHERE rowid=?", (link["cache_rowid"],)).fetchone()
            if row is None: _fail("SOURCE_EVIDENCE_REFERENCES", "source cache link is orphaned")
            links.append(link); caches[link["cache_table"]].append(dict(row))
    if len(links) > MAX_CACHE_LINKS: _fail("SOURCE_EVIDENCE_BOUNDS", "cache links exceed derived hard limit")
    return result, [dict(source.execute("SELECT event_id,raw_record_id,raw_text_sha256 FROM observed_events WHERE raw_record_id=?", (r["raw_record_id"],)).fetchone()) for r in result], links, caches


def _copy_rows(source, out, provenance):
    """Copy bounded evidence incrementally, retaining original cache row IDs."""
    _required(source, ("raw_network_records", "observed_events", "compatibility_evidence_links", *_CACHE))
    raw_count = event_count = link_count = 0
    for provenance_row in provenance:
        raw = source.execute("SELECT * FROM raw_network_records WHERE raw_record_id=?", (provenance_row["raw_record_id"],)).fetchone()
        if raw is None: _fail("SOURCE_EVIDENCE_RAW_SET", "projected raw evidence is absent")
        raw = dict(raw)
        if len(raw.get("raw_text", "").encode()) > MAX_TEXT_BYTES or len(raw.get("raw_record_json", "").encode()) > MAX_JSON_BYTES:
            _fail("SOURCE_EVIDENCE_BOUNDS", "source record exceeds limit")
        out.execute("INSERT INTO raw_records VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", tuple(raw.get(k) for k in ("raw_record_id","source","room","generation","reported_generation","seq","sender_did","signature","nonce","raw_text","raw_text_sha256","raw_record_json")))
        raw_count += 1
        events = source.execute("SELECT event_id,raw_record_id,raw_text_sha256 FROM observed_events WHERE raw_record_id=?", (raw["raw_record_id"],)).fetchall()
        if len(events) != 1: _fail("SOURCE_EVIDENCE_REFERENCES", "observed event is missing or ambiguous")
        out.execute("INSERT INTO observed_event_witnesses VALUES(?,?,?)", tuple(events[0])); event_count += 1
        for link in source.execute("SELECT cache_table,cache_rowid,raw_record_id,raw_text_sha256 FROM compatibility_evidence_links WHERE raw_record_id=?", (raw["raw_record_id"],)):
            link = dict(link)
            table = link["cache_table"]
            if table not in _CACHE: _fail("SOURCE_EVIDENCE_CACHE_TABLE", "unsupported cache table")
            row = source.execute("SELECT rowid AS cache_rowid,* FROM " + table + " WHERE rowid=?", (link["cache_rowid"],)).fetchone()
            if row is None: _fail("SOURCE_EVIDENCE_REFERENCES", "source cache link is orphaned")
            row = dict(row)
            if row["cache_rowid"] != link["cache_rowid"]: _fail("SOURCE_EVIDENCE_REFERENCES", "source cache rowid changed")
            cols = {"messages": ("cache_rowid","room","seq","text","sender"),
                    "evidence_records": ("cache_rowid","room","generation","seq","text","did","sig","nonce"),
                    "tclk_frames": ("cache_rowid","room","generation","seq","raw_text","transport_did"),
                    "kibble_events": ("cache_rowid","room","generation","seq","exact_text","sender_did")}[table]
            out.execute("INSERT INTO compatibility_links VALUES(?,?,?,?)", tuple(link.values()))
            out.execute("INSERT INTO " + table + "(" + ",".join(cols) + ") VALUES(" + ",".join("?" for _ in cols) + ")", [row.get(c) for c in cols])
            link_count += 1
            if link_count > MAX_CACHE_LINKS: _fail("SOURCE_EVIDENCE_BOUNDS", "cache links exceed derived hard limit")
    return raw_count, event_count, link_count


def _create(path):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600); os.close(fd)
    conn = sqlite3.connect(str(path)); conn.execute("PRAGMA journal_mode=DELETE")
    for name in _DDL: conn.execute(_DDL[name])
    return conn


def build(projection_path, source_path, staging_path, output_path, authorized_descriptor, observed_descriptor, archive_context):
    """Build one member atomically; all inputs and destinations are explicit."""
    validate_descriptor(authorized_descriptor, observed_descriptor)
    projection_path, source_path = _path(projection_path, "projection"), _path(source_path, "source")
    staging_path, output_path = _path(staging_path, "staging", True), _path(output_path, "output", True)
    if projection_path == source_path or staging_path.parent.stat().st_dev != output_path.parent.stat().st_dev: _fail("SOURCE_EVIDENCE_PATH", "paths are unsafe for atomic production")
    projection, source = _ro(projection_path), _ro(source_path)
    try:
        provenance = _read_projection(projection)
        # The established recovery independently verifies descriptor, source cut,
        # byte hashes, event witnesses, exact cache semantics, and closure.
        from scout_legacy_a1_recovery_sqlite import recover
        recovery = recover(projection_path, source_path, authorized_descriptor, observed_descriptor)
        _context(archive_context, authorized_descriptor, recovery)
        out = _create(staging_path)
        try:
            raw_count, event_count, link_count = _copy_rows(source, out, provenance)
            ddl = normalized_ddl_hash(out)
            out.execute("INSERT INTO source_evidence_metadata VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (1,SCHEMA,REVISION,ddl,_json(archive_context["accepted_anchor"]),_json(archive_context["bridge_predecessor"]),_json(archive_context["source_checkpoint"]),archive_context["previous_bridge_binding_sha256"],recovery["commitment"],raw_count,event_count,link_count))
            out.commit(); out.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally: out.close()
        os.chmod(staging_path, 0o600)
        result = validate(staging_path, projection_path, authorized_descriptor, observed_descriptor, archive_context)
        os.replace(staging_path, output_path); os.chmod(output_path, 0o600)
        result.update(path=str(output_path), size_bytes=output_path.stat().st_size, sha256=_sha(output_path))
        return result
    except Exception:
        if staging_path.exists(): staging_path.unlink()
        raise
    finally: projection.close(); source.close()


def _cache_validate(conn, raw):
    result = {}
    for table in _CACHE:
        rows = conn.execute("SELECT l.cache_rowid,l.raw_text_sha256,c.* FROM compatibility_links l LEFT JOIN " + table + " c ON c.cache_rowid=l.cache_rowid WHERE l.raw_record_id=? AND l.cache_table=?", (raw["raw_record_id"], table)).fetchall()
        if len(rows) > 1: _fail("SOURCE_EVIDENCE_REFERENCES", "cache witness is ambiguous")
        hashes = []
        for row in rows:
            row = dict(row)
            if row.get("cache_rowid") is None or row["raw_text_sha256"] != raw["raw_text_sha256"]: _fail("SOURCE_EVIDENCE_REFERENCES", "cache link is invalid")
            if row["room"] != raw["room"] or row["seq"] != raw["seq"] or row[_TEXT[table]] != raw["raw_text"]: _fail("SOURCE_EVIDENCE_REFERENCES", "cache evidence does not match raw record")
            if "generation" in row and _generation(row["generation"]) != _generation(raw.get("generation")):
                _fail("SOURCE_EVIDENCE_REFERENCES", "cache metadata does not match raw record")
            sender = row.get({"messages":"sender", "evidence_records":"did", "tclk_frames":"transport_did", "kibble_events":"sender_did"}[table])
            if sender is not None and sender != raw.get("sender_did"):
                _fail("SOURCE_EVIDENCE_REFERENCES", "cache sender does not match raw record")
            if table == "evidence_records" and row.get("sig") != raw.get("signature"):
                _fail("SOURCE_EVIDENCE_REFERENCES", "evidence signature witness does not match")
            if table == "evidence_records" and row.get("nonce") is not None and raw.get("nonce") is not None:
                if type(row["nonce"]) is not int or not isinstance(raw["nonce"], str) or not re.fullmatch(r"[0-9]+", raw["nonce"]) or row["nonce"] != int(raw["nonce"]):
                    _fail("SOURCE_EVIDENCE_REFERENCES", "evidence nonce witness does not match")
            hashes.append({"raw_text_sha256": row["raw_text_sha256"]})
        result[table] = hashes
    return result


def _generation(value):
    if value is None:
        return "UNKNOWN_LEGACY"
    if type(value) is int and value >= 0:
        return str(value)
    if not isinstance(value, str) or not value:
        _fail("SOURCE_EVIDENCE_REFERENCES", "cache generation is invalid")
    return value


def validate(member_path, projection_path, authorized_descriptor, observed_descriptor, archive_context, expected_member=None):
    """Independently validate an existing member; producer metadata is not trusted."""
    validate_descriptor(authorized_descriptor, observed_descriptor)
    member_path, projection_path = _path(member_path, "member"), _path(projection_path, "projection")
    if expected_member is not None:
        if expected_member.get("schema") != SCHEMA or expected_member.get("size_bytes") != member_path.stat().st_size or expected_member.get("sha256") != _sha(member_path): _fail("SOURCE_EVIDENCE_DESCRIPTOR", "member descriptor does not match bytes")
    member, projection = _ro(member_path), _ro(projection_path)
    try:
        if member.execute("PRAGMA integrity_check").fetchone()[0] != "ok": _fail("SOURCE_EVIDENCE_INTEGRITY", "member integrity check failed")
        if member.execute("PRAGMA foreign_key_check").fetchone() is not None: _fail("SOURCE_EVIDENCE_REFERENCES", "member foreign keys failed")
        ddl = validate_schema(member)
        meta = member.execute("SELECT * FROM source_evidence_metadata").fetchall()
        if len(meta) != 1: _fail("SOURCE_EVIDENCE_METADATA", "metadata record is not singular")
        meta = dict(meta[0])
        if meta["schema"] != SCHEMA or meta["revision"] != REVISION or meta["canonical_ddl_sha256"] != ddl: _fail("SOURCE_EVIDENCE_DDL", "metadata schema binding is invalid")
        for name in ("accepted_anchor","bridge_predecessor","source_checkpoint"):
            if parse_json(meta[name + "_json"], "SOURCE_EVIDENCE_METADATA") != archive_context[name]: _fail("SOURCE_EVIDENCE_METADATA", "metadata context differs from authorized context")
        if meta["previous_bridge_binding_sha256"] != archive_context["previous_bridge_binding_sha256"]: _fail("SOURCE_EVIDENCE_METADATA", "previous bridge binding differs")
        provenance = _read_projection(projection); provenance_by_raw = {r["raw_record_id"]: r for r in provenance}; wanted = set(provenance_by_raw)
        if member.execute("SELECT 1 FROM compatibility_links WHERE cache_table NOT IN ('messages','evidence_records','tclk_frames','kibble_events') LIMIT 1").fetchone() is not None:
            _fail("SOURCE_EVIDENCE_CACHE_TABLE", "unsupported cache table is present")
        for table in _CACHE:
            if member.execute("SELECT 1 FROM " + table + " c LEFT JOIN compatibility_links l ON l.cache_table=? AND l.cache_rowid=c.cache_rowid WHERE l.cache_rowid IS NULL LIMIT 1", (table,)).fetchone() is not None:
                _fail("SOURCE_EVIDENCE_REFERENCES", "unlinked cache evidence is present")
        rows = [dict(r) for r in member.execute("SELECT * FROM raw_records ORDER BY raw_record_id")]
        if {r["raw_record_id"] for r in rows} != wanted or len(rows) != len(wanted): _fail("SOURCE_EVIDENCE_RAW_SET", "raw set is not exact projection provenance")
        events = {r["raw_record_id"]: dict(r) for r in member.execute("SELECT * FROM observed_event_witnesses")}
        if len(events) != len(rows): _fail("SOURCE_EVIDENCE_REFERENCES", "event witness set is not exact")
        recovered = []
        for raw in rows:
            if not _HEX.fullmatch(raw["raw_text_sha256"]) or hashlib.sha256(raw["raw_text"].encode()).hexdigest() != raw["raw_text_sha256"]: _fail("SOURCE_EVIDENCE_RAW_SET", "raw text hash is invalid")
            envelope = parse_json(raw["raw_record_json"], "SOURCE_EVIDENCE_RAW_SET")
            if raw_record_id(raw["source"], raw["room"], raw["generation"], raw["reported_generation"], envelope) != raw["raw_record_id"]: _fail("SOURCE_EVIDENCE_RAW_SET", "raw identity is invalid")
            recovered.append({"provenance": provenance_by_raw[raw["raw_record_id"]], "raw": dict(raw, envelope=envelope), "event": [events.get(raw["raw_record_id"])], "cache_rows": _cache_validate(member, raw)})
        membership = [dict(r) for r in projection.execute("SELECT * FROM selection_membership WHERE entity_type='message'")]
        qualifications = [r[0] for r in projection.execute("SELECT record_json FROM durable_qualifications ORDER BY qualification_id")]
        coverage = []
        for item in projection.execute("SELECT * FROM coverage_history ORDER BY room,generation"):
            item = dict(item); msg = projection.execute("SELECT * FROM messages WHERE projection_row_id=?", ("sm1:" + item["witness_source_locator"],)).fetchone()
            if msg is None: _fail("SOURCE_EVIDENCE_REFERENCES", "coverage witness is missing")
            item["message"] = dict(msg); coverage.append(item)
        recovery = resolve(authorized_descriptor, observed_descriptor, recovered, membership, qualifications, coverage)
        _context(archive_context, authorized_descriptor, recovery)
        if meta["recovery_commitment_sha256"] != recovery["commitment"]: _fail("SOURCE_EVIDENCE_METADATA", "recovery commitment differs")
        counts = (len(rows), len(events), member.execute("SELECT count(*) FROM compatibility_links").fetchone()[0])
        if counts != (meta["raw_record_count"], meta["observed_event_count"], meta["cache_link_count"]): _fail("SOURCE_EVIDENCE_METADATA", "metadata counts differ from semantic counts")
        return {"schema": SCHEMA, "ddl_sha256": ddl, "records": counts[0], "events": counts[1], "cache_links": counts[2], "recovery": recovery}
    finally: member.close(); projection.close()
