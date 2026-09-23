import hashlib
import os
import sqlite3
from pathlib import Path

import pytest

import scout_epoch_fresh_snapshot as fresh


BRIDGE = "a" * 64


def _source(path, count=3):
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript("""
            CREATE TABLE evidence_schema(version INTEGER PRIMARY KEY, migrated_at TEXT NOT NULL);
            CREATE TABLE raw_network_records(raw_record_id TEXT NOT NULL, raw_text_sha256 TEXT NOT NULL,
                                             PRIMARY KEY(raw_record_id,raw_text_sha256));
            CREATE TABLE observed_events(
                event_id INTEGER PRIMARY KEY AUTOINCREMENT, raw_record_id TEXT NOT NULL,
                raw_text_sha256 TEXT NOT NULL, classification TEXT NOT NULL, source TEXT NOT NULL,
                room TEXT NOT NULL, parsed_at TEXT NOT NULL, parser_version TEXT NOT NULL,
                classification_version TEXT NOT NULL, classification_reason TEXT NOT NULL,
                signature_status TEXT NOT NULL, parse_status TEXT NOT NULL,
                structured_payload_json TEXT NOT NULL, duplicate_kind TEXT NOT NULL);
        """)
        conn.execute("INSERT INTO evidence_schema VALUES(1,'2026-01-01T00:00:00Z')")
        for number in range(count):
            raw = ("%064x" % (number + 1))
            text = hashlib.sha256(("text-%d" % number).encode()).hexdigest()
            conn.execute("INSERT INTO raw_network_records VALUES(?,?)", (raw, text))
            conn.execute("""INSERT INTO observed_events(
                raw_record_id,raw_text_sha256,classification,source,room,parsed_at,
                parser_version,classification_version,classification_reason,
                signature_status,parse_status,structured_payload_json,duplicate_kind)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                         (raw, text, "MESSAGE", "fixture", "room", "2026-01-01T00:00:00Z",
                          "fixture", "fixture", "fixture", "VALID", "PARSED", "{}", "NONE"))
        conn.commit()
    finally:
        conn.close()


def _args(source, output, minimum_cut=0, **extra):
    value = dict(source_path=source, output_path=output, source_id="test-source",
                 source_epoch="test-epoch", bridge_binding_sha256=BRIDGE,
                 minimum_cut=minimum_cut, created_at="2026-01-01T00:00:00Z",
                 disk_budget_bytes=16 * 1024 * 1024, reserve_bytes=0)
    value.update(extra)
    return value


def _code(call):
    with pytest.raises(fresh.FreshSnapshotError) as caught:
        call()
    return caught.value.code


def test_wal_backup_is_read_only_and_derives_authority_from_completed_backup(tmp_path):
    source, output = tmp_path / "observer.sqlite", tmp_path / "snapshot.sqlite"
    _source(source, 3)
    before = source.read_bytes()
    result = fresh.create_fresh_snapshot(**_args(source, output, minimum_cut=2))
    assert output.exists() and (output.stat().st_mode & 0o777) == 0o600
    assert source.read_bytes() == before
    assert result["checkpoint"]["source_cut"] == 3
    assert result["authority"]["committed_event_id"] == 3
    assert result["authority"]["snapshot"] == result["descriptor"]
    again = fresh.inspect_backup(output, source_id="test-source", source_epoch="test-epoch")
    assert again["descriptor"] == result["descriptor"]
    assert again["checkpoint"] == result["checkpoint"]


def test_committed_wal_write_can_participate_but_uncommitted_write_is_excluded(tmp_path):
    source, output = tmp_path / "observer.sqlite", tmp_path / "snapshot.sqlite"
    _source(source, 1)
    pending = sqlite3.connect(source)
    pending.execute("BEGIN IMMEDIATE")
    pending.execute("INSERT INTO raw_network_records VALUES(?,?)", ("f" * 64, "e" * 64))
    pending.execute("""INSERT INTO observed_events(raw_record_id,raw_text_sha256,classification,source,
        room,parsed_at,parser_version,classification_version,classification_reason,signature_status,
        parse_status,structured_payload_json,duplicate_kind)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        ("f" * 64, "e" * 64, "MESSAGE", "fixture", "room", "2026-01-01T00:00:00Z",
         "fixture", "fixture", "fixture", "VALID", "PARSED", "{}", "NONE"))
    try:
        result = fresh.create_fresh_snapshot(**_args(source, output))
    finally:
        pending.rollback(); pending.close()
    assert result["checkpoint"]["source_cut"] == 1
    assert result["checkpoint"]["row_counts"]["observed_events"] == 1


def test_committed_write_before_backup_snapshot_is_included(tmp_path):
    source, output = tmp_path / "observer.sqlite", tmp_path / "snapshot.sqlite"
    _source(source, 1)
    def commit_before_backup():
        conn = sqlite3.connect(source)
        try:
            conn.execute("INSERT INTO raw_network_records VALUES(?,?)", ("c" * 64, "d" * 64))
            conn.execute("""INSERT INTO observed_events(raw_record_id,raw_text_sha256,classification,source,
                room,parsed_at,parser_version,classification_version,classification_reason,signature_status,
                parse_status,structured_payload_json,duplicate_kind)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                ("c" * 64, "d" * 64, "MESSAGE", "fixture", "room", "2026-01-01T00:00:00Z",
                 "fixture", "fixture", "fixture", "VALID", "PARSED", "{}", "NONE"))
            conn.commit()
        finally:
            conn.close()
    result = fresh.create_fresh_snapshot(**_args(source, output, backup_hook=commit_before_backup))
    assert result["checkpoint"]["source_cut"] == 2


def test_fixed_backup_inspection_has_deterministic_authority_inputs(tmp_path):
    source, output = tmp_path / "observer.sqlite", tmp_path / "snapshot.sqlite"
    _source(source, 2)
    result = fresh.create_fresh_snapshot(**_args(source, output))
    first = fresh.inspect_backup(output, source_id="test-source", source_epoch="test-epoch")
    second = fresh.inspect_backup(output, source_id="test-source", source_epoch="test-epoch")
    assert first == second
    assert first["descriptor"]["sha256"] == result["authority"]["snapshot"]["sha256"]
    assert first["descriptor"]["semantic_checkpoint_sha256"] == result["authority"]["snapshot_checkpoint_sha256"]


def test_replacement_interruption_disk_and_cut_fail_closed_with_cleanup(tmp_path):
    source, output = tmp_path / "observer.sqlite", tmp_path / "snapshot.sqlite"
    _source(source, 2)
    assert _code(lambda: fresh.create_fresh_snapshot(**_args(source, output, interrupt=lambda: True))) == "FRESH_INTERRUPTED"
    assert not output.exists() and not list(tmp_path.glob(".fresh-snapshot-*"))
    assert _code(lambda: fresh.create_fresh_snapshot(**_args(source, output, disk_budget_bytes=1))) == "FRESH_DISK"
    assert _code(lambda: fresh.create_fresh_snapshot(**_args(source, output, minimum_cut=2))) == "FRESH_CUT"
    replacement = tmp_path / "replacement.sqlite"; _source(replacement, 3)
    def replace_source():
        os.replace(replacement, source)
    assert _code(lambda: fresh.create_fresh_snapshot(**_args(source, output, backup_hook=replace_source))) == "FRESH_SOURCE_REPLACED"
    assert not output.exists() and not list(tmp_path.glob(".fresh-snapshot-*"))


def test_symlink_existing_output_and_corrupt_backup_reject(tmp_path):
    source, output = tmp_path / "observer.sqlite", tmp_path / "snapshot.sqlite"
    _source(source, 2)
    linked = tmp_path / "linked.sqlite"; linked.symlink_to(source)
    assert _code(lambda: fresh.create_fresh_snapshot(**_args(linked, output))) == "FRESH_SOURCE_PATH"
    output.write_bytes(b"existing")
    assert _code(lambda: fresh.create_fresh_snapshot(**_args(source, output))) == "FRESH_OUTPUT_EXISTS"
    corrupt = tmp_path / "corrupt.sqlite"; corrupt.write_bytes(b"not sqlite")
    assert _code(lambda: fresh.inspect_backup(corrupt, source_id="test-source", source_epoch="test-epoch")) in {
        "FRESH_OUTPUT_PATH", "FRESH_QUICK_CHECK", "FRESH_SCHEMA", "FRESH_BACKUP_INVALID"}
