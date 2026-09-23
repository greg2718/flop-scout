"""Offline-only, read-only SQLite Backup-API producer for Epoch-V2 fresh cuts.

This module has no production defaults and never publishes, plans, or opens a
Router database.  The only writable object is a new caller-selected snapshot.
"""
import argparse
import hashlib
import json
import os
import re
import resource
import shutil
import sqlite3
import stat
import tempfile
import time
from pathlib import Path

from scout_epoch_v2 import commitment, fresh_cut_authority_commitment


SCHEMA = "flop-scout-epoch-source-snapshot/v1"
CHECKPOINT_SCHEMA = "flop-scout-epoch-source-snapshot-checkpoint/v1"
MAX_PATH_BYTES = 4096
_HEX = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[a-z][a-z0-9:._-]{0,128}$")
_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$")
REQUIRED_EVENT_COLUMNS = {
    "event_id", "raw_record_id", "raw_text_sha256", "classification", "source",
    "room", "parsed_at", "parser_version", "classification_version",
    "classification_reason", "signature_status", "parse_status",
    "structured_payload_json", "duplicate_kind",
}


class FreshSnapshotError(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def _fail(code, message):
    raise FreshSnapshotError(code, message)


def _fsync_dir(path):
    descriptor = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _regular(path, code):
    try:
        item = os.lstat(path)
    except OSError:
        _fail(code, "required path is unavailable")
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
        _fail(code, "path is not a regular non-symlink file")
    return item


def _directory_chain(path, code):
    """Validate each existing absolute ancestor without resolving a symlink."""
    if not isinstance(path, Path) or not path.is_absolute():
        _fail(code, "path must be absolute")
    if len(os.fsencode(str(path))) > MAX_PATH_BYTES:
        _fail(code, "path exceeds bound")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            item = os.lstat(current)
        except OSError:
            _fail(code, "required output ancestor is unavailable")
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
            _fail(code, "output ancestor is not a non-symlink directory")
    return path


def _absolute_file(path, code):
    path = Path(path)
    if not path.is_absolute():
        _fail(code, "path must be absolute")
    _directory_chain(path.parent, code)
    _regular(path, code)
    return path


def _new_output(path):
    path = Path(path)
    if not path.is_absolute():
        _fail("FRESH_OUTPUT_PATH", "output path must be absolute")
    _directory_chain(path.parent, "FRESH_OUTPUT_PATH")
    try:
        os.lstat(path)
    except FileNotFoundError:
        return path
    except OSError:
        _fail("FRESH_OUTPUT_PATH", "output path is unavailable")
    _fail("FRESH_OUTPUT_EXISTS", "final output already exists")


def _identity(value, name):
    if type(value) is not str or not _ID.match(value):
        _fail("FRESH_IDENTITY", "%s is not a bounded identifier" % name)
    return value


def _hash(value, name):
    if type(value) is not str or not _HEX.match(value):
        _fail("FRESH_HASH", "%s is not a lower-case SHA-256 digest" % name)
    return value


def _created_at(value):
    if type(value) is not str or not _TIME.match(value):
        _fail("FRESH_TIMESTAMP", "created_at is not canonical UTC RFC3339")
    return value


def _source_stat_identity(path):
    item = _regular(path, "FRESH_SOURCE_PATH")
    return item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns


def _require_same_source_inode(path, before):
    """Classify a disappearing/replaced source before exposing SQLite errors."""
    try:
        after = _source_stat_identity(path)
    except FreshSnapshotError:
        _fail("FRESH_SOURCE_REPLACED", "source became unavailable during backup")
    if after[:2] != before[:2]:
        _fail("FRESH_SOURCE_REPLACED", "source inode changed during backup")


def _stream_hash(path):
    hasher = hashlib.sha256()
    size = 0
    descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _fail("FRESH_OUTPUT_PATH", "snapshot is not regular")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            size += len(block)
            hasher.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        _fail("FRESH_CHANGING_FILE", "snapshot changed while hashing")
    return hasher.hexdigest(), size


def _normalized_schema(conn):
    rows = conn.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master "
        "WHERE type IN ('table','index','trigger','view') "
        "AND name NOT LIKE 'sqlite_%' ORDER BY type,name,tbl_name").fetchall()
    normal = []
    for kind, name, table, sql in rows:
        if sql is None:
            continue
        normal.append({"type": kind, "name": name, "table": table,
                       "sql": re.sub(r"\s+", " ", sql.strip())})
    user_version = conn.execute("PRAGMA user_version").fetchone()[0]
    return commitment("fresh-snapshot-schema", {"user_version": user_version,
                                                   "objects": normal})


def _check_backup(conn, source_id, source_epoch):
    quick = conn.execute("PRAGMA quick_check").fetchall()
    if quick != [("ok",)]:
        _fail("FRESH_QUICK_CHECK", "backup quick_check failed")
    foreign = conn.execute("PRAGMA foreign_key_check").fetchall()
    if foreign:
        _fail("FRESH_FOREIGN_KEYS", "backup foreign-key validation failed")
    tables = {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    if not {"observed_events", "raw_network_records", "evidence_schema"} <= tables:
        _fail("FRESH_SCHEMA", "backup lacks required observer tables")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(observed_events)")}
    if not REQUIRED_EVENT_COLUMNS <= columns:
        _fail("FRESH_SCHEMA", "backup observed-event schema is incompatible")
    event_id = conn.execute("SELECT coalesce(max(event_id),0) FROM observed_events").fetchone()[0]
    if type(event_id) is not int or event_id < 0:
        _fail("FRESH_CHECKPOINT", "backup event checkpoint is invalid")
    evidence_version = conn.execute(
        "SELECT coalesce(max(version),0) FROM evidence_schema").fetchone()[0]
    if type(evidence_version) is not int or evidence_version < 1:
        _fail("FRESH_SCHEMA", "backup evidence schema has no supported revision")
    counts = {
        "observed_events": conn.execute("SELECT count(*) FROM observed_events").fetchone()[0],
        "raw_network_records": conn.execute("SELECT count(*) FROM raw_network_records").fetchone()[0],
    }
    schema_hash = _normalized_schema(conn)
    checkpoint = {
        "schema": CHECKPOINT_SCHEMA,
        "source_id": source_id,
        "source_epoch": source_epoch,
        "source_cut": event_id,
        "evidence_schema_version": evidence_version,
        "row_counts": counts,
        "sqlite_schema_sha256": schema_hash,
    }
    return checkpoint, commitment("fresh-snapshot-checkpoint", checkpoint)


def inspect_backup(path, *, source_id, source_epoch):
    """Read-only backup verification used before final installation and by tests."""
    path = _absolute_file(path, "FRESH_OUTPUT_PATH")
    uri = path.as_uri() + "?mode=ro"
    conn = None
    try:
        conn = sqlite3.connect(uri, uri=True)
        conn.execute("PRAGMA query_only=ON")
        checkpoint, semantic = _check_backup(conn, source_id, source_epoch)
    except FreshSnapshotError:
        raise
    except sqlite3.Error:
        _fail("FRESH_BACKUP_INVALID", "backup cannot be independently validated")
    finally:
        if conn is not None:
            conn.close()
    digest, size = _stream_hash(path)
    return {"descriptor": {"schema": SCHEMA, "locator": path.name,
                            "sha256": digest, "size_bytes": size,
                            "sqlite_schema_sha256": checkpoint["sqlite_schema_sha256"],
                            "semantic_checkpoint_sha256": semantic},
            "checkpoint": checkpoint}


def create_fresh_snapshot(*, source_path, output_path, source_id, source_epoch,
                          bridge_binding_sha256, minimum_cut, created_at,
                          disk_budget_bytes, reserve_bytes, interrupt=None,
                          backup_hook=None):
    """Back up a live WAL source without writing it, then install one snapshot.

    ``interrupt`` and ``backup_hook`` are test-only cooperative hooks.  Neither
    is exposed by the CLI or used by production callers.
    """
    started = time.monotonic()
    source = _absolute_file(source_path, "FRESH_SOURCE_PATH")
    output = _new_output(output_path)
    source_id = _identity(source_id, "source_id")
    source_epoch = _identity(source_epoch, "source_epoch")
    _hash(bridge_binding_sha256, "bridge_binding_sha256")
    _created_at(created_at)
    if type(minimum_cut) is not int or type(minimum_cut) is bool or minimum_cut < 0:
        _fail("FRESH_CUT", "minimum cut is invalid")
    if (type(disk_budget_bytes) is not int or type(reserve_bytes) is not int or
            disk_budget_bytes < 1 or reserve_bytes < 0):
        _fail("FRESH_DISK", "disk budget or reserve is invalid")
    source_before = _source_stat_identity(source)
    if source_before[2] > disk_budget_bytes:
        _fail("FRESH_DISK", "source exceeds explicit snapshot budget")
    if shutil.disk_usage(output.parent).free < disk_budget_bytes + reserve_bytes:
        _fail("FRESH_DISK", "output filesystem lacks budget plus reserve")
    stage_dir = Path(tempfile.mkdtemp(prefix=".fresh-snapshot-", dir=str(output.parent)))
    os.chmod(stage_dir, 0o700)
    staged = stage_dir / "snapshot.sqlite"
    installed = False
    try:
        src = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)
        try:
            src.execute("PRAGMA query_only=ON")
            if backup_hook is not None:
                backup_hook()
            dst = sqlite3.connect(staged)
            try:
                os.chmod(staged, 0o600)
                def progress(_status, _remaining, _total):
                    if interrupt is not None and interrupt():
                        _fail("FRESH_INTERRUPTED", "backup interrupted")
                src.backup(dst, pages=256, progress=progress, sleep=0.01)
                # The destination is an independent immutable member.  Do not
                # leave it WAL-mode, which would require a new sidecar on its
                # later read-only verification path.
                dst.execute("PRAGMA journal_mode=DELETE")
                dst.commit()
            finally:
                dst.close()
        finally:
            src.close()
        _require_same_source_inode(source, source_before)
        verified = inspect_backup(staged, source_id=source_id, source_epoch=source_epoch)
        if verified["descriptor"]["size_bytes"] > disk_budget_bytes:
            _fail("FRESH_DISK", "completed backup exceeds explicit snapshot budget")
        cut = verified["checkpoint"]["source_cut"]
        if cut <= minimum_cut:
            _fail("FRESH_CUT", "backup source cut did not advance bridge cut")
        authority = {
            "schema": "flop-scout-epoch-fresh-cut-authority/v1",
            "source_id": source_id,
            "epoch": source_epoch,
            "committed_event_id": cut,
            "snapshot": verified["descriptor"],
            "snapshot_checkpoint_sha256": verified["descriptor"]["semantic_checkpoint_sha256"],
            "bridge_binding_sha256": bridge_binding_sha256,
        }
        authority["authority_sha256"] = fresh_cut_authority_commitment(authority)
        # Reopening is deliberately separate from the first backup inspection.
        repeat = inspect_backup(staged, source_id=source_id, source_epoch=source_epoch)
        if repeat != verified:
            _fail("FRESH_REVALIDATION", "backup changed before installation")
        descriptor = os.open(str(staged), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_dir(stage_dir)
        os.link(staged, output)
        installed = True
        _fsync_dir(output.parent)
        os.unlink(staged)
        _fsync_dir(stage_dir)
        elapsed = time.monotonic() - started
        return {"schema": "flop-scout-epoch-fresh-snapshot-result/v1",
                "created_at": created_at, "descriptor": verified["descriptor"],
                "checkpoint": verified["checkpoint"], "authority": authority,
                "seconds": elapsed,
                "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
    except FileExistsError:
        _fail("FRESH_OUTPUT_EXISTS", "final output appeared during installation")
    except sqlite3.Error:
        # A source replacement can cause SQLite's active read handle to report
        # a generic I/O error before normal post-backup inode verification.
        _require_same_source_inode(source, source_before)
        _fail("FRESH_BACKUP_INVALID", "source backup could not be completed")
    finally:
        if staged.exists() and not installed:
            staged.unlink()
        try:
            for item in stage_dir.iterdir():
                mode = os.lstat(item).st_mode
                if stat.S_ISREG(mode) or stat.S_ISLNK(mode):
                    item.unlink()
                else:
                    _fail("FRESH_STAGING", "unexpected staging entry")
            stage_dir.rmdir()
        except OSError:
            pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--source-epoch", required=True)
    parser.add_argument("--bridge-binding-sha256", required=True)
    parser.add_argument("--minimum-cut", type=int, required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--disk-budget-bytes", type=int, required=True)
    parser.add_argument("--reserve-bytes", type=int, required=True)
    args = parser.parse_args(argv)
    result = create_fresh_snapshot(
        source_path=args.source, output_path=args.output, source_id=args.source_id,
        source_epoch=args.source_epoch, bridge_binding_sha256=args.bridge_binding_sha256,
        minimum_cut=args.minimum_cut, created_at=args.created_at,
        disk_budget_bytes=args.disk_budget_bytes, reserve_bytes=args.reserve_bytes)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
