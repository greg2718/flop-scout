import contextlib
import hashlib
import json
import sqlite3

import pytest

import scout_promote_private_continuity as promotion
from scout_projection_contract import ProjectionError


TARGET = ('96', '95', 'a' * 64)
OLD = {'publication_id': '95', 'content_id': '94', 'published_database_sha256': 'b' * 64, 'source_cut': 'cut'}


def fixture(tmp_path, monkeypatch, *, ledger_state=OLD, projection_content='94', marker=True):
    root = tmp_path / 'publication'; private = tmp_path / 'private'
    root.mkdir(); private.mkdir()
    pointer = {'schema': 'flop-scout-router-current/v2', 'manifest': 'manifest-v2-96-' + 'c' * 64 + '.json', 'manifest_sha256': None, 'published_at': 'now'}
    manifest = {'snapshot_id': '96', 'database_content_id': '95', 'sha256': TARGET[2], 'publication_kind': 'CONTENT', 'database': 'router-projection-v2-95-' + 'd' * 64 + '.sqlite', 'contract_revision': 'A1'}
    raw = json.dumps(manifest, sort_keys=True).encode(); pointer['manifest_sha256'] = hashlib.sha256(raw).hexdigest()
    (root / 'current.json').write_text(json.dumps(pointer)); (root / pointer['manifest']).write_bytes(raw); (root / manifest['database']).write_bytes(b'fixture')
    with sqlite3.connect(private / 'projection.sqlite') as conn:
        conn.execute('CREATE TABLE snapshot_meta(singleton INTEGER PRIMARY KEY,database_content_id TEXT)')
        conn.execute('INSERT INTO snapshot_meta VALUES(1,?)', (projection_content,))
    with sqlite3.connect(private / 'projection.sqlite.ledger') as conn:
        conn.execute('CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT)')
        for key, value in ledger_state.items(): conn.execute('INSERT INTO state VALUES(?,?)', (key, value))
    if marker:
        (private / 'private-continuity-promotion.json').write_text(json.dumps({'schema': 'scout-private-continuity-promotion/v1', 'phase': 'PREPARED', 'old': OLD, 'target': dict(zip(('publication_id', 'content_id', 'published_database_sha256'), TARGET)), 'pointer': pointer}))
    monkeypatch.setattr(promotion, 'PublicationLock', lambda root: contextlib.nullcontext())
    monkeypatch.setattr(promotion, 'validate_database', lambda *args, **kwargs: None)
    monkeypatch.setattr(promotion, 'manifest_revision', lambda manifest: 'A1')
    monkeypatch.setattr(promotion, 'digest_rows', lambda *args: {})
    verified = []
    monkeypatch.setattr(promotion, '_verify_private', lambda *args: verified.append(args))
    return root, private, verified


def test_target_state_marker_recovers_before_idempotency(tmp_path, monkeypatch):
    target = dict(zip(('publication_id', 'content_id', 'published_database_sha256'), TARGET))
    root, private, verified = fixture(tmp_path, monkeypatch, ledger_state=dict(OLD, **target), projection_content='95')
    assert promotion.promote(root, private, *TARGET) == 'RECOVERED_PROMOTION'
    assert verified and not (private / 'private-continuity-promotion.json').exists()
    assert promotion.promote(root, private, *TARGET) == 'ALREADY_PROMOTED'


def test_old_state_marker_recovers_without_mutating(tmp_path, monkeypatch):
    root, private, verified = fixture(tmp_path, monkeypatch)
    assert promotion.promote(root, private, *TARGET) == 'RECOVERED_NOOP'
    assert verified and not (private / 'private-continuity-promotion.json').exists()
    with sqlite3.connect(private / 'projection.sqlite.ledger') as conn:
        assert dict(conn.execute('SELECT key,value FROM state')) == OLD


def test_mixed_marker_state_fails_closed(tmp_path, monkeypatch):
    target = dict(zip(('publication_id', 'content_id', 'published_database_sha256'), TARGET))
    root, private, verified = fixture(tmp_path, monkeypatch, ledger_state=dict(OLD, **target), projection_content='94')
    with pytest.raises(ProjectionError, match='partial or inconsistent'):
        promotion.promote(root, private, *TARGET)
    assert not verified and (private / 'private-continuity-promotion.json').exists()


def test_wrong_marker_binding_fails_closed(tmp_path, monkeypatch):
    root, private, verified = fixture(tmp_path, monkeypatch)
    marker = private / 'private-continuity-promotion.json'
    value = json.loads(marker.read_text()); value['target']['content_id'] = '999'; marker.write_text(json.dumps(value))
    with pytest.raises(ProjectionError, match='recovery binding mismatch'):
        promotion.promote(root, private, *TARGET)
    assert not verified and marker.exists()
