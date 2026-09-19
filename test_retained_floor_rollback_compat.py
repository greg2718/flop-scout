"""Rollback-target compatibility for the approved retained-floor addition."""
import sqlite3

import pytest

import flop_scout as scout
import scout_coverage as coverage
import scout_schema as schema


def make_db(tmp_path, monkeypatch, name='observer.sqlite'):
    monkeypatch.setattr(scout, 'HOME', tmp_path)
    monkeypatch.setattr(scout, 'LOG_FILE', tmp_path/'activity.jsonl')
    path = tmp_path/name
    conn = scout.observer_connect_write(path)
    scout.update_room_cursor(conn, 'technocore', 'g1', 100)
    coverage.state(conn, 'technocore', 'g1', 100)
    conn.commit()
    return conn, path


def test_clean_legacy_database_and_coverage_api_still_work(tmp_path, monkeypatch):
    conn, path = make_db(tmp_path, monkeypatch)
    try:
        state = coverage.save_tail(conn, 'technocore', 'g1', 100, 100, 100)
        assert state['coverage_cursor'] == 100
        assert 'retained_floor' not in state
    finally:
        conn.close()
    with scout.observer_connect_write(path) as reopened:
        assert schema.status(reopened)['status'] == 'PASS'


def test_approved_retained_floor_allows_old_create_and_update(tmp_path, monkeypatch):
    conn, path = make_db(tmp_path, monkeypatch)
    try:
        conn.execute('ALTER TABLE source_coverage_state ADD COLUMN retained_floor INTEGER')
        conn.commit()
    finally:
        conn.close()
    with scout.observer_connect_write(path) as reopened:
        existing = coverage.save_tail(reopened, 'technocore', 'g1', 100, 100, 100)
        created = coverage.state(reopened, 'new-room', 'g2', 7)
        assert existing['retained_floor'] is None
        assert created['retained_floor'] is None
        assert reopened.execute("SELECT retained_floor FROM source_coverage_state WHERE room='technocore' AND generation='g1'").fetchone()[0] is None
        assert reopened.execute("SELECT retained_floor FROM source_coverage_state WHERE room='new-room' AND generation='g2'").fetchone()[0] is None


def replace_coverage_table(conn, retained_definition, primary_key='room,generation'):
    conn.execute('DROP TABLE source_coverage_state')
    conn.execute(f'''CREATE TABLE source_coverage_state(
        source TEXT NOT NULL, room TEXT NOT NULL, generation TEXT NOT NULL,
        coverage_cursor INTEGER NOT NULL, observed_high_water INTEGER NOT NULL,
        server_tail_high_water INTEGER, coverage_status TEXT NOT NULL,
        backfill_required INTEGER NOT NULL, backfill_from_seq INTEGER, backfill_to_seq INTEGER,
        last_checked_at TEXT, last_backfill_at TEXT, last_backfill_result TEXT,
        origin_unknown INTEGER NOT NULL DEFAULT 0,
        retained_floor {retained_definition},
        PRIMARY KEY({primary_key}))''')
    conn.commit()


@pytest.mark.parametrize('definition,primary_key', [
    ('TEXT', 'room,generation'),
    ('INTEGER NOT NULL DEFAULT 0', 'room,generation'),
    ('INTEGER DEFAULT 0', 'room,generation'),
    ('INTEGER', 'room,generation,retained_floor'),
])
def test_incompatible_retained_floor_definitions_fail_closed(tmp_path, monkeypatch, definition, primary_key):
    conn, path = make_db(tmp_path, monkeypatch)
    try:
        replace_coverage_table(conn, definition, primary_key)
    finally:
        conn.close()
    with pytest.raises(schema.SchemaDrift, match='retained_floor'):
        scout.observer_connect_write(path)


def test_unrelated_additive_column_still_fails_closed(tmp_path, monkeypatch):
    conn, path = make_db(tmp_path, monkeypatch)
    try:
        conn.execute('ALTER TABLE source_coverage_state ADD COLUMN unrelated_addition INTEGER')
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(schema.SchemaDrift, match='column order/extra columns'):
        scout.observer_connect_write(path)
