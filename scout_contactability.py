"""Mailbox observations are contact metadata, never identity proof.

This module deliberately accepts note values as untrusted data.  It records the
advertised value verbatim and exposes only a syntax classification for Router.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone

MAILBOX_PATTERN = re.compile(r'^[a-z0-9][a-z0-9_-]{0,47}$')
MAILBOX_VALID = 'MAILBOX_VALID'
MAILBOX_INVALID_NAME = 'MAILBOX_INVALID_NAME'
MAILBOX_MISSING = 'MAILBOX_MISSING'
MAILBOX_UNKNOWN = 'MAILBOX_UNKNOWN'
ROUTER_CONTACTABILITY = {
    MAILBOX_VALID: 'CONTACTABLE_ADVERTISED',
    MAILBOX_INVALID_NAME: 'MAILBOX_INVALID',
    MAILBOX_MISSING: 'MAILBOX_MISSING',
    MAILBOX_UNKNOWN: 'CONTACTABILITY_UNKNOWN',
}
SCHEMA = 'flop-scout-contactability/v1'

DDL = '''
CREATE TABLE IF NOT EXISTS mailbox_observations(
 observation_id TEXT PRIMARY KEY, did TEXT NOT NULL, mailbox_value TEXT,
 mailbox_status TEXT NOT NULL, observed_at TEXT NOT NULL,
 note_provenance TEXT NOT NULL, contactability_confidence TEXT NOT NULL,
 CHECK(mailbox_status IN ('MAILBOX_VALID','MAILBOX_INVALID_NAME','MAILBOX_MISSING','MAILBOX_UNKNOWN')));
CREATE INDEX IF NOT EXISTS mailbox_observations_did_time ON mailbox_observations(did,observed_at);
CREATE TRIGGER IF NOT EXISTS mailbox_observations_no_update BEFORE UPDATE ON mailbox_observations
 BEGIN SELECT RAISE(ABORT,'mailbox observations are immutable'); END;
CREATE TRIGGER IF NOT EXISTS mailbox_observations_no_delete BEFORE DELETE ON mailbox_observations
 BEGIN SELECT RAISE(ABORT,'mailbox observations are immutable'); END;
'''

def now():
    return datetime.now(timezone.utc).isoformat()

def classify(value, *, observed=True):
    """Classify without repair.  ``observed=False`` means no note was available."""
    if not observed:
        return MAILBOX_UNKNOWN
    if value is None:
        return MAILBOX_MISSING
    return MAILBOX_VALID if isinstance(value, str) and MAILBOX_PATTERN.fullmatch(value) else MAILBOX_INVALID_NAME

def parse_note(note):
    """Return the advertised mailbox exactly as written; absent is distinct from unknown."""
    if note is None:
        return None, MAILBOX_UNKNOWN
    if not isinstance(note, str):
        return None, MAILBOX_INVALID_NAME
    values = [line[len('mailbox:'):].lstrip(' ') for line in note.splitlines()
              if line.startswith('mailbox:')]
    if not values:
        return None, MAILBOX_MISSING
    # Multiple declarations are itself not a usable single advertised mailbox.
    return values[-1] if len(values) == 1 else '\n'.join(values), classify(values[-1] if len(values) == 1 else '\n'.join(values))

def confidence(status):
    return 'SYNTAX_ONLY_ADVERTISED' if status == MAILBOX_VALID else 'NOT_CONTACTABLE_FROM_NOTE'

def _statements():
    statement = ''
    for line in DDL.splitlines(True):
        statement += line
        if sqlite3.complete_statement(statement):
            yield statement
            statement = ''


def _normalized(sql):
    return re.sub(r'\s+', ' ', sql.strip().rstrip(';')).lower()


def _validate_table(conn, table, expected):
    if not table or table[0] != 'table':
        raise sqlite3.DatabaseError('SCHEMA_DRIFT: mailbox_observations table missing or incompatible')
    expected_columns = [
        ('observation_id', 'TEXT', 0, None, 1), ('did', 'TEXT', 1, None, 0),
        ('mailbox_value', 'TEXT', 0, None, 0), ('mailbox_status', 'TEXT', 1, None, 0),
        ('observed_at', 'TEXT', 1, None, 0), ('note_provenance', 'TEXT', 1, None, 0),
        ('contactability_confidence', 'TEXT', 1, None, 0),
    ]
    columns = [(row[1], row[2].upper(), row[3], row[4], row[5]) for row in conn.execute('PRAGMA table_info(mailbox_observations)')]
    if columns != expected_columns:
        raise sqlite3.DatabaseError('SCHEMA_DRIFT: mailbox_observations columns incompatible')
    if _normalized(table[3]) != _normalized(expected[0].replace(' IF NOT EXISTS', '')):
        raise sqlite3.DatabaseError('SCHEMA_DRIFT: mailbox_observations table definition incompatible')


def _validate_schema(conn):
    objects = {row[1]: row for row in conn.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name LIKE 'mailbox_observations%'")}
    expected = list(_statements())
    _validate_table(conn, objects.get('mailbox_observations'), expected)
    index = objects.get('mailbox_observations_did_time')
    if not index or index[0] != 'index' or [row[2] for row in conn.execute('PRAGMA index_info(mailbox_observations_did_time)')] != ['did', 'observed_at']:
        raise sqlite3.DatabaseError('SCHEMA_DRIFT: mailbox_observations index incompatible')
    if _normalized(index[3]) != _normalized(expected[1].replace(' IF NOT EXISTS', '')):
        raise sqlite3.DatabaseError('SCHEMA_DRIFT: mailbox_observations index definition incompatible')
    expected_triggers = {'mailbox_observations_no_update': expected[2], 'mailbox_observations_no_delete': expected[3]}
    actual_triggers = {row[1]: row for row in conn.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name='mailbox_observations'")}
    if set(actual_triggers) != set(expected_triggers):
        raise sqlite3.DatabaseError('SCHEMA_DRIFT: mailbox_observations trigger set incompatible')
    for name, sql in expected_triggers.items():
        row = actual_triggers[name]
        if row[0] != 'trigger' or _normalized(row[3]) != _normalized(sql.replace(' IF NOT EXISTS', '')):
            raise sqlite3.DatabaseError('SCHEMA_DRIFT: '+name+' definition incompatible')


def install_schema(conn):
    """Install and validate contactability objects atomically within this schema unit."""
    conn.execute('SAVEPOINT contactability_schema')
    try:
        expected = list(_statements())
        existing = conn.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name='mailbox_observations'").fetchone()
        if existing is not None:
            _validate_table(conn, existing, expected)
        for statement in _statements():
            conn.execute(statement)
        _validate_schema(conn)
        conn.execute('RELEASE contactability_schema')
    except BaseException:
        conn.execute('ROLLBACK TO contactability_schema')
        conn.execute('RELEASE contactability_schema')
        raise

def observe(conn, did, mailbox_value, *, note_provenance, observed_at=None, observed=True):
    if not isinstance(did, str) or not did:
        raise ValueError('A DID is required for a mailbox observation')
    observed_at = observed_at or now()
    status = classify(mailbox_value, observed=observed)
    # The time is intentionally part of the identity: two separate note reads are
    # historical observations, even when they advertise the same value.
    body = json.dumps([did, mailbox_value, status, observed_at, note_provenance], separators=(',', ':'), ensure_ascii=True)
    oid = hashlib.sha256(body.encode()).hexdigest()
    with conn:
        conn.execute('INSERT OR IGNORE INTO mailbox_observations VALUES (?,?,?,?,?,?,?)',
            (oid, did, mailbox_value, status, observed_at, note_provenance, confidence(status)))
    return dict(observation_id=oid, did=did, mailbox_value=mailbox_value, mailbox_status=status,
                mailbox_observed_at=observed_at, mailbox_note_provenance=note_provenance,
                contactability_confidence=confidence(status), router_contactability=ROUTER_CONTACTABILITY[status])

def latest(conn, did):
    row = conn.execute('SELECT * FROM mailbox_observations WHERE did=? ORDER BY observed_at DESC, observation_id DESC LIMIT 1', (did,)).fetchone()
    if row is None:
        return None
    row = dict(row)
    return dict(row, mailbox_observed_at=row.pop('observed_at'), mailbox_note_provenance=row.pop('note_provenance'),
                router_contactability=ROUTER_CONTACTABILITY[row['mailbox_status']])

def guard_self_publication(mailbox_value):
    status = classify(mailbox_value)
    if status != MAILBOX_VALID:
        raise ValueError('Scout self-publication blocked: persistent mailbox is '+status)
    return status
