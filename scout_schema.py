"""Physical evidence schema contract and conservative, atomic reconciliation.

The canonical DDL is instantiated only in memory. No network or identity access.
Unknown historical epoch origins stay unknown; reconciliation never advances cursors.
"""
import re
import sqlite3
from functools import lru_cache


class SchemaDrift(RuntimeError):
    pass


def quote(name):
    return '"' + name.replace('"', '""') + '"'


def normalized(sql):
    parts = re.split(r"('(?:''|[^'])*')", sql or '')
    return ''.join(part if i % 2 else re.sub(r'\s+', ' ', part).lower()
                   for i, part in enumerate(parts)).strip().replace('if not exists ', '')


def structure(conn):
    objects = {}
    for kind, name, table, sql in conn.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"):
        entry = {'kind': kind, 'table': table, 'sql': sql}
        if kind == 'table':
            entry['columns'] = [tuple(r)[1:] for r in conn.execute('PRAGMA table_info('+quote(name)+')')]
            entry['foreign_keys'] = sorted(tuple(r)[1:] for r in conn.execute('PRAGMA foreign_key_list('+quote(name)+')'))
            entry['unique'] = sorted(
                (r[2], r[3], r[4], tuple(tuple(x)[1:] for x in conn.execute('PRAGMA index_xinfo('+quote(r[1])+')')))
                for r in conn.execute('PRAGMA index_list('+quote(name)+')') if r[3] != 'c')
        objects[name] = entry
    return objects


@lru_cache(maxsize=1)
def contract():
    import scout_evidence as ev
    import scout_coverage as cv
    with sqlite3.connect(':memory:') as c:
        c.executescript(ev.DDL)
        c.executescript(ev.GAP_DDL)
        cv.install_schema(c)
        return structure(c)


@lru_cache(maxsize=1)
def projection_outbox_contract():
    """Exact opt-in objects only; never allow arbitrary evidence-table triggers."""
    import scout_evidence as ev
    from scout_projection_source import OUTBOX_SQL, update_trigger_sql
    with sqlite3.connect(':memory:') as c:
        c.executescript(ev.DDL)
        c.executescript("""
          CREATE TABLE compatibility_evidence_links(cache_table TEXT,cache_rowid INTEGER,raw_record_id TEXT,raw_text_sha256 TEXT);
          CREATE TABLE tclk_frames(offer_id TEXT,frame_type TEXT,room TEXT,generation TEXT,contract_id TEXT);
          CREATE TABLE interactions(room TEXT,source_seq INTEGER,response_seq INTEGER,source_did TEXT,target_did TEXT,relationship_type TEXT,confidence REAL);
          CREATE TABLE messages(dummy TEXT);
          CREATE TABLE evidence_records(dummy TEXT);
          CREATE TABLE kibble_events(dummy TEXT);
        """)
        c.executescript(OUTBOX_SQL)
        for table in ('messages','evidence_records','kibble_events','tclk_frames'):c.execute(update_trigger_sql(table))
        return {name:obj for name,obj in structure(c).items() if name.startswith('router_projection_')}


def status(conn):
    expected, actual = dict(contract()), structure(conn)
    optional=projection_outbox_contract() if any(name.startswith('router_projection_') for name in actual) else {}
    expected.update(optional)
    result = dict(declared_schema_version=None, expected_schema_version=3,
                  missing_tables=[], missing_columns=[], missing_indexes=[],
                  missing_triggers=[], incompatible_objects=[])
    if 'evidence_schema' in actual:
        try:
            result['declared_schema_version'] = conn.execute('SELECT max(version) FROM evidence_schema').fetchone()[0]
        except sqlite3.Error:
            result['incompatible_objects'].append('evidence_schema: invalid version metadata')
    for name, obj in expected.items():
        other = actual.get(name)
        if other is None:
            key = {'table':'missing_tables', 'index':'missing_indexes', 'trigger':'missing_triggers'}[obj['kind']]
            result[key].append(name)
            continue
        if other['kind'] != obj['kind']:
            result['incompatible_objects'].append(name+': wrong object kind')
        elif obj['kind'] == 'table':
            cols = {r[0]: r for r in other['columns']}
            for col in obj['columns']:
                if col[0] not in cols:
                    result['missing_columns'].append(name+'.'+col[0])
                elif col != cols[col[0]]:
                    result['incompatible_objects'].append(name+'.'+col[0]+': type/default/nullability/PK mismatch')
            # Positional inserts require exact column order, including rejecting extras.
            present = [c for c in obj['columns'] if c[0] in cols]
            if [c[0] for c in present] != [c[0] for c in other['columns']]:
                result['incompatible_objects'].append(name+': column order/extra columns')
            for field in ('foreign_keys', 'unique'):
                if obj[field] != other[field]:
                    result['incompatible_objects'].append(name+': '+field+' mismatch')
            # Covers CHECK constraints, collations, table options and generated columns.
            def table_sql(sql):
                text = normalized(sql).replace('"', '')
                if name == 'source_coverage_state':
                    text = re.sub(r',?\s*origin_unknown integer not null default 0\s*,?', ',', text)
                return re.sub(r'\s*([(),])\s*', r'\1', text).replace(',)', ')')
            if table_sql(obj['sql']) != table_sql(other['sql']):
                result['incompatible_objects'].append(name+': table definition mismatch')
        elif normalized(obj['sql']) != normalized(other['sql']):
            result['incompatible_objects'].append(name+': definition mismatch')
    for name, obj in actual.items():
        if optional and name.startswith('router_projection_') and name not in optional:
            result['incompatible_objects'].append(name+': unexpected projection outbox object')
        if obj['kind'] == 'trigger' and obj['table'] in expected and name not in expected:
            result['incompatible_objects'].append(name+': unexpected trigger on evidence table')
    if optional and any(name in optional for key in ('missing_tables','missing_indexes','missing_triggers') for name in result[key]):
        result['incompatible_objects'].append('projection outbox: incomplete feed schema requires explicit recovery')
    version = result['declared_schema_version']
    if version != 3:
        result['incompatible_objects'].append('requires declared schema version 3; use normal initialization for older schemas')
    if version == 3 and {r[0] for r in conn.execute('SELECT version FROM evidence_schema')} != {1, 2, 3}:
        result['incompatible_objects'].append('incomplete version history')
    # Missing historical tables cannot safely be reconstructed as empty evidence.
    if result['missing_tables']:
        result['incompatible_objects'].append('missing tables require reviewed recovery; empty replacements may erase provenance')
    if any(c != 'source_coverage_state.origin_unknown' for c in result['missing_columns']):
        result['incompatible_objects'].append('missing columns have no approved backfill semantics')
    dirty = any(result[k] for k in ('missing_tables','missing_columns','missing_indexes','missing_triggers','incompatible_objects'))
    result['reconciliation_required'] = dirty
    result['status'] = 'INCOMPATIBLE' if result['incompatible_objects'] else ('RECONCILIATION_REQUIRED' if dirty else 'PASS')
    result['physical_schema_status'] = result['status']
    return result


def reconcile(conn):
    conn.execute('SAVEPOINT schema_reconcile')
    try:
        before = status(conn)
        if before['status'] == 'INCOMPATIBLE':
            raise SchemaDrift('SCHEMA_DRIFT: '+repr(before))
        if before['missing_columns']:
            conn.execute('ALTER TABLE source_coverage_state ADD COLUMN origin_unknown INTEGER NOT NULL DEFAULT 0')
            # Legacy rows predate explicit epoch-origin tracking. There is no durable
            # proof distinguishing imported baselines from generation changes.
            conn.execute('UPDATE source_coverage_state SET origin_unknown=1')
        for name in before['missing_indexes'] + before['missing_triggers']:
            conn.execute(contract()[name]['sql'])
        after = status(conn)
        if after['status'] != 'PASS':
            raise SchemaDrift('SCHEMA_DRIFT: verification after reconciliation failed: '+repr(after))
        conn.execute('RELEASE schema_reconcile')
        return dict(after, changed=before['status'] != 'PASS')
    except BaseException:
        conn.execute('ROLLBACK TO schema_reconcile')
        conn.execute('RELEASE schema_reconcile')
        raise
