"""Roots-first TCLK evidence lookup remains bounded and semantically exact."""
import collections
import sqlite3

import flop_scout

from scout_projection_source import Outbox


CURRENT_SQL="""WITH roots AS (
    SELECT rowid FROM tclk_frames WHERE offer_id=?
    UNION
    SELECT rowid FROM tclk_frames WHERE contract_id=?
)
SELECT r.* FROM roots t
JOIN compatibility_evidence_links l ON l.cache_table='tclk_frames' AND l.cache_rowid=t.rowid
JOIN raw_network_records r ON r.raw_record_id=l.raw_record_id
WHERE r.room=? AND r.generation IS ? LIMIT 201"""

CANDIDATE_SQL="""WITH roots AS (
    SELECT rowid FROM tclk_frames WHERE offer_id=?
    UNION
    SELECT rowid FROM tclk_frames WHERE contract_id=?
)
SELECT r.* FROM roots t
CROSS JOIN compatibility_evidence_links l INDEXED BY sqlite_autoindex_compatibility_evidence_links_1
ON l.cache_table='tclk_frames' AND l.cache_rowid=t.rowid
JOIN raw_network_records r ON r.raw_record_id=l.raw_record_id
WHERE r.room=? AND r.generation IS ? LIMIT 201"""


def database(path=':memory:'):
    c=sqlite3.connect(path);c.row_factory=sqlite3.Row
    flop_scout.init_observer_db(c);Outbox(c,epoch='test',install=True)
    return c


def add(c,n,offer=None,contract=None,room='room',generation='1',raw=None):
    raw=raw or 'raw-'+str(n);text='tclk1 {"type":"offer","id":"'+str(offer or contract or n)+'"}'
    digest='hash-'+raw
    c.execute("""INSERT OR IGNORE INTO raw_network_records(
        raw_record_id,source,room,generation,seq,retrieved_at,raw_text,raw_text_sha256,
        raw_record_json,signature_status,did_mismatch,transport_metadata_json,
        ingestion_schema,ingestion_version,created_at,legacy_record,raw_completeness)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(
        raw,'test',room,generation,n,'now',text,digest,'{}','VERIFIED_OFFLINE',0,'{}',
        'test','1','now',0,'COMPLETE'))
    c.execute("""INSERT INTO tclk_frames(
        room,generation,seq,transport_verification_status,transport_binding_status,
        frame_hash,offer_id,contract_id,observed_at,parse_status,raw_text)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)""",(
        room,generation,n,'VERIFIED_OFFLINE','SIGNED_TCLK_FRAME','frame-'+str(n),
        offer,contract,'now','TCLK_PARSEABLE',text))


def rows(c,sql,key,room='room',generation='1'):
    return c.execute(sql,(key,key,room,generation)).fetchall()


def multiset(rows):
    return collections.Counter(tuple(row) for row in rows)


def pair_multiset(rows):
    return collections.Counter((row['raw_record_id'],row['raw_text_sha256']) for row in rows)


def fixture(c):
    add(c,1,offer='offer');add(c,2,contract='contract');add(c,3,offer='mixed',contract='mixed')
    add(c,4,offer='duplicate');add(c,5,contract='duplicate')
    add(c,6,offer='offer',room='other');add(c,7,contract='contract',generation='other')


def test_roots_first_matches_current_for_offer_contract_mixed_and_duplicates():
    c=database();fixture(c)
    for key,expected in [('offer',1),('contract',1),('mixed',1),('duplicate',2)]:
        current=rows(c,CURRENT_SQL,key);candidate=rows(c,CANDIDATE_SQL,key)
        assert len(current)==len(candidate)==expected
        assert pair_multiset(current)==pair_multiset(candidate)
        assert multiset(current)==multiset(candidate)
        assert all(row['room']=='room' and row['generation']=='1' for row in candidate)
        assert len(candidate)<201
    assert all(count==1 for count in pair_multiset(rows(c,CANDIDATE_SQL,'duplicate')).values())


def test_roots_first_plan_uses_bounded_indexes_without_cache_table_scan():
    c=database();fixture(c)
    details=[' '.join(row[3].split()) for row in c.execute('EXPLAIN QUERY PLAN '+CANDIDATE_SQL,('mixed','mixed','room','1'))]
    plan='\n'.join(details)
    assert 'router_projection_tclk_offer' in plan
    assert 'router_projection_tclk_contract' in plan
    assert 'sqlite_autoindex_compatibility_evidence_links_1' in plan
    assert 'cache_table=? AND cache_rowid=?' in plan
    assert not any('cache_table=?)' in detail and 'cache_rowid' not in detail for detail in details)


def test_roots_first_limit_201_preserves_fail_closed_diagnostic_boundary():
    c=database()
    for n in range(202):add(c,n,offer='many',raw='many-'+str(n))
    current=rows(c,CURRENT_SQL,'many');candidate=rows(c,CANDIDATE_SQL,'many')
    assert len(current)==201 and len(candidate)==201


def test_roots_first_read_only_query_does_not_mutate_fixture(tmp_path):
    path=tmp_path/'observer.sqlite';c=database(path);fixture(c);c.commit();c.close()
    before=path.stat();c=sqlite3.connect('file:'+str(path)+'?mode=ro&immutable=1',uri=True);c.row_factory=sqlite3.Row
    c.execute('PRAGMA query_only=ON')
    assert len(rows(c,CANDIDATE_SQL,'mixed'))==1
    assert c.execute('PRAGMA query_only').fetchone()[0]==1
    c.close();assert path.stat()==before
