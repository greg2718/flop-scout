import json
import sqlite3
from pathlib import Path
import pytest
import flop_scout as scout
from scout_current_publication import generate,Source,LOCAL_DIDS
from scout_projection_publish import validate_database
from scout_projection_contract import instant,utc


def test_current_publication_bounded_and_restart(tmp_path):
    source=tmp_path/'observer.sqlite'
    c=scout.observer_connect_write(source)
    for seq in range(1,15):
        scout.ingest_messages(c,'technocore',[dict(seq=seq,text='hello current '+str(seq),**{'from':LOCAL_DIDS[0]})],generation='g1',source_endpoint='/r/technocore')
    c.close()
    state=tmp_path/'router.json';state.write_text('{}')
    work=tmp_path/'work';root=tmp_path/'public'
    first=generate(source,work,root,state,limit=5)
    assert first['record_count']==14 # mandatory local identity reserve
    assert first['source_selection']['selected']<=50000
    assert first['contract_revision']=='A1'
    before=(root/'current.json').read_bytes()
    second=generate(source,work,root,state,limit=5)
    assert second['database']==first['database']
    assert second['record_count']==first['record_count']
    with sqlite3.connect(first['database']) as c:
        annotations=[json.loads(r[0]) for r in c.execute('SELECT annotations_json FROM source_provenance')]
        assert all(x['same_operator'] is True and x['independent_reputation'] is False for x in annotations)
    assert (root/'current.json').read_bytes()!=before # safe heartbeat, same immutable DB


def test_existing_router_requires_explicit_pin_export(tmp_path):
    state=tmp_path/'router.json';state.write_text(json.dumps({'scout_contract':'V2_A1'}))
    with pytest.raises(ValueError,match='explicit pins'):
        generate(tmp_path/'unused',tmp_path/'work',tmp_path/'public',state)
    assert not (tmp_path/'public'/'current.json').exists()


def test_missing_tclk_root_is_retained_as_unresolved(tmp_path):
    from unittest.mock import patch
    from scout_current_publication import current_bundle
    source=tmp_path/'observer.sqlite';c=scout.observer_connect_write(source)
    scout.ingest_messages(c,'tclk-offers',[dict(seq=1,text='tclk1 {"type":"cancel","ref":"missing"}',**{'from':LOCAL_DIDS[0]})],generation='g1',source_endpoint='/r/tclk-offers')
    rid=c.execute('SELECT raw_record_id FROM raw_network_records').fetchone()[0]
    with patch('scout_projection_source.map_raw',side_effect=ValueError('Authenticated TCLK transition has no authoritative offer root')):
        b=current_bundle(c,rid)
    assert b['message']['text']=='tclk1 {"type":"cancel","ref":"missing"}'
    assert b['facts']['workflow']['identity']['protocol']=='scout-unresolved/v1'
    assert b['facts']['workflow']['terminal'] is None
    assert b['facts']['workflow']['authenticated'] is False
    c.close()


def test_does_not_open_existing_historical_projection(tmp_path):
    work=tmp_path/'work';work.mkdir();historical=work/'projection.sqlite';historical.write_bytes(b'untouched')
    state=tmp_path/'router.json';state.write_text('{}')
    with pytest.raises(ValueError,match='pre-existing projection'):
        generate(tmp_path/'unused',work,tmp_path/'public',state)
    assert historical.read_bytes()==b'untouched'
