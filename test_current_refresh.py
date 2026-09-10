import json
import sqlite3
from datetime import timedelta
import pytest
import flop_scout as scout
from scout_current_publication import generate,LOCAL_DIDS
from scout_current_refresh import refresh,manifest
from scout_projection_contract import utc,instant


def setup(tmp_path):
    source=tmp_path/'observer.sqlite'
    c=scout.observer_connect_write(source)
    scout.ingest_messages(c,'technocore',[{'seq':1,'from':LOCAL_DIDS[0],'text':'hello initial'}],generation='g1',source_endpoint='/r/technocore')
    c.close()
    state=tmp_path/'router.json';state.write_text('{}')
    work=tmp_path/'work';root=tmp_path/'public'
    generate(source,work,root,state)
    return source,work,root


def add(source,seq):
    c=scout.observer_connect_write(source)
    scout.ingest_messages(c,'technocore',[{'seq':seq,'from':LOCAL_DIDS[0],'text':'hello refresh '+str(seq)}],generation='g1',source_endpoint='/r/technocore')
    c.close()


def test_refresh_advances_capture_and_preserves_continuity(tmp_path):
    source,work,root=setup(tmp_path);old=manifest(root);add(source,2)
    result=refresh(source,work,root,now=utc(instant(old['produced_at'])+timedelta(seconds=1)))
    new=manifest(root)
    assert result['new_publication_id']=='2' and result['admitted_records']==1
    assert new['source_checkpoint']['epoch']==old['source_checkpoint']['epoch']
    assert int(new['source_checkpoint']['committed_event_id'])>int(old['source_checkpoint']['committed_event_id'])
    assert instant(result['new_expiry'])>instant(result['old_expiry'])
    assert new['row_counts']['messages']==2
    assert not (work/'refresh-pending.json').exists()


def test_crash_after_apply_replays_without_duplicate_publication(tmp_path):
    source,work,root=setup(tmp_path);old=manifest(root);add(source,2)
    when=utc(instant(old['produced_at'])+timedelta(seconds=1))
    def crash(_):raise RuntimeError('simulated crash')
    with pytest.raises(RuntimeError,match='simulated crash'):refresh(source,work,root,now=when,fail=crash)
    assert manifest(root)==old
    result=refresh(source,work,root,now=when)
    assert result['new_publication_id']=='2' and manifest(root)['row_counts']['messages']==2


def test_capacity_does_not_launder_freshness(tmp_path,monkeypatch):
    import scout_current_refresh as module
    source,work,root=setup(tmp_path);old=(root/'current.json').read_bytes();add(source,2)
    monkeypatch.setattr(module,'MAX_ENROLLED',1)
    with pytest.raises(ValueError,match='capacity reached'):refresh(source,work,root)
    assert (root/'current.json').read_bytes()==old


def test_pre_capture_timestamp_corrected_before_staging(tmp_path):
    source,work,root=setup(tmp_path);old=manifest(root);add(source,2)
    result=refresh(source,work,root,now=old['produced_at'])
    assert result['new_publication_id']=='2'
    assert manifest(root)['row_counts']['messages']==2


def test_empty_failed_staging_recovers_without_rewriting_event(tmp_path):
    from scout_projection import Projector
    from scout_current_publication import Source,copy_records,atomic
    source,work,root=setup(tmp_path);old=manifest(root);add(source,2)
    src=Source(source)
    event=src.rows('SELECT event_id,raw_record_id FROM observed_events ORDER BY event_id DESC LIMIT 1')[0]
    local=sqlite3.connect(work/'current-source.sqlite');local.row_factory=sqlite3.Row
    kept,excluded,size=copy_records(src,local,[event['raw_record_id']],event['event_id'])
    local.close();src.close()
    pending=dict(cut=str(event['event_id']),when=old['produced_at'],raw_ids=kept,excluded=excluded,bytes=size,
                 previous_id=old['snapshot_id'],previous_cut=old['source_checkpoint']['committed_event_id'])
    atomic(work/'refresh-pending.json',pending)
    with Projector(work/'projection.sqlite') as p:
        number=p.begin(pending['cut'],pending['when'],'SOURCE_BATCH')
        original=json.loads(p.conn.execute('SELECT body FROM evaluations WHERE number=?',(number,)).fetchone()[0])
    assert refresh(source,work,root)['new_publication_id']=='2'
    with Projector(work/'projection.sqlite') as p:
        row=p.conn.execute('SELECT body,status FROM evaluations WHERE number=?',(number,)).fetchone()
        assert row['status']=='COMPLETE'
        sealed=json.loads(row['body'])
        assert all(sealed[key]==value for key,value in original.items())
    assert manifest(root)['row_counts']['messages']==2


def test_stale_capture_keeps_pointer_then_allows_new_capture(tmp_path,monkeypatch):
    import scout_current_refresh as module
    from datetime import datetime,timezone
    source,work,root=setup(tmp_path);old=manifest(root);add(source,2)
    clock=datetime.now(timezone.utc)
    class Later(datetime):
        @classmethod
        def now(cls,tz=None):return clock+timedelta(seconds=601)
    with monkeypatch.context() as patch:
        patch.setattr(module,'datetime',Later)
        with pytest.raises(ValueError,match='capture exceeded'):
            refresh(source,work,root,now=utc(clock))
    assert manifest(root)==old and not (work/'refresh-pending.json').exists()
    assert refresh(source,work,root)['new_publication_id']=='2'


def test_crash_after_publication_does_not_issue_another_id(tmp_path,monkeypatch):
    import scout_current_refresh as module
    source,work,root=setup(tmp_path);add(source,2)
    original=module.atomic
    def interrupted(path,value):
        if path.name=='refresh-status.json':raise RuntimeError('status crash')
        return original(path,value)
    with monkeypatch.context() as patch:
        patch.setattr(module,'atomic',interrupted)
        with pytest.raises(RuntimeError,match='status crash'):refresh(source,work,root)
    assert manifest(root)['snapshot_id']=='2'
    assert refresh(source,work,root)['new_publication_id']=='2'
    assert not (work/'refresh-pending.json').exists()
