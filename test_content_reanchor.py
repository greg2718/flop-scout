import json
from pathlib import Path

import pytest

import flop_scout as scout
from scout_content_reanchor import reanchor, preflight
from scout_current_publication import generate, LOCAL_DIDS
from scout_projection_contract import ProjectionError
from scout_projection_publish import PublicationLock


def setup(tmp_path):
    source=tmp_path/'observer.sqlite';conn=scout.observer_connect_write(source)
    scout.ingest_messages(conn,'technocore',[dict(seq=1,text='reanchor fixture',**{'from':LOCAL_DIDS[0]})],generation='0',source_endpoint='/r/technocore')
    conn.close();state=tmp_path/'router-state.json';state.write_text('{}');work=tmp_path/'initial';root=tmp_path/'publication'
    generate(source,work,root,state)
    return source,work,root


def pointer(root):
    return (root/'current.json').read_bytes()


def test_reanchor_is_explicit_content_and_wrong_id_fails_without_pointer_change(tmp_path):
    source,work,root=setup(tmp_path);before=pointer(root)
    with pytest.raises(ProjectionError,match='Expected current publication ID mismatch'):
        reanchor(source,root,work/'pins.json',2,work_parent=work)
    assert pointer(root)==before
    result=reanchor(source,root,work/'pins.json',1,work_parent=work)
    current=json.loads(pointer(root));manifest=json.loads((root/current['manifest']).read_text())
    assert manifest['publication_kind']=='CONTENT'
    assert (manifest['snapshot_id'],manifest['database_content_id'])==('2','2')
    assert manifest['sha256'] != json.loads((root/json.loads(before)['manifest']).read_text())['sha256']
    assert all(path.exists() for path in (root/json.loads(before)['manifest'],))


def test_reanchor_respects_normal_publication_lock(tmp_path):
    source,work,root=setup(tmp_path)
    with PublicationLock(root):
        with pytest.raises(ProjectionError,match='Publication/retention already has an owner'):
            reanchor(source,root,work/'pins.json',1,work_parent=work)


def test_reanchor_preflight_is_read_only_and_checks_expected_id(tmp_path):
    source,work,root=setup(tmp_path);before=pointer(root)
    result=preflight(source,root,work/'pins.json',1,work_parent=work)
    assert result['ready'] and result['current_publication_id']=='1'
    assert pointer(root)==before
    with pytest.raises(ProjectionError,match='Expected current publication ID mismatch'):
        preflight(source,root,work/'pins.json',2,work_parent=work)
    assert pointer(root)==before
