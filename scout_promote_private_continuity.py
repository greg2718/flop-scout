"""Manual-only promotion of verified private continuity metadata."""
import argparse, hashlib, json, os, sqlite3
from datetime import datetime, timezone
from pathlib import Path

from scout_projection_contract import ProjectionError, require
from scout_projection_publish import PublicationLock, read_artifact, MANIFEST_PATTERN, manifest_revision, validate_database, atomic_json, fsync_directory

STATE_KEYS=('content_id','publication_id','published_database_sha256','source_cut')
TABLES=(('durable_qualifications','qualification_id','record_json'),('qualification_events','event_id','event_json'),('messages','projection_row_id','room,generation,seq,timestamp,sender,text,nonce,sig'),('source_provenance','projection_row_id','entity_type,source_namespace,source_record_locator,raw_record_id,annotations_json'),('selection_membership','entity_type||"|"||projection_row_id','retention_class,first_observed_at,retain_until,pin_roots_json'),('watermarks','room||"|"||generation','record_count,min_seq,max_seq'),('coverage_history','room||"|"||generation','max_ever_projected_seq,witness_source_locator,witness_record_sha256'))

def digest_rows(path,table,key,columns):
    with sqlite3.connect(path) as c:
        return {r[0]:hashlib.sha256('|'.join('' if v is None else str(v) for v in r[1:]).encode()).hexdigest() for r in c.execute('SELECT '+key+','+columns+' FROM '+table)}


def _state(ledger):
    with sqlite3.connect(ledger) as conn:
        return dict(conn.execute('SELECT key,value FROM state WHERE key IN ('+','.join('?'*len(STATE_KEYS))+')',STATE_KEYS))


def _verify_private(projection, revision):
    """Run the normal private ledger/provenance verification before recovery."""
    validate_database(projection,contract_revision=revision)
    from scout_projection import Projector
    with Projector(projection):
        pass


def _marker(marker):
    require(marker.is_file() and not marker.is_symlink(),'Unsafe private continuity recovery marker')
    try: value=json.loads(marker.read_text())
    except (OSError,json.JSONDecodeError) as exc: raise ProjectionError('Invalid private continuity recovery marker') from exc
    require(type(value) is dict and value.get('schema')=='scout-private-continuity-promotion/v1' and value.get('phase')=='PREPARED','Invalid private continuity recovery marker')
    return value


def _clear_marker(marker):
    marker.unlink()
    fsync_directory(marker.parent)

def promote(root,private,publication_id,content_id,database_sha256,*,fail=None):
    root=Path(root);private=Path(private);marker=private/'private-continuity-promotion.json'
    require(all(p.is_absolute() and not p.is_symlink() for p in (root,private)),'Explicit non-symlink paths required')
    with PublicationLock(root):
        pointer=json.loads(read_artifact(root,'current.json',limit=16384));raw=read_artifact(root,pointer['manifest'],MANIFEST_PATTERN)
        require(hashlib.sha256(raw).hexdigest()==pointer['manifest_sha256'],'Current manifest corrupted');m=json.loads(raw);manifest_revision(m)
        require((m['snapshot_id'],m['database_content_id'],m['sha256'],m['publication_kind'])==(str(publication_id),str(content_id),database_sha256,'CONTENT'),'Expected publication binding mismatch')
        validate_database(root/m['database'],contract_revision=m['contract_revision'])
        projection=private/'projection.sqlite';ledger=private/'projection.sqlite.ledger'
        before={name:digest_rows(projection,*spec) for name,spec in zip('dq qe msg prov sel water cov'.split(),TABLES)}
        published={name:digest_rows(root/m['database'],*spec) for name,spec in zip('dq qe msg prov sel water cov'.split(),TABLES)}
        require(before==published,'Private substantive state differs from publication')
        state=_state(ledger)
        target=dict(publication_id=str(publication_id),content_id=str(content_id),published_database_sha256=database_sha256)
        # A marker is durable evidence of an interrupted operation.  It must be
        # assessed before the ordinary idempotency path, never ignored.
        if marker.exists() or marker.is_symlink():
            recovery=_marker(marker)
            require(recovery.get('target')==target and recovery.get('pointer')==pointer,'Private continuity recovery binding mismatch')
            old=recovery.get('old')
            require(type(old) is dict and set(old)==set(STATE_KEYS),'Invalid private continuity recovery old state')
            with sqlite3.connect(projection) as conn:
                meta=conn.execute('SELECT database_content_id FROM snapshot_meta').fetchone()[0]
            if all(state.get(k)==v for k,v in target.items()) and meta==target['content_id']:
                _verify_private(projection,m['contract_revision'])
                _clear_marker(marker);return 'RECOVERED_PROMOTION'
            if state==old and meta==old['content_id']:
                _verify_private(projection,m['contract_revision'])
                _clear_marker(marker);return 'RECOVERED_NOOP'
            raise ProjectionError('Private continuity recovery state is partial or inconsistent')
        if all(state.get(k)==v for k,v in target.items()):
            with sqlite3.connect(projection) as c: meta=c.execute('SELECT database_content_id FROM snapshot_meta').fetchone()[0]
            require(meta==str(content_id),'Idempotent promotion has inconsistent projection metadata');return 'ALREADY_PROMOTED'
        atomic_json(private,marker.name,dict(schema='scout-private-continuity-promotion/v1',old=state,target=target,pointer=pointer,created_at=datetime.now(timezone.utc).isoformat(),phase='PREPARED'))
        if fail: fail('before_mutation')
        with sqlite3.connect(projection) as c:c.execute('UPDATE snapshot_meta SET database_content_id=? WHERE singleton=1',(str(content_id),));c.commit()
        if fail: fail('after_projection')
        with sqlite3.connect(ledger) as c:
            for k,v in target.items():c.execute('UPDATE state SET value=? WHERE key=?',(v,k))
            c.commit()
        if fail: fail('after_ledger')
        require(before=={name:digest_rows(projection,*spec) for name,spec in zip('dq qe msg prov sel water cov'.split(),TABLES)},'Promotion changed substantive state')
        validate_database(projection,contract_revision=m['contract_revision'])
        _clear_marker(marker);return 'PROMOTED'

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--private',type=Path,required=True);p.add_argument('--expected-publication-id',type=int,required=True);p.add_argument('--expected-content-id',type=int,required=True);p.add_argument('--expected-database-sha256',required=True);p.add_argument('--yes-promote-private-continuity',action='store_true');a=p.parse_args()
    if not a.yes_promote_private_continuity:p.error('--yes-promote-private-continuity is required')
    print(promote(a.root,a.private,a.expected_publication_id,a.expected_content_id,a.expected_database_sha256))
if __name__=='__main__':main()
