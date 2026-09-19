"""Manual-only one-shot bounded-current CONTENT re-anchor; never a scheduler mode."""
import argparse
import hashlib
import json
import tempfile
import shutil
import sqlite3
from pathlib import Path

from scout_projection_contract import require, digest, loads
from scout_projection_publish import PublicationLock, read_artifact, MANIFEST_PATTERN, manifest_revision, validate_database
from scout_current_publication import Source
from scout_current_refresh import refresh


def sqlite_snapshot(source, destination):
    """Create a consistent read-only SQLite backup in isolated work space."""
    src=sqlite3.connect(Path(source).as_uri()+'?mode=ro',uri=True)
    try:
        dst=sqlite3.connect(destination)
        try: src.backup(dst)
        finally: dst.close()
    finally: src.close()


def preflight(source, root, pins, expected_current_publication_id, *, work_parent=None):
    """Read-only readiness check; it never takes the publication lock."""
    root=Path(root);source=Path(source);pins=Path(pins)
    require(all(p.is_absolute() and not p.is_symlink() for p in (source,root,pins)),'Explicit non-symlink paths required')
    require(type(expected_current_publication_id) is int and expected_current_publication_id>0,'Positive expected current publication ID required')
    pointer=json.loads(read_artifact(root,'current.json',limit=16384));require(pointer['schema']=='flop-scout-router-current/v2','Invalid current pointer')
    raw=read_artifact(root,pointer['manifest'],MANIFEST_PATTERN);require(hashlib.sha256(raw).hexdigest()==pointer['manifest_sha256'],'Current manifest corrupted')
    manifest=json.loads(raw);manifest_revision(manifest)
    require(manifest['snapshot_id']==str(expected_current_publication_id),'Expected current publication ID mismatch')
    validate_database(root/manifest['database'],contract_revision=manifest['contract_revision'])
    doc=loads(pins.read_bytes());require(doc['content_sha256']==digest({k:v for k,v in doc.items() if k!='content_sha256'}),'Pin export hash mismatch')
    base=Path(work_parent) if work_parent else root.parent/'private'
    require(base.is_absolute() and base.exists() and not base.is_symlink(),'Explicit existing private work parent required')
    src=Source(source)
    try: cut=src.rows('SELECT coalesce(max(event_id),0) FROM observed_events')[0][0]
    finally: src.close()
    return dict(ready=True,current_publication_id=manifest['snapshot_id'],source_epoch=manifest['source_checkpoint']['epoch'],source_cut=str(cut),pin_sha256=doc['content_sha256'])


def reanchor(source, root, pins, expected_current_publication_id, *, limit=25000, work_parent=None):
    root=Path(root);source=Path(source);pins=Path(pins)
    require(all(p.is_absolute() and not p.is_symlink() for p in (source,root,pins)),'Explicit non-symlink paths required')
    require(type(expected_current_publication_id) is int and expected_current_publication_id>0,'Positive expected current publication ID required')
    with PublicationLock(root):
        pointer=json.loads(read_artifact(root,'current.json',limit=16384));require(pointer['schema']=='flop-scout-router-current/v2','Invalid current pointer')
        raw=read_artifact(root,pointer['manifest'],MANIFEST_PATTERN)
        require(hashlib.sha256(raw).hexdigest()==pointer['manifest_sha256'],'Current manifest corrupted')
        manifest=json.loads(raw);manifest_revision(manifest)
        require(manifest['snapshot_id']==str(expected_current_publication_id),'Expected current publication ID mismatch')
        base=Path(work_parent) if work_parent else root.parent/'private'
        require(base.is_absolute() and base.exists() and not base.is_symlink(),'Explicit existing private work parent required')
        ledger=base/'projection.sqlite.ledger';projection=base/'projection.sqlite'
        require(projection.exists() and ledger.exists(),'Missing live continuity state')
        with __import__('sqlite3').connect(ledger) as conn:
            state=dict(conn.execute("SELECT key,value FROM state WHERE key IN ('content_id','publication_id','published_database_sha256')"))
        require(state.get('content_id')==manifest['database_content_id'] and state.get('publication_id')==manifest['snapshot_id'] and state.get('published_database_sha256')==manifest['sha256'],'Live continuity state does not match accepted content')
        with tempfile.TemporaryDirectory(prefix='.reanchor-',dir=base) as name:
            work=Path(name)
            # SQLite backups are consistent snapshots; never raw-copy live DBs.
            for filename in ('projection.sqlite','projection.sqlite.ledger','current-source.sqlite'):
                sqlite_snapshot(base/filename,work/filename)
            for filename in ('plan.json','pins.json'):
                shutil.copy2(base/filename,work/filename)
            result=refresh(source,work,root,force_content=True,expected_current_id=expected_current_publication_id,publication_locked=True)
            return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--pins',type=Path,required=True)
    parser.add_argument('--expected-current-publication-id',type=int,required=True);parser.add_argument('--limit',type=int,default=25000);parser.add_argument('--work-parent',type=Path)
    parser.add_argument('--preflight',action='store_true',help='read-only readiness validation; performs no capture, rebuild, lock, or publication')
    parser.add_argument('--yes-reanchor-content',action='store_true',help='required acknowledgement for this one-shot manual CONTENT publication')
    args=parser.parse_args()
    if args.preflight:
        print(json.dumps(preflight(args.source,args.root,args.pins,args.expected_current_publication_id,work_parent=args.work_parent),indent=2));return
    if not args.yes_reanchor_content: parser.error('--yes-reanchor-content is required')
    print(json.dumps(reanchor(args.source,args.root,args.pins,args.expected_current_publication_id,limit=args.limit,work_parent=args.work_parent),indent=2))


if __name__=='__main__':main()
