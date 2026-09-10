"""Physical public-row capacity stress, independent of source throughput fixtures.

Uses synthetic row replication and normalized-text padding to exercise the exact
canonical byte accounting boundary. It is not a production-shaped source sample.
"""
import argparse
import hashlib
import json
import shutil
import sqlite3
import time
from pathlib import Path
from scout_projection_contract import connect, ProjectionError
from scout_projection_tclk import validate_public


def run(root, manifest_path):
    root.mkdir(parents=True, exist_ok=False)
    manifest = json.loads(manifest_path.read_text())
    target = root/'capacity.sqlite'
    shutil.copyfile(manifest_path.parent/manifest['database'], target)
    conn = connect(target)
    # Benchmark source has ten independently signed valid offers plus enrolled
    # records. Replicas retain a real signed body but have synthetic raw locators.
    original = conn.execute("SELECT m.* FROM messages m LEFT JOIN legacy_tclk_records l ON l.message_id=m.projection_row_id WHERE l.raw_ref IS NULL LIMIT 1").fetchone()
    assert original is not None
    provenance = conn.execute("SELECT * FROM source_provenance WHERE entity_type='message' AND projection_row_id=?", (original['projection_row_id'],)).fetchone()
    membership = conn.execute("SELECT * FROM selection_membership WHERE entity_type='message' AND projection_row_id=?", (original['projection_row_id'],)).fetchone()
    initial = conn.execute('SELECT count(*) FROM messages').fetchone()[0]
    def insert(number):
        rid = hashlib.sha256(('capacity-replica-'+str(number)).encode()).hexdigest()
        message = dict(original); message.update(projection_row_id='sm1:'+rid, seq=1000000+number, evidence_id=None)
        proof = dict(provenance); proof.update(projection_row_id='sm1:'+rid, raw_record_id=rid, source_record_locator=rid, scout_event_id=str(1000000+number))
        member = dict(membership); member['projection_row_id']='sm1:'+rid
        for name, row in [('messages',message),('source_provenance',proof),('selection_membership',member)]:
            conn.execute('INSERT INTO '+name+'('+','.join(row)+') VALUES('+','.join('?' for _ in row)+')', tuple(row.values()))
        return 'sm1:'+rid
    for number in range(initial, 99999):
        insert(number)
        if number % 1000 == 0: conn.commit()
    conn.commit()
    checkpoint = manifest['source_checkpoint']; results = []
    def check(label, reject=False):
        started=time.perf_counter()
        try:
            result=validate_public(conn,manifest['legacy_tclk_cohort'],checkpoint['source_id'],checkpoint['epoch'],checkpoint['committed_event_id'])
            assert not reject, label+' unexpectedly passed'
            results.append(dict(case=label,valid=True,held_messages=result['held_message_count'],bytes=result['dependency_bytes'],seconds=time.perf_counter()-started))
            print(json.dumps(results[-1]), flush=True)
            return result
        except ProjectionError as exc:
            if not reject: raise
            results.append(dict(case=label,valid=False,error=str(exc),seconds=time.perf_counter()-started))
            print(json.dumps(results[-1]), flush=True)
    check('99999 messages')
    insert(99999);conn.commit();baseline=check('100000 messages')
    excess=insert(100000);conn.commit();check('100001 messages',True)
    with conn:
        conn.execute('DELETE FROM messages WHERE projection_row_id=?',(excess,))
        for name in ('source_provenance','selection_membership'):conn.execute('DELETE FROM '+name+" WHERE entity_type='message' AND projection_row_id=?",(excess,))
    assert conn.execute('SELECT count(*) FROM messages WHERE normalized_text IS NOT NULL').fetchone()[0] == 0
    remaining=268435455-baseline['dependency_bytes']
    assert remaining > 0
    padding=remaining//100000+2
    with conn:conn.execute('UPDATE messages SET normalized_text=?',('x'*padding,))
    leftover=remaining-100000*(padding-2)
    with conn:conn.execute('UPDATE messages SET normalized_text=normalized_text||? WHERE projection_row_id=?',('x'*leftover,original['projection_row_id']))
    below=check('268435455 bytes');assert below['dependency_bytes']==268435455
    with conn:conn.execute("UPDATE messages SET normalized_text=normalized_text||'x' WHERE projection_row_id=?",(original['projection_row_id'],))
    equal=check('268435456 bytes');assert equal['dependency_bytes']==268435456
    with conn:conn.execute("UPDATE messages SET normalized_text=normalized_text||'x' WHERE projection_row_id=?",(original['projection_row_id'],))
    check('268435457 bytes',True)
    conn.close()
    (root/'results.json').write_text(json.dumps(results,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--manifest',type=Path,required=True)
    args=parser.parse_args();assert str(args.root).startswith('/private/tmp/') and str(args.manifest).startswith('/private/tmp/')
    run(args.root,args.manifest)
