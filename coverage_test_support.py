"""Local synthetic fixtures; never use production state or make network requests."""
import json
from pathlib import Path
import scout_coverage as coverage


def messages(first,last):
    return [{'seq':i,'from':'fixture','text':f'fixture {i}'} for i in range(first,last+1)]


def tail(records, since=0, limit=200, generation='g1'):
    selected=[r for r in records if r['seq']>since][-min(200,max(1,limit)):]
    return {'room':'technocore','count':len(selected),'first_seq':selected[0]['seq'] if selected else None,
        'last_seq':selected[-1]['seq'] if selected else since,'generation':generation,'messages':selected}


def export_snapshot(directory, records, room='technocore', generation='g1', **metadata):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    path=directory/'fixture-export.jsonl'
    path.write_bytes(b''.join(json.dumps(r,ensure_ascii=True).encode()+b'\n' for r in records))
    endpoint=f'https://technocore.chat/r/{room}/export'
    meta={'headers':{'X-Room-Generation':generation},'complete':True,**metadata}
    snapshot=coverage.inspect_export(path,room,generation,endpoint,endpoint,meta)
    destination=directory/(snapshot['snapshot_id']+'.jsonl')
    path.replace(destination);snapshot['path']=str(destination)
    return snapshot
