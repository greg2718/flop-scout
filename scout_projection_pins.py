"""Cumulative local Router pin imports. No Router database or remote access."""
from scout_projection_contract import *

EXPORT_KEYS = set('schema source_id epoch revision produced_at previous_sha256 pins content_sha256'.split())
PIN_KEYS = set('schema pin_id created_at producer router_did reason root decision_id task_hash retention_mode operator_group evidence_refs dependency_refs content_sha256'.split())
LOCAL_KINDS = {'RAW_RECORD','SCOUT_EVENT','MESSAGE','EVIDENCE_RECORD','INTERACTION','WORKFLOW'}


def validate_pin(pin, config):
    keys(pin, PIN_KEYS)
    require(pin['schema']=='flop-router-projection-pin/v1' and pin['producer']=='FLOP_ROUTER' and pin['reason']=='RETAIN_EVIDENCE' and pin['retention_mode']=='PERMANENT' and pin['operator_group']==FAMILY,'Unsupported pin contract')
    require(pin['router_did']==config['router_did'],'Unexpected Router public DID')
    instant(pin['created_at']); roots([pin['root']]); string(pin['decision_id'],True); sha(pin['task_hash'],True)
    if pin['root']['kind']=='ROUTING_DECISION':require(pin['decision_id']==pin['root']['id'],'Pin decision mismatch')
    if pin['root']['kind']=='TASK':require(pin['task_hash']==pin['root']['id'],'Pin task hash mismatch')
    for field in ('evidence_refs','dependency_refs'):
        refs=pin[field]
        require(type(refs) is list and len(refs)<=256 and (refs or field=='dependency_refs'),'Invalid pin references')
        require([canonical(r) for r in refs]==sorted(set(canonical(r) for r in refs)),'Pin references must be sorted and unique')
        for ref in refs:
            reference(ref,LOCAL_KINDS|({'EXTERNAL'} if field=='dependency_refs' else set()),True)
            if ref['kind']=='EXTERNAL':require(ref['source_id']!=config['source_id'],'Local evidence cannot masquerade as external')
            else:require((ref['source_id'],ref['source_epoch'])==(config['source_id'],config['epoch']),'Pin local namespace mismatch')
    expected=identity('rp1',{k:pin[k] for k in ('schema','producer','router_did','root','evidence_refs','dependency_refs')})
    require(pin['pin_id']==expected and pin['content_sha256']==digest({k:v for k,v in pin.items() if k!='content_sha256'}),'Pin hash mismatch')


def resolve(projector, ref):
    conn=projector.conn; kind=ref['kind']; identifier=ref['id']; found=[]; expected=None
    if kind=='EXTERNAL':
        if ref['sha256'] is not None:
            row=conn.execute('SELECT * FROM local_artifacts WHERE id=? AND source_id=? AND epoch=?',(identifier,ref['source_id'],ref['source_epoch'])).fetchone()
            require(row and row['hash']==ref['sha256'] and hashlib.sha256(row['body']).hexdigest()==ref['sha256'],'Unverifiable external artifact hash')
        return []
    if kind=='MESSAGE':
        b=projector.bundle(identifier);found=[identifier];expected=text_hash(b['message']['text'])
    elif kind in {'RAW_RECORD','SCOUT_EVENT','EVIDENCE_RECORD'}:
        # Aliases are resolved against immutable source bundles, not cache rowids.
        # Indexed source aliases are added at ingestion; old deployments cannot guess.
        if kind=='RAW_RECORD':
            b=projector.bundle('sm1:'+identifier);found=['sm1:'+identifier];expected=b['provenance']['raw_record_sha256']
        else:
            for row in conn.execute('SELECT id FROM source_aliases WHERE kind=? AND alias=? ORDER BY id',(kind,identifier)):
                b=projector.bundle(row[0]);value=b['provenance']['scout_event_id'] if kind=='SCOUT_EVENT' else b['message']['evidence_id']
                found.append(row[0]);expected=None if kind=='SCOUT_EVENT' else b['message']['message_hash']
            require(len(found)==1,'Missing or ambiguous pin alias')
    elif kind=='WORKFLOW':
        row=conn.execute('SELECT identity_json FROM workflows WHERE id=?',(identifier,)).fetchone()
        require(row,'Missing pinned workflow');found=[identifier];expected=digest(loads(row[0]))
    elif kind=='INTERACTION':
        row=conn.execute('SELECT value FROM state WHERE key=?',('interaction:'+identifier,)).fetchone()
        require(row,'Missing pinned interaction');found=[identifier];expected=digest(loads(row[0]))
    require(found,'Missing pin target')
    if ref['sha256'] is not None:require(expected is not None and ref['sha256']==expected,'Unsupported or conflicting pin hash basis')
    return found


def _import_pins(projector, raw, now=None):
    projector.check(); require(not projector.conn.execute("SELECT 1 FROM evaluations WHERE status!='COMPLETE'").fetchone(),'Pin import requires a completed source cut'); doc=loads(raw);keys(doc,EXPORT_KEYS);config=projector.config
    require(doc['schema']=='flop-router-projection-pins/v1','Unsupported pin export')
    require((doc['source_id'],doc['epoch'])==(config['router_source_id'],config['router_epoch']),'Pin export namespace changed')
    revision=int(decimal(doc['revision']));produced=instant(doc['produced_at']);now=instant(now or utc())
    require(produced<=now+timedelta(seconds=60),'Future pin export')
    require(doc['content_sha256']==digest({k:v for k,v in doc.items() if k!='content_sha256'}),'Pin export hash mismatch')
    require(not projector.get('pending_pin_sha256') or projector.get('pending_pin_sha256')==doc['content_sha256'],'Resume the interrupted pin export before another revision')
    pins=doc['pins'];require(type(pins) is list and len(pins)<=10000,'Pin export capacity exceeded')
    require([p['pin_id'] for p in pins]==sorted(set(p['pin_id'] for p in pins)),'Unsorted pins')
    for pin in pins:
        validate_pin(pin,config)
        require(instant(pin['created_at'])<=produced,'Pin created after export')
    previous=projector.conn.execute('SELECT * FROM pin_exports ORDER BY revision DESC LIMIT 1').fetchone()
    if previous and revision==previous['revision']:
        require(previous['hash']==doc['content_sha256'],'Conflicting repeated pin revision');return {'revision':revision,'idempotent':True}
    require(revision==(previous['revision']+1 if previous else 0),'Pin revision gap/regression')
    require(doc['previous_sha256']==(previous['hash'] if previous else None),'Pin predecessor mismatch')
    if previous:require(produced>=instant(loads(previous['body'])['produced_at']),'Regressed pin time')
    old={r['id']:r['body'] for r in projector.conn.execute('SELECT * FROM pins')}
    new={p['pin_id']:canonical(p).decode() for p in pins}
    require(all(new.get(k)==v for k,v in old.items()),'Pin removal or immutable pin conflict')
    # Resolve all local dependencies before accepting any change. Failures retain
    # previous accepted pins and persist a readiness blocker for subsequent publish.
    try:
        resolved=[]
        for pin in pins:
            starts=[]
            for ref in pin['evidence_refs']+pin['dependency_refs']:starts.extend(resolve(projector,ref))
            resolved.append((pin,projector.closure(starts)))
    except ProjectionError as exc:
        with projector.conn:projector.set('pin_error',str(exc))
        raise
    with projector.conn:
        projector.set('pending_pin_sha256',doc['content_sha256']);projector.set('pin_error','Pin import incomplete; resume the same export')
    for pin,members in resolved:
        with projector.conn:projector.conn.execute('INSERT OR IGNORE INTO pins VALUES(?,?)',(pin['pin_id'],canonical(pin).decode()))
        for start in range(0,len(members),200):
            projector.check()
            with projector.conn:
                for rid in members[start:start+200]:
                    projector.conn.execute('INSERT OR IGNORE INTO pin_members VALUES(?,?)',(rid,canonical(pin['root']).decode()))
                    projector.apply_pin_member(rid,projector.get('evaluated_at') or utc())
    with projector.conn:
        projector.conn.execute('INSERT INTO pin_exports VALUES(?,?,?)',(revision,doc['content_sha256'],canonical(doc).decode()))
        projector.set('pending_pin_sha256','');projector.set('pin_error','')
        projector.record_operation('PIN',dict(revision=revision))
    return {'revision':revision,'pins':len(pins),'members':sum(len(m) for _,m in resolved)}


def refresh_pins(projector,number):
    """New explicit workflow/dependency members inherit already accepted roots."""
    for row in projector.conn.execute('SELECT body FROM pins ORDER BY id'):
        pin=loads(row[0]);starts=[]
        for ref in pin['evidence_refs']+pin['dependency_refs']:starts.extend(resolve(projector,ref))
        members=projector.closure(starts)
        for start in range(0,len(members),200):
            projector.check()
            with projector.conn:
                for rid in members[start:start+200]:
                    projector.conn.execute('INSERT OR IGNORE INTO pin_members VALUES(?,?)',(rid,canonical(pin['root']).decode()))
                    projector.conn.execute('INSERT OR IGNORE INTO evaluation_groups SELECT ?,sender FROM current_inputs WHERE id=?',(number,rid))
                    projector.conn.execute('INSERT OR IGNORE INTO evaluation_groups SELECT ?,peer.sender FROM current_inputs c JOIN current_inputs peer ON peer.template=c.template WHERE c.id=?',(number,rid))
                    projector.apply_pin_member(rid,projector.get('evaluated_at') or utc())


def import_pins(projector,raw,now=None,evaluate=True):
    try:
        result=_import_pins(projector,raw,now)
        if evaluate and not result.get('idempotent') and projector.get('source_cut'):
            cut=loads(projector.get('source_cut'));when=utc(max(instant(now or utc()),instant(projector.get('evaluated_at'))))
            number=projector.begin(cut['committed_event_id'],when,'SOURCE_BATCH')
            with projector.conn:
                projector.conn.execute('INSERT OR IGNORE INTO evaluation_groups SELECT ?,c.sender FROM pin_members p JOIN current_inputs c ON c.id=p.id',(number,))
                projector.conn.execute('INSERT OR IGNORE INTO evaluation_groups SELECT ?,peer.sender FROM pin_members p JOIN current_inputs c ON c.id=p.id JOIN current_inputs peer ON peer.template=c.template',(number,))
            projector.seal(number)
        return result
    except Exception as exc:
        with projector.conn:projector.set('pin_error',str(exc))
        raise
