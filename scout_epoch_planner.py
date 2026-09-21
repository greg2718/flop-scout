"""Pure advisory V2 active-epoch planner; it never builds or mutates artifacts."""
import hashlib
import json

HARD_MAX = 50000

class PlanError(ValueError):
    def __init__(self, code, message): self.code=code; super().__init__(message)

def fail(code, message): raise PlanError(code, message)
def canon(value): return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
def digest(value): return hashlib.sha256(b'flop-scout/epoch-plan/v1\0'+canon(value)).hexdigest()

RECORD_FIELDS=frozenset(('record_id','content_sha256','source_position','room','generation','domain','observation_class','recency','mandatory_reasons','dependencies','archive_required','retained_floor'))
POLICY_FIELDS=frozenset(('target','headroom','reserve','hard_max','selection_policy_version','source_cut','predecessor_epoch_id','archive_commitment','prior_floors'))

def _record(item):
    if type(item) is not dict or set(item)!=RECORD_FIELDS: fail('PLAN_RECORD_FIELDS','invalid normalized record')
    for key in ('record_id','content_sha256','room','generation','domain','observation_class'):
        if type(item[key]) is not str or not item[key] or any(ord(c)>127 for c in item[key]): fail('PLAN_RECORD_TYPE','invalid normalized string')
    if type(item['source_position']) is not int or item['source_position']<0 or type(item['recency']) is not int: fail('PLAN_SOURCE_POSITION','invalid source position')
    if type(item['mandatory_reasons']) is not list or item['mandatory_reasons']!=sorted(set(item['mandatory_reasons'])): fail('PLAN_REASON_ORDER','mandatory reasons must be sorted unique')
    if type(item['dependencies']) is not list or item['dependencies']!=sorted(set(item['dependencies'])): fail('PLAN_DEPENDENCY_ORDER','dependencies must be sorted unique')
    if type(item['archive_required']) is not bool or item['retained_floor'] is not None and (type(item['retained_floor']) is not int or item['retained_floor']<0): fail('PLAN_RECORD_TYPE','invalid normalized record')

def plan(records, policy):
    """Return a deterministic advisory plan or raise a stable fail-closed error."""
    if type(records) is not list or type(policy) is not dict or set(policy)!=POLICY_FIELDS: fail('PLAN_INPUT','invalid planner input')
    if len(records)>HARD_MAX*2: fail('PLAN_INPUT_BOUNDS','too many records')
    for item in records: _record(item)
    by_id={item['record_id']:item for item in records}
    if len(by_id)!=len(records): fail('PLAN_DUPLICATE_ID','duplicate record id')
    positions={}
    for item in records:
        if item['source_position'] in positions and positions[item['source_position']]!=item['record_id']: fail('PLAN_SOURCE_POSITION','conflicting source position')
        positions[item['source_position']]=item['record_id']
    target,headroom,reserve,hard=(policy[k] for k in ('target','headroom','reserve','hard_max'))
    if any(type(x) is not int for x in (target,headroom,reserve,hard)) or hard!=HARD_MAX or target<1 or headroom<1 or reserve<0 or target+headroom+reserve>hard: fail('PLAN_CAPACITY','invalid target/headroom/reserve arithmetic')
    if not isinstance(policy['archive_commitment'],str) or not policy['archive_commitment']: fail('PLAN_ARCHIVE_BINDING','archive commitment is required')
    mandatory=set(); reasons={}
    for item in records:
        if item['mandatory_reasons']:
            mandatory.add(item['record_id']); reasons[item['record_id']]=list(item['mandatory_reasons'])
    queue=sorted(mandatory)
    while queue:
        item=by_id[queue.pop(0)]
        for dep in item['dependencies']:
            if dep not in by_id: fail('PLAN_DEPENDENCY_MISSING','mandatory dependency is unavailable')
            if dep not in mandatory:
                mandatory.add(dep); reasons.setdefault(dep,['DEPENDENCY']); queue.append(dep)
    if len(mandatory)>target: fail('PLAN_MANDATORY_CAPACITY','mandatory closure exceeds target')
    prior=policy['prior_floors']
    if type(prior) is not dict: fail('PLAN_FLOOR','invalid prior floors')
    floors={}
    for item in records:
        key='|'.join((item['room'],item['generation'],item['domain']))
        if item['retained_floor'] is not None: floors[key]=max(floors.get(key,-1),item['retained_floor'])
    for key,value in prior.items():
        if type(key) is not str or type(value) is not int or floors.get(key,value)<value: fail('PLAN_FLOOR_REGRESSION','retained floor regressed')
    optional=[r for r in records if r['record_id'] not in mandatory]
    optional.sort(key=lambda r:(-r['recency'],r['observation_class'],r['room'],r['generation'],r['domain'],r['record_id']))
    selected=set(mandatory); remaining=target-len(selected)
    # First preserve one optional representative per domain, then stable recency.
    seen=set()
    for item in optional:
        key=(item['room'],item['generation'],item['domain'])
        if remaining and key not in seen: selected.add(item['record_id']);seen.add(key);remaining-=1
    for item in optional:
        if remaining and item['record_id'] not in selected: selected.add(item['record_id']);remaining-=1
    omitted=sorted(set(by_id)-selected)
    if any(by_id[item]['archive_required'] for item in omitted) and not policy['archive_commitment']: fail('PLAN_ARCHIVE_BINDING','archive binding is required for omission')
    chosen=sorted(selected,key=lambda i:(by_id[i]['source_position'],i))
    optional_ids=sorted(selected-mandatory,key=lambda i:(by_id[i]['source_position'],i))
    counts={}
    for item in chosen:
        record=by_id[item]; key=record['domain']; counts[key]=counts.get(key,0)+1
    output={'selection_policy_version':policy['selection_policy_version'],'source_cut':policy['source_cut'],'predecessor_epoch_id':policy['predecessor_epoch_id'],'archive_commitment':policy['archive_commitment'],'mandatory_record_ids':sorted(mandatory),'optional_record_ids':optional_ids,'selected_record_ids':chosen,'omitted_record_ids':omitted,'mandatory_reasons':{k:reasons[k] for k in sorted(reasons)},'counts_by_domain':counts,'retained_floor_proposal':floors,'capacity':{'target':target,'headroom':headroom,'reserve':reserve,'hard_max':hard,'mandatory_count':len(mandatory),'selected_count':len(chosen),'trigger':hard-headroom-reserve}}
    output['plan_sha256']=digest(output)
    return output
