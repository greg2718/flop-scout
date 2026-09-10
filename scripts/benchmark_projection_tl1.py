"""Actual signed synthetic source -> TL1 projection benchmark. Explicit temp root."""
import argparse
import json
import resource
import sys
import time
from pathlib import Path
from scripts.projection_tl1_support import add, source, offer, cohort, DID, NOW
from scout_projection_source import map_batch
from scout_projection import initialize, Projector
from scout_projection_contract import TL1_REVISION
from scout_projection_tclk import structural, prepare_holds
from test_scout_projection import apply, empty_pins
from scout_projection_publish import publish


def run(root, count):
    root.mkdir(parents=True, exist_ok=False)
    conn = source(root/'synthetic-source.sqlite')
    source_ids = []
    for n in range(1, 11): source_ids.append(add(conn, n=n, obj=offer(n)))
    receipt_count = round(count*132/2505)
    for n in range(11, count+11):
        kwargs = dict(obj=dict(type='receipt', **{'from':DID}, outcome='claimed')) if n-11 >= count-receipt_count else {}
        source_ids.append(add(conn, n=n, **kwargs))
    mapped = []; started = time.perf_counter()
    for start in range(0, len(source_ids), 200): mapped.extend(map_batch(conn, source_ids[start:start+200], [DID], TL1_REVISION))
    map_seconds = time.perf_counter()-started
    conn.close()
    enrollment, members = cohort(mapped)
    path = root/'work'/'projection.sqlite'
    initialize(path, epoch='source-epoch', router_source_id='router', router_epoch='router-epoch', router_did=DID,
               local_dids=[DID], contract_revision=TL1_REVISION, legacy_tclk_cohort=enrollment, legacy_tclk_raw_ids=members)
    started = time.perf_counter()
    for bundle in mapped: structural(bundle['message']['text'])
    classify_seconds = time.perf_counter()-started
    with Projector(path) as owner:
        started = time.perf_counter(); apply(owner, mapped); enroll_seconds = time.perf_counter()-started
        started = time.perf_counter(); prepare_holds(owner); hold_seconds = time.perf_counter()-started
        details = json.loads(owner.get('tl1_status'))
        table_bytes = owner.conn.execute("SELECT sum(pgsize) FROM dbstat('projection') WHERE name='legacy_tclk_records'").fetchone()[0]
        empty_pins(owner)
        result = publish(owner, root/'public', checked_cut=owner.status()['source_cut'], evaluated_at=NOW)
    return dict(enrolled=count, synthetic_accepts=count-receipt_count, synthetic_receipts=receipt_count, table_bytes=table_bytes, bytes_per_record=table_bytes/count, audit_hint_storage_bytes=0,
                classification_seconds=classify_seconds, classification_records_per_second=len(mapped)/classify_seconds,
                source_mapping_seconds=map_seconds, enrollment_seconds=enroll_seconds, enrollment_records_per_second=count/enroll_seconds,
                hold_seconds=hold_seconds, peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*(1 if sys.platform=='darwin' else 1024),
                dependency_amplification=details['held_message_count']/count, diagnostics=details,
                manifest=result['pointer']['manifest'], database=result['manifest']['database'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--count', type=int, choices=(2505,4096), required=True)
    args = parser.parse_args()
    assert args.root.is_absolute() and '/private/tmp/' in str(args.root)
    result = run(args.root, args.count)
    (args.root/'measurement.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
