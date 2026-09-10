#!/usr/bin/env python3
"""Isolate exact locator operations on existing synthetic source rows only."""
import argparse
import json
import sqlite3
import sys
import timeit
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scout_projection_contract import canonical, digest, string


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert args.source.resolve().is_relative_to(Path('/private/tmp'))
    assert args.output.resolve().is_relative_to(Path('/private/tmp')) and not args.output.exists()
    result = {}
    with sqlite3.connect(args.source.resolve().as_uri()+'?mode=ro', uri=True) as conn:
        conn.row_factory = sqlite3.Row
        for table in ('evidence_records', 'kibble_events'):
            record = dict(conn.execute('SELECT * FROM '+table+' ORDER BY rowid LIMIT 1').fetchone())
            h = digest(record)
            locator = record['evidence_id'] if table == 'evidence_records' else h
            token = '' if locator == h else locator
            ref = dict(cache_table=table, record_sha256=h, source_record_locator=locator,
                       reported_generation=record['generation'])
            operations = {
                'canonical_record_hash': lambda: digest(record),
                'locator_selection_and_validation': lambda: string(record['evidence_id'] if table == 'evidence_records' else h),
                'witness_reference_serialization': lambda: canonical(ref),
                'compact_token_encoding': lambda: '' if locator == h else locator,
                'locator_decoding': lambda: h if token == '' else token,
            }
            result[table] = dict(stored_locator_bytes=len(token.encode()), decoded_locator_bytes=len(locator.encode()),
                microseconds_per_operation={name: min(timeit.repeat(fn, number=20000, repeat=3))/20000*1e6
                                            for name, fn in operations.items()})
    args.output.write_text(json.dumps(dict(scope='Isolated Python microbenchmark; minimum of three 20k repetitions; not additive to end-to-end profiling. Uses exact existing locator expressions, SHA-256 and canonical serialization.', results=result), indent=2)+'\n')
    print(args.output)


if __name__ == '__main__':
    main()
