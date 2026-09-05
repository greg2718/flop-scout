"""Operational time windows must not turn schema migration into network traffic."""
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import flop_scout as scout
import scout_evidence as ev


class TimeSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / 'observer.sqlite'
        self.conn = sqlite3.connect(self.db)
        self.conn.row_factory = sqlite3.Row
        self.addCleanup(self.conn.close)
        self.current = datetime.now(timezone.utc)
        self.old = (self.current - timedelta(days=10)).isoformat()
        self.recent = (self.current - timedelta(seconds=1)).isoformat()
        self.today = self.current.date().isoformat()

    def migrate(self, network_time=None, retrieval_time=None):
        self.conn.execute('CREATE TABLE messages(room,seq,text,sender,timestamp,discovered_at)')
        for seq in range(100):
            self.conn.execute('INSERT INTO messages VALUES (?,?,?,?,?,?)', (
                'kibble', seq, json.dumps({'type':'work_result','result':seq}),
                f'did:key:historical-{seq % 20}', network_time, retrieval_time))
        self.conn.commit()
        ev.initialize(self.conn, scout.verify_signed_record_offline)
        ev.sync_collections(self.conn, ev.DEFAULT_COLLECTIONS)

    def fresh(self):
        ev.initialize(self.conn, scout.verify_signed_record_offline)
        ev.sync_collections(self.conn, ev.DEFAULT_COLLECTIONS)

    def capture(self, seq=200, retrieved=None, network=None, did='did:key:fresh', **kwargs):
        with self.conn:
            return ev.ingest(self.conn, 'kibble', {
                'seq':seq,'from':did,'ts':network,'text':'{"type":"work_result"}'},
                scout.verify_signed_record_offline,
                endpoint='https://technocore.chat/r/kibble?format=json&limit=200',
                retrieved_at=retrieved if retrieved is not None else self.recent, **kwargs)

    def assert_no_recent(self):
        status = ev.metrics(self.conn)
        self.assertEqual(status['events_last_hour'],0)
        self.assertEqual(status['events_last_24h'],0)
        self.assertEqual(status['new_dids_last_24h'],0)
        return status

    def test_migration_100_old_records_and_20_dids_not_recent(self):
        self.migrate(self.old, self.old)
        self.assert_no_recent()
        self.assertEqual(ev.integrity(self.conn)['raw_records'],100)
        self.assertEqual(self.conn.execute('SELECT count(DISTINCT sender_did) FROM raw_network_records').fetchone()[0],20)

    def test_migration_with_unknown_dates_has_no_fabricated_retrieval(self):
        self.migrate()
        self.assert_no_recent()
        self.assertEqual(self.conn.execute("SELECT count(*) FROM raw_network_records WHERE retrieved_at='' AND network_timestamp IS NULL").fetchone()[0],100)
        self.assertTrue(self.conn.execute('SELECT min(created_at) FROM raw_network_records').fetchone()[0].startswith(self.today))

    def test_previously_migrated_rows_with_current_retrieval_still_excluded(self):
        # Simulates the old importer's migration-time retrieval fallback without
        # rewriting any immutable rows or requiring a new schema migration.
        self.migrate(self.old, self.recent)
        before = [tuple(r) for r in self.conn.execute('SELECT * FROM raw_network_records ORDER BY raw_record_id')]
        self.assert_no_recent()
        report = ev.daily(self.conn,self.today)
        self.assertEqual(report['classifications'],{})
        self.assertEqual(report['new_did_count'],0)
        self.assertEqual(report['watch_changes']['kibble'],0)
        self.assertEqual(before,[tuple(r) for r in self.conn.execute('SELECT * FROM raw_network_records ORDER BY raw_record_id')])

    def test_new_complete_capture_counts_in_windows(self):
        self.fresh()
        self.capture(network=self.recent)
        status = ev.metrics(self.conn)
        self.assertEqual(status['events_last_hour'],1)
        self.assertEqual(status['events_last_24h'],1)
        self.assertEqual(status['new_dids_last_24h'],1)
        self.assertEqual(status['live_records_ingested'],1)
        self.assertEqual(ev.daily(self.conn,self.today)['useful_work']['WORK_RESULT'],1)

    def test_late_old_network_event_counts_on_observation_day(self):
        self.fresh()
        rid = self.capture(network=self.old)
        self.assertEqual(ev.metrics(self.conn)['events_last_hour'],1)
        self.assertEqual(ev.daily(self.conn,self.today)['useful_work']['WORK_RESULT'],1)
        self.assertEqual(ev.daily(self.conn,self.old[:10])['useful_work']['WORK_RESULT'],0)
        self.assertEqual(self.conn.execute('SELECT network_timestamp FROM raw_network_records WHERE raw_record_id=?',(rid,)).fetchone()[0],self.old)

    def test_parsing_and_insertion_today_do_not_make_old_capture_recent(self):
        self.fresh()
        self.capture(retrieved=self.old,network=self.old)
        row = self.conn.execute('SELECT r.created_at,e.parsed_at FROM raw_network_records r JOIN observed_events e USING(raw_record_id)').fetchone()
        self.assertTrue(row['created_at'].startswith(self.today))
        self.assertTrue(row['parsed_at'].startswith(self.today))
        self.assert_no_recent()
        self.assertEqual(ev.daily(self.conn,self.today)['classifications'],{})
        self.assertEqual(ev.daily(self.conn,self.old[:10])['useful_work']['WORK_RESULT'],1)

    def test_soak_counters_not_started_by_migration(self):
        self.migrate(self.old,self.recent)
        status = ev.metrics(self.conn)
        self.assertEqual(status['records_ingested'],100)
        self.assertEqual(status['total_persisted_records'],100)
        self.assertEqual(status['live_records_ingested'],0)
        self.assertEqual(status['soak']['poll_cycles'],0)
        self.assertEqual(status['soak']['runtime_seconds'],0)
        self.assertIsNone(status['last_cycle'])
        self.assertIsNone(status['last_successful_poll'])
        self.assertEqual(status['network_reads'],0)

    def test_known_legacy_did_is_not_new_on_live_reappearance(self):
        self.migrate(None,self.recent)
        self.capture(did='did:key:historical-0')
        self.assertEqual(ev.metrics(self.conn)['events_last_hour'],1)
        self.assertEqual(ev.metrics(self.conn)['new_dids_last_24h'],0)
        self.assertEqual(ev.daily(self.conn,self.today)['new_did_count'],0)

    def test_first_observation_not_latest_reappearance(self):
        self.fresh()
        self.capture(seq=1,retrieved=self.old)
        self.capture(seq=2)
        self.assertEqual(ev.metrics(self.conn)['new_dids_last_24h'],0)

    def test_partial_nonlegacy_not_operational_capture(self):
        self.fresh()
        with self.conn:
            ev.ingest(self.conn,'kibble',{'seq':1,'from':'did:key:partial','text':'hello'},scout.verify_signed_record_offline,retrieved_at=self.recent)
        self.assert_no_recent()
        self.assertEqual(ev.daily(self.conn,self.today)['classifications'],{})

    def test_daily_duplicates_and_conflicts_exclude_legacy(self):
        self.fresh()
        for text in ('Capabilities: parser nonce=1','Capabilities: parser nonce=2','Capabilities: parser nonce=2'):
            with self.conn:
                ev.ingest(self.conn,'kibble',{'seq':1,'text':text},scout.verify_signed_record_offline,
                          legacy=True,retrieved_at=self.recent)
        report = ev.daily(self.conn,self.today)
        self.assertEqual(report['duplicates'],{'exact_reposts':0,'template_variants':0,'rereads':0,'top_groups':[]})
        self.assertEqual(report['provenance_conflicts'],0)
        self.assertTrue(all(v==0 for v in report['tclk'].values()))

    def test_equivalent_offset_dates_and_future_capture(self):
        self.fresh()
        offset = datetime.fromisoformat(self.recent).astimezone(timezone(timedelta(hours=9)))
        self.capture(seq=1,retrieved=offset.isoformat())
        self.capture(seq=2,retrieved=(self.current+timedelta(days=1)).isoformat(),did='did:key:future')
        self.assertEqual(ev.metrics(self.conn)['events_last_hour'],1)
        self.assertEqual(ev.metrics(self.conn)['new_dids_last_24h'],1)

    def test_reporting_readonly_and_integrity_unchanged(self):
        self.migrate(self.old,self.recent)
        with scout.observer_connect_readonly(self.db) as reader, \
             patch.object(ev,'initialize',side_effect=AssertionError('migration')), \
             patch.object(scout,'load_key',side_effect=AssertionError('key')), \
             patch.object(scout.urllib.request,'urlopen',side_effect=AssertionError('network')):
            before=reader.total_changes
            ev.metrics(reader); ev.daily(reader,self.today)
            result=ev.integrity(reader)
            self.assertEqual(reader.total_changes,before)
            self.assertEqual(result['status'],'PASS')
            for key in ('orphaned_events','hash_mismatches','raw_identity_mismatches','missing_events'):
                self.assertEqual(result[key],0)


if __name__=='__main__': unittest.main()
