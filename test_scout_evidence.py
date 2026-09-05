import io
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import flop_scout as scout
import scout_evidence as ev
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name)/'observer.sqlite'
        self.home_patch = patch.object(scout,'HOME',Path(self.tmp.name))
        self.home_patch.start()
        self.addCleanup(self.home_patch.stop)
        self.conn = scout.observer_connect_write(self.db)
        self.addCleanup(self.conn.close)

    def raw(self, seq=1, text='hello', nonce=123, room='lobby'):
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        did = scout.public_did(key)
        return {'seq':seq,'ts':'2026-09-05T12:34:56.001Z','from':did,
                'did':did,'nonce':nonce,'sig':scout.b64u(key.sign(f'{room}|{nonce}|{text}'.encode())), 'text':text}

    def ingest(self, raw, room='lobby', generation='g1', **kwargs):
        with self.conn:
            return ev.ingest(self.conn, room, raw, scout.verify_signed_record_offline,
                generation=generation, endpoint='https://technocore.chat/r/'+room+'?format=json&limit=200&since=0', **kwargs)

    def row(self, rid):
        return self.conn.execute('SELECT * FROM raw_network_records WHERE raw_record_id=?',(rid,)).fetchone()

    def test_exact_utf8_text_and_provenance(self):
        text = '  {"z": 1, "a":"e\u0301 ☃ 😀\\n"}\n\t trailing  '
        raw = self.raw(text=text,nonce='000123')
        rid = self.ingest(raw, retrieved_at='2026-09-05T13:00:00+00:00')
        row = self.row(rid)
        self.assertEqual(row['raw_text'].encode(),text.encode())
        self.assertEqual(row['raw_text_sha256'],ev.digest(text))
        for field,key in [('signature','sig'),('nonce','nonce'),('sender_did','did'),('network_timestamp','ts')]:
            self.assertEqual(row[field],raw[key])
        self.assertEqual(row['retrieved_at'],'2026-09-05T13:00:00+00:00')
        self.assertIn('since=0',row['source_endpoint'])
        self.assertEqual(row['signature_status'],'VERIFIED_OFFLINE')
        self.assertEqual(row['raw_completeness'],'COMPLETE')
        self.assertEqual(json.loads(row['raw_record_json']),raw)

    def test_unicode_forms_remain_distinct(self):
        ids = [self.ingest(self.raw(text=t)) for t in ('é','e\u0301')]
        self.assertNotEqual(ids[0],ids[1])
        self.assertEqual(ev.integrity(self.conn)['seq_conflicts'],1)

    def test_raw_immutable_update_delete_and_replace(self):
        rid = self.ingest(self.raw())
        for sql in ('UPDATE raw_network_records SET raw_text="changed"','DELETE FROM raw_network_records'):
            with self.assertRaises(sqlite3.IntegrityError):
                self.conn.execute(sql)
        self.conn.rollback()
        self.assertEqual(self.row(rid)['raw_text'],'hello')

    def test_idempotent_reread_and_repost(self):
        raw = self.raw()
        rid = self.ingest(raw)
        self.assertEqual(self.ingest(dict(reversed(list(raw.items())))),rid)
        self.assertEqual(len(list(ev.feed(self.conn))),1)
        raw['seq']=2
        self.ingest(raw)
        self.assertEqual(list(ev.feed(self.conn))[-1]['duplicate_kind'],'EXACT_DUPLICATE')
        self.assertEqual(ev.metrics(self.conn)['exact_duplicate_suppression'],1)

    def test_conflict_and_generation(self):
        first = self.ingest(self.raw(text='first'))
        other = self.ingest(self.raw(text='different'))
        next_gen = self.ingest(self.raw(text='first'), generation='g2')
        self.assertEqual(len({first,other,next_gen}),3)
        self.assertEqual(ev.integrity(self.conn)['seq_conflicts'],1)

    def test_signature_failures_missing_and_did_mismatch_retained(self):
        bad = self.raw(); bad['text']='altered'
        missing = self.raw(seq=2); del missing['sig']
        mismatch = self.raw(seq=3); mismatch['from']='other'
        ids = [self.ingest(x) for x in (bad,missing,mismatch)]
        self.assertEqual([self.row(x)['signature_status'] for x in ids],['FAILED','MISSING','FAILED'])
        self.assertEqual(self.row(ids[2])['signature_error'],'DID_MISMATCH')
        self.assertEqual(ev.integrity(self.conn)['raw_records'],3)

    def test_float_nonce_never_coerced(self):
        raw = self.raw(); raw['nonce']=123.0
        with patch.object(scout,'verify_signed_record_offline',side_effect=AssertionError('must not verify float')):
            rid=self.ingest(raw)
        self.assertEqual(self.row(rid)['signature_status'],'UNSUPPORTED')
        self.assertEqual(scout.message_nonce(raw),None)

    def test_malformed_records_and_unknown_retained(self):
        raws = [None,42,['not','object'],{'seq':1,'text':{}}, {'seq':2,'text':'\ud800'},self.raw(seq=3,text='ordinary unknown words')]
        scout.ingest_messages(self.conn,'lobby',raws,generation='g1')
        self.assertEqual(ev.integrity(self.conn)['raw_records'],6)
        self.assertEqual(ev.integrity(self.conn)['status'],'PASS')
        self.assertEqual(list(ev.feed(self.conn))[-1]['classification'],'UNCLASSIFIED')

    def test_fk_hash_and_missing_raw_rejected(self):
        rid = self.ingest(self.raw())
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("UPDATE observed_events SET raw_text_sha256='wrong'")
        self.conn.rollback()
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("UPDATE observed_events SET raw_record_id='missing'")
        self.conn.rollback()
        self.assertEqual(ev.integrity(self.conn)['status'],'PASS')

    def test_repair_raw_without_event(self):
        rid = self.ingest(self.raw())
        with self.conn:
            self.conn.execute('DELETE FROM observed_events')
        self.assertEqual(ev.integrity(self.conn)['missing_events'],1)
        ev.repair(self.conn)
        self.assertEqual(ev.integrity(self.conn)['status'],'PASS')
        self.assertEqual(list(ev.feed(self.conn))[0]['raw_record_id'],rid)
        ev.repair(self.conn)
        self.assertEqual(len(list(ev.feed(self.conn))),1)

    def test_restart_durable_cursor_and_event_ids(self):
        page={'messages':[self.raw(seq=i) for i in range(1,4)]}
        with patch.object(scout,'fetch_room_view',return_value=(page,'g1')):
            scout.service_poll_room(self.conn,'lobby')
        before=list(ev.feed(self.conn))
        self.conn.close()
        self.conn=scout.observer_connect_write(self.db)
        self.addCleanup(self.conn.close)
        self.assertEqual(scout.room_cursor(self.conn,'lobby')['last_seq'],3)
        with patch.object(scout,'fetch_room_view',return_value=(page,'g1')):
            scout.service_poll_room(self.conn,'lobby')
        self.assertEqual(before,list(ev.feed(self.conn)))

    def test_crash_before_cursor_safe_replay(self):
        page={'messages':[self.raw(seq=i) for i in range(1,4)]}
        with patch.object(scout,'fetch_room_view',return_value=(page,'g1')), patch.object(scout,'update_room_cursor',side_effect=RuntimeError('crash')):
            with self.assertRaises(RuntimeError): scout.service_poll_room(self.conn,'lobby')
        self.assertEqual(scout.room_cursor(self.conn,'lobby')['last_seq'],0)
        self.assertEqual(ev.integrity(self.conn)['raw_records'],3)
        with patch.object(scout,'fetch_room_view',return_value=(page,'g1')):
            scout.service_poll_room(self.conn,'lobby')
        self.assertEqual(scout.room_cursor(self.conn,'lobby')['last_seq'],3)
        self.assertEqual(ev.integrity(self.conn)['raw_records'],3)

    def test_raw_transaction_failure_does_not_advance(self):
        page={'messages':[self.raw(seq=i) for i in range(1,4)]}
        original=ev.ingest
        def fail(conn, room, raw, *a, **kw):
            if raw['seq']==2: raise sqlite3.OperationalError('simulated disk failure')
            return original(conn,room,raw,*a,**kw)
        with patch.object(scout,'fetch_room_view',return_value=(page,'g1')),patch.object(ev,'ingest',side_effect=fail):
            with self.assertRaises(sqlite3.OperationalError): scout.service_poll_room(self.conn,'lobby')
        self.assertEqual(scout.room_cursor(self.conn,'lobby')['last_seq'],0)
        self.assertEqual(ev.integrity(self.conn)['raw_records'],0)

    def test_cannot_skip_unpersisted_page_member(self):
        rows=[self.raw(seq=i) for i in range(1,4)]
        self.ingest(rows[-1])
        with self.assertRaises(RuntimeError): scout.highest_persisted_page_seq(self.conn,'lobby','g1',rows)

    def test_malformed_page_middle_keeps_later_records(self):
        page={'messages':[self.raw(),{'seq':2,'text':None},None,self.raw(seq=3)]}
        with patch.object(scout,'fetch_room_view',return_value=(page,'g1')):
            result=scout.service_poll_room(self.conn,'lobby')
        self.assertEqual(result['cursor_after'],3)
        self.assertEqual(ev.integrity(self.conn)['raw_records'],4)

    def test_450_pagination_and_budget(self):
        rows=[{'seq':i,'text':f'message {i}'} for i in range(1,451)]
        calls=[]
        def fetch(room,limit,since,allow_missing):
            calls.append(since)
            return {'messages':[r for r in rows if r['seq']>since][:limit],'latest_seq':450},'g1'
        with patch.object(scout,'fetch_room_view',side_effect=fetch):
            first=scout.service_poll_room(self.conn,'lobby',max_pages=2)
            self.assertEqual(first['continuity'],'CATCHING_UP')
            self.assertTrue(first['backlog_remaining'])
            last=scout.service_poll_room(self.conn,'lobby')
        self.assertEqual(calls,[0,200,400])
        self.assertEqual(last['cursor_after'],450)
        self.assertEqual(ev.integrity(self.conn)['raw_records'],450)

    def test_cursor_regression_rejected(self):
        scout.update_room_cursor(self.conn,'lobby','g1',5)
        with self.assertRaises(ValueError): scout.update_room_cursor(self.conn,'lobby','g1',4)
        self.assertEqual(scout.room_cursor(self.conn,'lobby')['last_seq'],5)

    def test_every_required_class_claim_only(self):
        classes=list(ev.CLASSES)
        for i,cls in enumerate(classes,1):
            with self.subTest(cls=cls):
                self.ingest(self.raw(seq=i,text=json.dumps({'type':cls})))
                item=list(ev.feed(self.conn))[-1]
                self.assertEqual(item['classification'],cls)
                self.assertTrue(item['structured_event']['claim_only'])
                self.assertFalse(item['structured_event']['correctness_verified'])
        self.ingest(self.raw(seq=99,text='tclk1 {"type":"offer"}'))
        self.assertEqual(list(ev.feed(self.conn))[-1]['classification'],'TCLK_TRANSCRIPT_EVENT')
        self.ingest(self.raw(seq=100,text='tclk1 {broken'))
        self.assertEqual(list(ev.feed(self.conn))[-1]['classification'],'MALFORMED_UNVERIFIABLE_EVENT')

    def test_template_variable_fields_and_substantive_difference(self):
        for seq,variation in enumerate(('timestamp=2026-01-01','timestamp=2026-01-02','nonce=10','nonce=20','job_id=one','job_id=two'),1):
            self.ingest(self.raw(seq=seq,text='Capabilities: analyze Python '+variation))
        items=list(ev.feed(self.conn))
        self.assertEqual([x['duplicate_kind'] for x in items],['UNIQUE','TEMPLATE_VARIANT','UNIQUE','TEMPLATE_VARIANT','UNIQUE','TEMPLATE_VARIANT'])
        self.ingest(self.raw(seq=8,text='Capabilities: analyze Rust nonce=20'))
        self.assertEqual(list(ev.feed(self.conn))[-1]['duplicate_kind'],'UNIQUE')
        for seq,text in ((9,'Result: 2 jobs completed nonce=20'),(10,'Result: 3 jobs completed nonce=21')):
            self.ingest(self.raw(seq=seq,text=text))
        self.assertEqual(list(ev.feed(self.conn))[-1]['duplicate_kind'],'UNIQUE')

    def test_json_template_and_different_claim(self):
        for seq,body in enumerate(({'type':'capability','task':'python','nonce':1}, {'type':'capability','task':'python','nonce':2}, {'type':'capability','task':'rust','nonce':3}),1):
            self.ingest(self.raw(seq=seq,text=json.dumps(body)))
        self.assertEqual([x['duplicate_kind'] for x in ev.feed(self.conn)],['UNIQUE','TEMPLATE_VARIANT','UNIQUE'])

    def test_watch_multiple_memberships_no_duplicate_raw(self):
        config={'one':{'enabled':True,'rooms':['lobby']},'two':{'enabled':True,'rooms':['lobby']}}
        ev.sync_collections(self.conn,config)
        self.ingest(self.raw())
        self.assertEqual(list(ev.feed(self.conn))[0]['watch_collections'],['one','two'])
        self.assertEqual(len(list(ev.feed(self.conn,collection='one'))),1)
        self.assertEqual(ev.integrity(self.conn)['raw_records'],1)
        config['one']['enabled']=False
        ev.sync_collections(self.conn,config)
        self.assertEqual(ev.metrics(self.conn)['watch_collections_active'],1)

    def test_watch_rejects_urls_and_commands(self):
        path=Path(self.tmp.name)/'watch.json'
        for room in ('https://evil.example','../identity.pem','lobby;run'):
            path.write_text(json.dumps({'bad':{'enabled':True,'rooms':[room]}}))
            with self.assertRaises(ValueError): ev.load_collections(path)

    def test_feed_independent_checkpoints_and_filters(self):
        for seq in range(1,5): self.ingest(self.raw(seq=seq,text=json.dumps({'type':'work_result','answer':seq})))
        items=list(ev.feed(self.conn)); ids=[r['event_id'] for r in items]
        checkpoints={'router':ids[1],'bench':ids[0],'sentinel':0}
        for name,cursor in checkpoints.items():
            self.assertEqual([r['event_id'] for r in ev.feed(self.conn,since_id=cursor)],[i for i in ids if i>cursor])
        self.assertEqual(items,list(ev.feed(self.conn)))
        for item in items:
            self.assertEqual(item['schema'],ev.SCHEMA)
            self.assertEqual(self.row(item['raw_record_id'])['raw_text_sha256'],item['raw_text_sha256'])
        self.assertEqual(len(list(ev.feed(self.conn,since_seq=2,classification='WORK_RESULT'))),2)

    def test_daily_fixture(self):
        texts=['{"type":"work_request"}','{"type":"work_acceptance"}','{"type":"work_result"}', '{"type":"verification_result"}', 'tclk1 {"type":"offer"}', 'tclk1 {"type":"lock"}', 'tclk1 broken','Capabilities: Python nonce=1','Capabilities: Python nonce=2','Capabilities: Python nonce=2']
        for seq,text in enumerate(texts,1): self.ingest(self.raw(seq=seq,text=text,room='kibble'), room='kibble', retrieved_at='2026-09-05T13:00:00+00:00')
        bad=self.raw(seq=11);bad['sig']='bad'
        self.ingest(bad,retrieved_at='2026-09-05T13:00:00+00:00')
        result=ev.daily(self.conn,'2026-09-05')
        self.assertEqual(result['new_did_count'],1)
        self.assertEqual(result['useful_work']['WORK_RESULT'],1)
        self.assertEqual(result['malformed'],1)
        self.assertEqual(result['signature_failures'],1)
        self.assertEqual(result['tclk']['offers'],1)
        self.assertEqual(result['tclk']['settlement_rail_claims'],1)
        self.assertEqual(result['watch_changes']['kibble'],10)
        self.assertEqual(result['duplicates']['template_variants'],1)
        self.assertEqual(result['duplicates']['exact_reposts'],1)
        self.assertTrue(all(v==0 for v in result['safety'].values()))

    def test_readers_concurrent_writer_no_import_or_migration_or_network(self):
        self.ingest(self.raw())
        ready,stop=threading.Event(),threading.Event()
        failures=[]
        def writer():
            try:
                conn=sqlite3.connect(self.db)
                conn.execute('BEGIN IMMEDIATE')
                conn.execute("INSERT INTO evidence_metrics VALUES ('test_writer',1)")
                ready.set();stop.wait(5)
                conn.commit();conn.close()
            except Exception as exc: failures.append(exc);ready.set()
        thread=threading.Thread(target=writer);thread.start();self.assertTrue(ready.wait(3))
        try:
            with patch.object(scout,'import_local_history',side_effect=AssertionError('import')),patch.object(scout,'init_observer_db',side_effect=AssertionError('migration')),patch.object(scout,'load_key',side_effect=AssertionError('key')),patch.object(scout.urllib.request,'urlopen',side_effect=AssertionError('network')),patch('sys.stdout',new_callable=io.StringIO) as output:
                scout.service_status(self.db)
                scout.daily_report(SimpleNamespace(db=self.db,date='2026-09-05',output=None))
                scout.evidence_local_command(SimpleNamespace(db=self.db,evidence_cmd='feed',since_id=0,since_seq=None,classification=None,collection=None,output=None))
                self.assertIn('flop-scout-evidence/v1',output.getvalue())
                with scout.observer_connect_readonly(self.db) as reader:
                    with self.assertRaises(sqlite3.OperationalError): reader.execute('DELETE FROM observed_events')
        finally:
            stop.set();thread.join(5)
        self.assertEqual(failures,[])

    def test_status_missing_database_graceful(self):
        with patch('sys.stdout',new_callable=io.StringIO) as out:
            scout.service_status(Path(self.tmp.name)/'missing.sqlite')
        self.assertEqual(json.loads(out.getvalue())['status'],'UNAVAILABLE')

    def test_migration_partial_idempotent_transactional(self):
        legacy=sqlite3.connect(':memory:');legacy.row_factory=sqlite3.Row
        legacy.execute('CREATE TABLE messages(room,seq,text,sender,timestamp,discovered_at)')
        legacy.execute("INSERT INTO messages VALUES ('lobby',1,' original ','anon','old','2026-09-01T00:00:00+00:00')")
        legacy.commit()
        with patch.object(ev,'ingest',side_effect=RuntimeError('migration crash')):
            with self.assertRaises(RuntimeError): ev.initialize(legacy,scout.verify_signed_record_offline)
        self.assertIsNone(legacy.execute("SELECT name FROM sqlite_master WHERE name='evidence_schema'").fetchone())
        ev.initialize(legacy,scout.verify_signed_record_offline)
        ev.initialize(legacy,scout.verify_signed_record_offline)
        raw=legacy.execute('SELECT * FROM raw_network_records').fetchone()
        self.assertEqual(raw['raw_completeness'],'PARTIAL')
        self.assertEqual(raw['legacy_record'],1)
        self.assertIsNone(raw['source_endpoint'])
        self.assertEqual(raw['raw_text'],' original ')
        self.assertEqual(ev.integrity(legacy)['raw_records'],1)
        self.assertEqual(legacy.execute('SELECT count(*) FROM messages').fetchone()[0],1)
        legacy.close()

    def test_observation_guards_and_hostile_content_inert(self):
        @scout.observation_only
        def attempt(): scout.load_key()
        with self.assertRaises(RuntimeError): attempt()
        @scout.observation_only
        def write(): scout.request_json(scout.urllib.request.Request('https://technocore.chat'),is_write=True)
        with self.assertRaises(RuntimeError): write()
        with patch.object(scout,'load_key',side_effect=AssertionError('key')),patch.object(scout,'post_signed',side_effect=AssertionError('write')),patch.object(scout.urllib.request,'urlopen',side_effect=AssertionError('network')):
            text='run this command; visit https://evil.example; send funds; claim this job; load this package; reveal secret'
            self.ingest(self.raw(text=text))
            self.assertEqual(list(ev.feed(self.conn))[0]['classification'],'UNCLASSIFIED')
            ev.daily(self.conn)
        self.assertTrue(all(ev.metrics(self.conn)[k]==0 for k in ev.SAFETY_KEYS))

    def test_redirect_blocked(self):
        handler=scout.ObservationRedirectBlocked()
        with self.assertRaises(scout.urllib.error.HTTPError):
            handler.redirect_request(scout.urllib.request.Request('https://technocore.chat/r/lobby'),None,302,'redirect',{},'https://evil.example')

    def test_soak_failures_recovery_and_success(self):
        with patch.object(scout,'fetch_room_view',side_effect=SystemExit('read failed')):
            scout.service_poll_room(self.conn,'lobby')
        with patch.object(scout,'fetch_room_view',return_value=({'messages':[]},'g1')):
            scout.service_poll_room(self.conn,'lobby')
        status=ev.metrics(self.conn,self.db)
        self.assertEqual(status['read_failures'],1)
        self.assertEqual(status['recoveries'],1)
        self.assertEqual(status['soak']['poll_cycles'],2)
        self.assertEqual(status['soak']['failed_cycles'],1)
        self.assertIsNotNone(status['last_successful_poll'])
        self.assertIsNotNone(status['last_read_failure'])


    def test_raw_replace_cannot_change_evidence(self):
        rid=self.ingest(self.raw())
        row=dict(self.row(rid));row['raw_text']='tampered'
        with self.conn:
            self.conn.execute('INSERT OR REPLACE INTO raw_network_records VALUES ('+','.join('?' for _ in row)+')',tuple(row.values()))
        self.assertEqual(self.row(rid)['raw_text'],'hello')


    def test_generation_change_full_page_budget_and_restart(self):
        scout.update_room_cursor(self.conn,'lobby','old',1000)
        page={'messages':[self.raw(seq=i) for i in range(1,201)],'latest_seq':300}
        with patch.object(scout,'log'),patch.object(scout,'fetch_room_view',return_value=(page,'new')):
            result=scout.service_poll_room(self.conn,'lobby',max_pages=1)
        self.assertEqual(result['cursor_after'],200)
        self.assertEqual(result['continuity'],'CATCHING_UP')
        self.assertEqual(scout.room_cursor(self.conn,'lobby')['generation'],'new')


    def test_transport_generation_conflict_preserved_no_cursor_advance(self):
        page={'messages':[self.raw()], '_scout_transport':{'generation_conflict':True,'header_generation':'old','body_generation':'new'}}
        with patch.object(scout,'fetch_room_view',return_value=(page,'new')):
            result=scout.service_poll_room(self.conn,'lobby')
        self.assertEqual(result['continuity'],'READ_FAILED')
        self.assertEqual(result['cursor_after'],0)
        self.assertEqual(ev.integrity(self.conn)['raw_records'],1)


    def test_ring_gap_retained_but_not_silently_skipped(self):
        scout.update_room_cursor(self.conn,'lobby','g1',5)
        page={'messages':[self.raw(seq=20)],'first_seq':20}
        with patch.object(scout,'fetch_room_view',return_value=(page,'g1')):
            result=scout.service_poll_room(self.conn,'lobby')
        self.assertEqual(result['continuity'],'READ_FAILED')
        self.assertEqual(result['cursor_after'],5)
        self.assertEqual(ev.integrity(self.conn)['raw_records'],1)


    def test_nonce_larger_than_sqlite_integer_is_lossless(self):
        raw=self.raw(nonce=9999999999999999999)
        scout.ingest_messages(self.conn,'lobby',[raw],generation='g1')
        row=self.conn.execute('SELECT * FROM raw_network_records').fetchone()
        self.assertEqual(row['nonce'],'9999999999999999999')
        self.assertEqual(json.loads(row['raw_record_json'])['nonce'],9999999999999999999)
        self.assertEqual(row['signature_status'],'VERIFIED_OFFLINE')


    def test_template_result_job_id_not_removed(self):
        for seq in (1,2):
            self.ingest(self.raw(seq=seq,text=json.dumps({'type':'work_result','job_id':str(seq),'answer':'42'})))
        self.assertEqual(list(ev.feed(self.conn))[-1]['duplicate_kind'],'UNIQUE')


    def test_tclk_frame_binding_mismatch_separate_from_signature(self):
        rid=self.ingest(self.raw(text='tclk1 {"type":"offer","from":"different"}'))
        self.assertEqual(self.row(rid)['signature_status'],'VERIFIED_OFFLINE')
        self.assertEqual(self.row(rid)['did_mismatch'],1)
        self.assertEqual(list(ev.feed(self.conn))[0]['parse_status'],'UNVERIFIABLE')


    def test_compatibility_caches_have_raw_links(self):
        scout.ingest_messages(self.conn,'lobby',[self.raw(text='Work request: test a parser')],generation='g1')
        scout.refresh_opportunities(self.conn)
        self.assertEqual(ev.integrity(self.conn)['unlinked_compatibility_records'],0)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM compatibility_evidence_links WHERE cache_table='messages'").fetchone()[0],1)

    def test_malformed_unicode_metadata_and_deep_text_retained(self):
        raw={'seq':1,'from':'bad\ud800','sig':'bad\ud800','nonce':1,'ts':'bad\ud800','text':'['*1200+']'*1200}
        scout.ingest_messages(self.conn,'lobby',[raw,self.raw(seq=2)],generation='g1')
        self.assertEqual(ev.integrity(self.conn)['raw_records'],2)
        stored=self.conn.execute('SELECT raw_record_json FROM raw_network_records WHERE seq=1').fetchone()[0]
        self.assertEqual(json.loads(stored),raw)


if __name__=='__main__': unittest.main()
