import sqlite3
import unittest
import scout_evidence as evidence


class RetrievalNormalizationTests(unittest.TestCase):
    def setUp(self):
        self.conn=sqlite3.connect(':memory:'); self.conn.row_factory=sqlite3.Row
        evidence.initialize(self.conn,lambda room,raw:'UNSIGNED')

    def tearDown(self): self.conn.close()

    def test_page_metadata_is_stored_once_and_reread_view_is_compatible(self):
        stamp='2026-09-13T00:00:00+00:00'; metadata={'headers':{'cf-ray':'same'},'status':200}
        batch=evidence.create_retrieval_batch(self.conn,stamp,'/r/lobby',metadata)
        for seq in range(2):
            raw={'seq':seq,'text':'same-'+str(seq)}
            evidence.ingest(self.conn,'lobby',raw,lambda room,item:'UNSIGNED',endpoint='/r/lobby',retrieved_at=stamp,metadata=metadata,retrieval_batch_id=batch)
            evidence.ingest(self.conn,'lobby',raw,lambda room,item:'UNSIGNED',endpoint='/r/lobby',retrieved_at=stamp,metadata=metadata,retrieval_batch_id=batch)
        self.assertEqual(self.conn.execute('SELECT count(*) FROM evidence_retrieval_batches').fetchone()[0],1)
        self.assertEqual(self.conn.execute('SELECT count(*) FROM evidence_retrieval_links').fetchone()[0],4)
        self.assertEqual(self.conn.execute('SELECT count(*) FROM evidence_retrievals').fetchone()[0],2)
        raw=self.conn.execute('SELECT * FROM raw_network_records LIMIT 1').fetchone()
        self.assertEqual(evidence.transport_metadata(self.conn,raw)['headers']['cf-ray'],'same')
