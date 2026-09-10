"""Bounded, read-cut-local source lookup reuse; admission stays in legacy checks."""
from collections import defaultdict
from scout_projection_contract import *

SOURCE_BATCH_ROWS=50


class SourceInputs:
    def __init__(self,conn,raw_ids):
        from scout_projection_legacy import CACHE_TEXT, check
        require(0<len(raw_ids)<=SOURCE_BATCH_ROWS,'Source lookup batch exceeds bound')
        self.conn=conn;ids=list(dict.fromkeys(raw_ids));marks=','.join('?' for _ in ids)
        self.raws={r['raw_record_id']:dict(r) for r in conn.execute('SELECT * FROM raw_network_records WHERE raw_record_id IN ('+marks+')',ids)}
        self.events={r['raw_record_id']:dict(r) for r in conn.execute('SELECT * FROM observed_events WHERE raw_record_id IN ('+marks+')',ids)}
        self.candidates={rid for rid,r in self.raws.items() if r['generation'] in (None,'UNKNOWN_LEGACY') and r.get('reported_generation') not in (None,'UNKNOWN_LEGACY','GENERATION_MISSING','')}
        self.links=defaultdict(list);self.records={}
        candidates=sorted(self.candidates);candidate_marks=','.join('?' for _ in candidates)
        # Noncandidate mapping only reads these four compatibility tables. The
        # complete link set is mandatory for every candidate, including unknown
        # kinds so the existing validator rejects them rather than filtering them.
        query="SELECT raw_record_id,cache_table,cache_rowid,raw_text_sha256 FROM compatibility_evidence_links WHERE raw_record_id IN ("+marks+") AND (cache_table IN ('messages','evidence_records','tclk_frames','kibble_events')"
        if candidates:query+=' OR raw_record_id IN ('+candidate_marks+')'
        query+=') ORDER BY raw_record_id,cache_table,cache_rowid'
        for row in conn.execute(query,ids+candidates):
            rid=row['raw_record_id'];link={k:row[k] for k in ('cache_table','cache_rowid','raw_text_sha256')}
            self.links[rid].append(link)
            check(len(self.links[rid])<=256,'LG1_LINK_BOUND_EXCEEDED')
        by_table=defaultdict(set)
        for links in self.links.values():
            for link in links:
                check(link['cache_table'] in CACHE_TEXT,'LG1_UNSUPPORTED_LEGACY')
                by_table[link['cache_table']].add(link['cache_rowid'])
        for table,rowids in by_table.items():
            rowids=sorted(rowids)
            for start in range(0,len(rowids),200):
                batch=rowids[start:start+200]
                for row in conn.execute('SELECT rowid AS projection_cache_rowid,* FROM '+table+' WHERE rowid IN ('+','.join('?' for _ in batch)+')',batch):
                    item=dict(row);rowid=item.pop('projection_cache_rowid');self.records[table,rowid]=item
        self.alternates=set();self.retrievals=set()
        if candidates:
            self.alternates={r[0] for r in conn.execute('SELECT r.raw_record_id FROM raw_network_records r WHERE r.raw_record_id IN ('+candidate_marks+') AND EXISTS (SELECT 1 FROM raw_network_records a WHERE a.room=r.room AND a.seq=r.seq AND a.raw_text_sha256=r.raw_text_sha256 AND a.raw_record_id<>r.raw_record_id)',candidates)}
            self.retrievals={r[0] for r in conn.execute('SELECT DISTINCT raw_record_id FROM evidence_retrievals WHERE raw_record_id IN ('+candidate_marks+')',candidates)}

    def joined_cache(self,raw_id,table):
        rows=[]
        for link in self.links.get(raw_id,()):
            if link['cache_table']!=table:continue
            row=self.records.get((table,link['cache_rowid']))
            # An inner compatibility join omits a dangling record; full candidate
            # proof independently rejects it, exactly as the scalar path does.
            if row is not None:rows.append(dict(row,projection_link_hash=link['raw_text_sha256']))
        return rows
