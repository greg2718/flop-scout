"""Bounded reader-side preparation. No SQLite connection and no signing/key load."""
import hashlib
import json
from pathlib import Path
import scout_coverage as coverage
import scout_evidence as evidence
import scout_diagnostics as diagnostics


def prepare(room,records):
    import flop_scout as scout
    with diagnostics.operation('evidence_prepare',room):
        return {evidence.dumps([room,raw]):scout.verify_signed_record_offline(room,raw)
                for raw in records if isinstance(raw,dict)}


class ExportStream:
    """Owned exclusively by the one export-reader executor; bounded batches."""
    def __init__(self,snapshot,processed=0):
        self.room=snapshot['room'];self.generation=snapshot['generation']
        self.snapshot=coverage.inspect_export(snapshot['path'],self.room,self.generation,snapshot['source_endpoint'],
                                             f'https://technocore.chat/r/{self.room}/export',json.loads(snapshot['metadata_json']))
        if self.snapshot['sha256']!=snapshot['sha256']:raise ValueError('Export changed after validation')
        self.stream=Path(snapshot['path']).open('rb');self.position=0;self.digest=hashlib.sha256()
        self.done=False
        try:
            # Read/skipping is off the writer and scheduler, including resume.
            while self.position<processed:
                line=self.stream.readline(coverage.MAX_LINE_BYTES+1)
                if not line:raise ValueError('Export incomplete during resume')
                self.digest.update(line);self.position+=1
        except BaseException:
            self.close();raise

    def batch(self,size):
        records=[]
        try:
            with diagnostics.operation('export_parse',self.room):
                for _ in range(size):
                    line=self.stream.readline(coverage.MAX_LINE_BYTES+1)
                    if not line:
                        self.done=True
                        if self.digest.hexdigest()!=self.snapshot['sha256'] or self.position!=self.snapshot['record_count']:
                            raise ValueError('Export changed during processing')
                        self.close();break
                    if len(line)>coverage.MAX_LINE_BYTES or not line.endswith(b'\n'):raise ValueError('Export incomplete line')
                    self.digest.update(line);self.position+=1;records.append(json.loads(line))
            return records,prepare_page(self.room,records,generation=self.generation,source='export-backfill',
                endpoint=self.snapshot['source_endpoint'],
                metadata={**json.loads(self.snapshot['metadata_json']),'snapshot_id':self.snapshot['snapshot_id']},
                retrieved_at=self.snapshot['retrieved_at']),self.position,self.done
        except BaseException:
            self.close();raise

    def close(self):
        self.stream.close()


def prepare_page(room,records,*,generation=None,source='service-poll',endpoint=None,metadata=None,retrieved_at=None):
    """Reader-owned immutable inputs; no SQLite reads, writes or identity access."""
    import flop_scout as scout
    stamp=retrieved_at or scout.utc_now()
    cache=prepare(room,records)
    token=scout._VERIFICATION_CACHE.set(cache)
    items=[]
    try:
        for raw in records:
            values=evidence.prepare_record(room,raw,scout.verify_signed_record_offline,
                generation=None if (metadata or {}).get('generation_conflict') else generation,
                reported_generation=str(generation) if (metadata or {}).get('generation_conflict') else None,
                endpoint=endpoint,metadata=metadata,retrieved_at=stamp)
            row=dict(zip(('raw_record_id','source','source_endpoint','room','generation','reported_generation','seq',
                'network_timestamp','retrieved_at','nonce','sender_did','signature','raw_text','raw_text_sha256',
                'raw_record_json','signature_status','signature_error','did_mismatch','transport_metadata_json',
                'ingestion_schema','ingestion_version','created_at','legacy_record','raw_completeness'),values))
            items.append(dict(raw=values,row=row,event=evidence.prepare_event(row),
                compatibility=scout.prepare_compatibility(room,[raw],generation,source,stamp)))
        return dict(verifications=cache,items=items,retrieved_at=stamp)
    finally:scout._VERIFICATION_CACHE.reset(token)
