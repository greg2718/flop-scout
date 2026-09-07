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
            return records,prepare(self.room,records),self.position,self.done
        except BaseException:
            self.close();raise

    def close(self):
        self.stream.close()
