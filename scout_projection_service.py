"""Optional projection owner. Observation never waits for projection/publication."""
from pathlib import Path
import threading
import time
from scout_projection_contract import *
from scout_projection import Projector
from scout_projection_source import consume
from scout_projection_pins import import_pins
from scout_projection_publish import publish


class ProjectionService:
    def __init__(self,source,path,root,pin_path,diag,stop,cadence=900):
        require(cadence>=60,'Publication cadence must be at least 60 seconds')
        self.source=Path(source);self.path=Path(path);self.root=Path(root);self.pin_path=Path(pin_path)
        require(all(p.is_absolute() for p in (self.source,self.path,self.root,self.pin_path)),'Explicit absolute projection configuration required')
        self.diag=diag;self.stop=stop;self.cadence=cadence
        self.thread=threading.Thread(target=self.run,name='scout-projection-owner',daemon=False)

    def start(self):self.thread.start()
    def close(self):self.thread.join()
    def report(self,**values):
        with self.diag.lock:self.diag.values['router_projection']=values

    def run(self):
        try:
            with Projector(self.path,self.stop) as projector:
                last=projector.get('last_publication');age=max(0,(instant(utc())-instant(last)).total_seconds()) if last else self.cadence
                due=time.monotonic()+max(0,self.cadence-age);failures=int(projector.get('publication_failures','0'))
                while not self.stop.is_set():
                    try:
                        result=consume(projector,self.source)
                        if result['source_caught_up'] and time.monotonic()>=due:
                            require(not self.pin_path.is_symlink(),'Pin input symlink rejected')
                            with open(self.pin_path,'rb') as stream:raw=stream.read(4*1024*1024+1)
                            import_pins(projector,raw)
                            output=publish(projector,self.root,checked_cut=result['source_cut'])
                            due=time.monotonic()+self.cadence;failures=0
                            result=projector.status();result['readiness']=output['readiness']
                        if not result.get('source_caught_up',True):result['readiness']='NOT_READY'
                        self.report(**result)
                    except InterruptedError:break
                    except Exception as exc:
                        failures+=1;delay=min(self.cadence,15*2**min(failures,6))
                        self.report(readiness='NOT_READY',error=str(exc),failures=failures,retry_seconds=delay)
                        self.stop.wait(delay)
                    self.stop.wait(0.25)
        except Exception as exc:self.report(readiness='NOT_READY',error=str(exc))
