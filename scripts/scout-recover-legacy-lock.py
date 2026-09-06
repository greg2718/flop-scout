#!/usr/bin/env python3
"""One-time local migration. Scheduling must be quiesced by the operator first."""
import argparse
import fcntl
import os
from pathlib import Path
import re
import subprocess


def recover(state, scheduler_quiesced):
    if not scheduler_quiesced:
        raise SystemExit('Refusing migration: first quiesce scheduled and manual launches; pass --scheduler-quiesced')
    run = Path(state)/'run'
    legacy = run/'service-poll.lock'
    if not legacy.exists():
        return
    if legacy.is_symlink() or not legacy.is_dir():
        raise SystemExit('Refusing migration: legacy lock is not a plain directory')
    with (run/'service-poll.flock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit('Refusing migration: active poll lock held')
        processes = subprocess.run(['/bin/ps','-axo','pid=,command='],check=True,
                                   capture_output=True,text=True).stdout
        for line in processes.splitlines():
            fields=line.strip().split(None,1)
            if len(fields)!=2 or int(fields[0])==os.getpid():
                continue
            command=fields[1]
            if re.search(r'(?:^|[ /])scout-service-poll\.sh(?:\s|$)',command) or re.search(r'flop_scout\.py\s+service-poll(?:\s|$)',command):
                raise SystemExit('Refusing migration: Scout service-poll process is active')
        # Never recursively delete contents: unexpected state requires inspection.
        legacy.rmdir()
        print('LEGACY_STALE_LOCK_RECOVERED',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir',type=Path,default=Path(os.environ.get('FLOP_SCOUT_STATE_DIR',str(Path.home()/'.flop_scout'))))
    parser.add_argument('--scheduler-quiesced',action='store_true')
    args=parser.parse_args()
    recover(args.state_dir,args.scheduler_quiesced)
