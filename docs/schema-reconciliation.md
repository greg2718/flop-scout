# Schema reconciliation: development report and unexecuted production plan

## Findings

The affected table is `source_coverage_state`. The required definition is
`origin_unknown INTEGER NOT NULL DEFAULT 0`.

The first repository commit containing the column is `4b996db` (2026-09-06
15:46:40 UTC), the initial coverage-worker commit. Production recorded v3 at
14:52:01 UTC with an earlier physical layout. The exact uncommitted edit time
cannot be recovered from Git. The old initializer returned solely on finding
version 3, so subsequent DDL additions were never applied. `CREATE TABLE IF NOT
EXISTS` alone would not add a column to an existing table either.

Read-only inspection on 2026-09-06 found these additional missing objects:

- `snapshot_facts_immutable`
- `snapshot_no_delete`
- `snapshot_no_replace`

No other required physical drift was detected. No production data/schema was
modified; no worker was restarted. Bench and Router remain outside this change.

## Contract and repair

`scout_schema.py` constructs the full evidence v1/v2/v3 contract from existing
DDL in an in-memory database. It compares actual table columns, order, types,
defaults, nullability, primary/unique keys, foreign keys, index definitions,
trigger definitions and table constraints/options. Required evidence tables,
indexes, columns and triggers are reported individually. Unexpected triggers on
contract tables are incompatible. SQL string-literal case is significant.
Version metadata and physical structure must both pass.

Writer initialization reconciles current-version drift before runtime queries.
`evidence schema-status` uses a read-only connection and skips home-directory
initialization. `evidence reconcile-schema --db PATH` uses an existing database
(mode=rw), acquires that state's Scout singleton lock, and performs no network or
identity access. Lock diagnostics go to stderr; results on stdout are JSON.

Reconciliation uses a SAVEPOINT, adds only the explicitly approved column,
restores missing named indexes/triggers and verifies the result before release.
Any error rolls back the entire reconciliation. Missing historical tables,
other missing columns, incompatible definitions, future versions or incomplete
version history fail closed with `SCHEMA_DRIFT`; no empty provenance replacement
or destructive rebuild is attempted. Version remains 3: this repairs the
already-declared contract, not a new logical version.

Existing raw records, parsed events, hashes, IDs, coverage positions, backfill
checkpoints, timestamps and version rows are unchanged. A second repair does
nothing. The newly added flag is the only value populated on historical rows.

## Historical origin semantics

The SQL default remains exactly `0`, as required for newly initialized rows.
Normal current-code creation uses its explicit imported/resume baseline; a
known generation transition explicitly sets the flag to `1`.

For rows predating the flag, reconciliation sets `origin_unknown=1`. This is a
conservative uncertainty marker, not a statement that a generation changed.
The earlier schema cannot prove which old rows were generation transitions.
Blindly applying default zero would permit subsequent exports to assert
retention loss across an unproven epoch origin. Existing flags are never reset
when repairing other objects. Migration itself advances no cursor and declares
no retention loss. Subsequent validated consecutive export processing uses the
existing unknown-origin baseline path, records its export provenance, and clears
the flag when resolved. This can deliberately forgo a retention-loss claim for
historical intervals whose origin cannot be established. Historical v2 gaps
remain immutable and separately reassessable.

## Validation

Final results: **290 tests passed**, self-test PASS, compilation PASS,
`git diff --check` PASS, temporary schema-status PASS and integrity PASS.
There are 19 new parameterized regression cases (271 prior cases).

Regression coverage includes populated v3 drift reproduction, column repair,
complete row/ID/hash/count preservation, idempotence, integrity PASS, read-only
CLI byte preservation, multiple missing objects, index/trigger restoration,
incompatible type/default/nullability/FK/constraint detection, wrong trigger or
index definitions, missing tables/other columns, rollback injection, real worker
startup initialization with a stubbed coordinator, CLI reconciliation, and
historical unknown-origin export behavior. All network calls are blocked in tests.

The temporary demonstration loads `HEAD:scout_coverage.py` as the old code,
reproduces `KeyError('origin_unknown')` after its version-gated initialization,
then runs the new CLI repair, schema-status, integrity and writer/query paths.
Artifact directory: `/var/folders/j3/shdns_9950b1yl5mwhl8_1j00000gn/T/scout-schema-validation-7f68un9o`.
It is also recorded in `/private/tmp/scout-schema-validation-path.txt`.
No production copy or production writes are used in that demonstration.

Run validation in this workstation's existing test dependency environment:

```sh
cd /Users/greg/Dev/flop_scout_v02
PYTHONPATH=/private/tmp/scout-test-deps .venv/bin/python -m pytest -q
FLOP_SCOUT_STATE_DIR=/private/tmp/scout-schema-selftest .venv/bin/python flop_scout.py self-test
PYTHONPYCACHEPREFIX=/private/tmp/scout-schema-pycache .venv/bin/python -m py_compile flop_scout.py scout_evidence.py scout_coverage.py scout_worker.py scout_schema.py
git diff --check
```

The repository venv lacks pytest; the existing temporary dependency directory
provides it without modifying the venv. Self-test uses ephemeral test signing
material and does not load a production identity.

Schema-status before repair reports version 3, the missing column and three
triggers above, `reconciliation_required: true`, and
`status: RECONCILIATION_REQUIRED`. After repair all missing/incompatible lists
are empty and status is `PASS`. Non-PASS status exits 1.

## Production commands — PLAN ONLY, NOT EXECUTED

Execute only during a later approved maintenance window. Do not run `flop-start`
or load `com.flop.scout.poll`. Do not restart Bench or Router. Stop at any failed
command or check. A backup alone is insufficient to restore referenced snapshot
files, so preserve those too. Use the same shell for the variables below.

### A. Stop only Scout and verify quiescence

```sh
cd /Users/greg/Dev/flop_scout_v02
SCOUT_PY=/Users/greg/Dev/flop_scout_v02/.venv/bin/python
SCOUT_DB=/Users/greg/.flop_scout/observer.sqlite
launchctl bootout gui/$(id -u) /Users/greg/Library/LaunchAgents/com.flop-scout.worker.plist
launchctl print gui/$(id -u)/com.flop-scout.worker
ps -axo pid,command | rg '[f]lop_scout.py.*worker run|[f]lop_scout.py.*service-poll'
lsof /Users/greg/.flop_scout/run/service-poll.flock
```

Expected: service not found, no worker/poller process and no flock owner. Those
absence commands may exit nonzero. Do not continue until the old process has
exited. The legacy `com.flop.scout.poll` label must also remain unloaded.

### B. Consistent backup, including snapshot files

```sh
SCOUT_BACKUP=/Users/greg/.flop_scout/backups/schema-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$SCOUT_BACKUP"
export SCOUT_BACKUP SCOUT_DB
"$SCOUT_PY" - <<'PY'
import os, sqlite3, shutil
from pathlib import Path
root=Path(os.environ['SCOUT_BACKUP'])
source=Path(os.environ['SCOUT_DB'])
with sqlite3.connect(source.as_uri()+'?mode=ro',uri=True) as src:
    with sqlite3.connect(root/'observer.sqlite') as dst:
        src.backup(dst)
        assert dst.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
snapshots=source.parent/'evidence'/'export-snapshots'
if snapshots.exists():
    shutil.copytree(snapshots,root/'export-snapshots')
print(root)
PY
```

Retain original snapshot paths for normal operation. A later restoration to a
different directory needs a separate reviewed path-handling plan; do not rewrite
immutable snapshot metadata to relocate it.

### C–F. Inspect, reconcile, verify

```sh
"$SCOUT_PY" flop_scout.py evidence schema-status --db "$SCOUT_DB" > "$SCOUT_BACKUP/schema-before.json"
```

Expected exit 1 for RECONCILIATION_REQUIRED. Inspect the JSON. Proceed only if
all drift is safe and understood; INCOMPATIBLE blocks this plan.

```sh
env -u FLOP_SCOUT_STATE_DIR "$SCOUT_PY" flop_scout.py evidence reconcile-schema --db "$SCOUT_DB" > "$SCOUT_BACKUP/reconciliation.json"
"$SCOUT_PY" flop_scout.py evidence schema-status --db "$SCOUT_DB" > "$SCOUT_BACKUP/schema-after.json"
env -u FLOP_SCOUT_STATE_DIR "$SCOUT_PY" flop_scout.py evidence verify-integrity --db "$SCOUT_DB" > "$SCOUT_BACKUP/integrity-after.json"
```

All three must exit 0. Stop on failure; leave Scout stopped for reviewed recovery.
Do not replace the live DB with its backup while any writer is running.

### G–H. Start only Scout; check resumed backfills

```sh
plutil -lint /Users/greg/Library/LaunchAgents/com.flop-scout.worker.plist
launchctl bootstrap gui/$(id -u) /Users/greg/Library/LaunchAgents/com.flop-scout.worker.plist
launchctl print gui/$(id -u)/com.flop-scout.worker
launchctl print gui/$(id -u)/com.flop.scout.poll
ps -axo pid,command | rg '[f]lop_scout.py.*worker run|[f]lop_scout.py.*service-poll'
lsof /Users/greg/.flop_scout/run/service-poll.flock
env -u FLOP_SCOUT_STATE_DIR "$SCOUT_PY" flop_scout.py service status
env -u FLOP_SCOUT_STATE_DIR "$SCOUT_PY" flop_scout.py evidence soak-status --db "$SCOUT_DB"
```

Require exactly one new Scout worker, one flock owner, old label absent, advancing
successful-poll timestamps and coverage/backfill checkpoints. Previous failure
counters are historical: assess new deltas and current errors, not total zero.

### I. Repeat the full 30-minute stack qualification

Run only after all prequalification checks pass. This records four checkpoints
at approximately 0/10/20/30 minutes; execute interactively and stop if a hard
blocker appears. No formal soak marker is created by this loop.

```sh
QUAL_DIR=/Users/greg/.flop_agents/soaks/qualification-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$QUAL_DIR"
date -u +%Y-%m-%dT%H:%M:%SZ > "$QUAL_DIR/start-utc.txt"
for minute in 0 10 20 30; do
  if [ "$minute" != 0 ]; then sleep 600; fi
  date -u > "$QUAL_DIR/time-$minute.txt"
  "$SCOUT_PY" flop_scout.py evidence schema-status --db "$SCOUT_DB" > "$QUAL_DIR/schema-$minute.json" || break
  env -u FLOP_SCOUT_STATE_DIR "$SCOUT_PY" flop_scout.py evidence verify-integrity --db "$SCOUT_DB" > "$QUAL_DIR/integrity-$minute.json" || break
  env -u FLOP_SCOUT_STATE_DIR "$SCOUT_PY" flop_scout.py evidence soak-status --db "$SCOUT_DB" > "$QUAL_DIR/scout-$minute.json" || break
  /Users/greg/Dev/flop_bench/.venv/bin/flop-bench worker health --state-dir /Users/greg/.flop_agents/bench > "$QUAL_DIR/bench-$minute.json" || break
  /Users/greg/Dev/flop-router/.venv/bin/python /Users/greg/Dev/flop-router/router.py worker status --state-dir /Users/greg/.flop_agents/router > "$QUAL_DIR/router-$minute.txt" || break
  ps -axo pid,lstart,command > "$QUAL_DIR/processes-$minute.txt"
  for label in com.flop-scout.worker com.flop.scout.poll com.greg.flop-bench.worker com.greg.flop-router.worker; do
    launchctl print gui/$(id -u)/$label > "$QUAL_DIR/$label-$minute.txt" 2>&1
  done
  tail -100 /Users/greg/.flop_scout/logs/worker-error.log > "$QUAL_DIR/scout-errors-$minute.txt"
  tail -100 /Users/greg/.flop_agents/bench/logs/worker.stderr.log > "$QUAL_DIR/bench-errors-$minute.txt"
  tail -100 /Users/greg/.flop_agents/router/logs/worker.stderr.log > "$QUAL_DIR/router-errors-$minute.txt"
done
```

Review all four checkpoints: Scout integrity/schema PASS, all safety counters,
cursor regressions and DB errors zero; backfills progressing/completing; no
unexplained unresolved coverage or repeated new failures. Bench must be healthy
with persistent state and no new fatal errors; Router must be healthy SHADOW,
network_writes=0 and private_key_accesses=0. Confirm exactly one worker per agent,
no crash loops, old Scout unloaded and no unexplained restarts. A completed loop
alone does not establish PASS.

### J. Only after documented qualification PASS, begin formal soak

This remains a separate later operational step. Record the reviewed decision:

```sh
printf 'PASS\n' > "$QUAL_DIR/qualification-result.txt"
export QUAL_DIR
SOAK_DIR=$("$SCOUT_PY" - <<'PY'
from pathlib import Path
from datetime import datetime,timezone,timedelta
import os,shutil
qual=Path(os.environ['QUAL_DIR'])
assert (qual/'qualification-result.txt').read_text().strip()=='PASS'
assert (qual/'time-30.txt').exists()
start=datetime.now(timezone.utc).replace(microsecond=0)
end=start+timedelta(hours=24)
root=qual.parent/start.strftime('%Y%m%dT%H%M%SZ')
root.mkdir(exist_ok=False)
(root/'start-utc.txt').write_text(start.strftime('%Y-%m-%dT%H:%M:%SZ')+'\n')
(root/'target-end-utc.txt').write_text(end.strftime('%Y-%m-%dT%H:%M:%SZ')+'\n')
shutil.copytree(qual,root/'qualification')
(root/'README.txt').write_text('FLOP 24-HOUR STACK SOAK\nQualification: PASS\n'
    'Scout: com.flop-scout.worker, persistent\nBench: com.greg.flop-bench.worker\n'
    'Router: com.greg.flop-router.worker, SHADOW\n'
    f'Start UTC: {start.isoformat()}\nTarget end UTC: {end.isoformat()}\n'
    'No code/launchd changes, network writes, claims, wallet or TCLK actions.\n'
    'No manual restarts unless failure requires them; record every restart/failure.\n'
    'Integrity must remain PASS.\n')
print(root)
PY
)
export SOAK_DIR
"$SCOUT_PY" - <<'PY'
import subprocess,os
from pathlib import Path
root=Path(os.environ['SOAK_DIR'])
scout=Path('/Users/greg/Dev/flop_scout_v02')
bench=Path('/Users/greg/Dev/flop_bench')
router=Path('/Users/greg/Dev/flop-router')
env=dict(os.environ);env.pop('FLOP_SCOUT_STATE_DIR',None)
def capture(name,args,cwd=scout):
    r=subprocess.run(args,cwd=cwd,env=env,text=True,capture_output=True)
    (root/name).write_text(r.stdout+r.stderr)
    if r.returncode: raise RuntimeError(name+' failed; record soak blocker immediately')
capture('scout-integrity.json',[str(scout/'.venv/bin/python'),'flop_scout.py','evidence','verify-integrity'])
capture('scout-baseline.json',[str(scout/'.venv/bin/python'),'flop_scout.py','service','status'])
capture('bench-baseline.txt',[str(bench/'.venv/bin/flop-bench'),'worker','status','--state-dir','/Users/greg/.flop_agents/bench'],bench)
capture('router-baseline.txt',[str(router/'.venv/bin/python'),'router.py','worker','status','--state-dir','/Users/greg/.flop_agents/router'],router)
parts=[]
for label in ('com.flop-scout.worker','com.flop.scout.poll','com.greg.flop-bench.worker','com.greg.flop-router.worker'):
    r=subprocess.run(['launchctl','print',f'gui/{os.getuid()}/{label}'],text=True,capture_output=True)
    parts.append(r.stdout+r.stderr)
for cmd in (['ps','-axo','pid,lstart,command'],['uptime'],['df','-h','/Users/greg']):
    r=subprocess.run(cmd,text=True,capture_output=True);parts.append(r.stdout+r.stderr)
for app,state in [('scout',Path('/Users/greg/.flop_scout')),('bench',Path('/Users/greg/.flop_agents/bench')),('router',Path('/Users/greg/.flop_agents/router'))]:
    for p in sorted(state.rglob('*')):
        if p.is_file() and p.name.endswith(('.db','.db-wal','.db-shm','.sqlite','.sqlite-wal','.sqlite-shm','.log')):
            parts.append(f'{p.stat().st_size} {p}')
    for p in (state/'logs').glob('*.log'):
        capture(app+'-'+p.name+'-tail.txt',['tail','-100',str(p)])
(root/'process-baseline.txt').write_text('\n'.join(parts)+'\n')
for app,repo in [('scout',scout),('bench',bench),('router',router)]:
    capture(app+'-git-status.txt',['git','status','--short'],repo)
print(root)
PY
```

Review the fresh baseline immediately. Any failed capture or health regression
invalidates the start and must be recorded as a blocker. Leave workers
launchd-owned; do not attach or start duplicates. This development task does not
start soak.

## Limitations

The verifier covers the evidence subsystem through v3, not every legacy Scout
cache table or other agents' schemas. SQL definitions are compared conservatively;
semantically equivalent but textually different expressions may require review.
Restored triggers protect future writes; they cannot retroactively prove that no
alteration occurred while absent. Existing evidence integrity remains a separate
required check. Missing historical tables are reported and blocked rather than
recreated empty. Startup can repair safe drift, but the explicit production plan
still requires quiescence, backup and review. Test artifacts use synthetic data;
actual production migration remains unvalidated until the later authorized run.
