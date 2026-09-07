# SQLite checkpoint latency investigation and local correction

## Scope and decision

Production remains on commit `70a7af3`, Scout PID 64256. This task did not modify
the production database, restart workers, change launchd, access private keys,
commit, push, qualify production, or start a soak. All experimental writes went
to disposable copies under `/private/tmp/scout-sqlite-latency`.

The final read-only launchd/process check still showed Scout PID 64256 and
Router PID 5805. Bench was running as PID **65737**, replacing the supplied
37819; launchd listed its previous exit status as 1. This task did not signal,
restart, reconfigure, or otherwise intervene in Bench. The cause of that
process change was not investigated as part of this SQLite task.

The checkpoint failure mode is reproduced on a 39.27 GB production copy. Local
code now controls checkpoints and WAL admission, strengthens commit durability,
and exposes commit versus checkpoint latency. Production rollout still requires
review and a new qualification. Short offline benchmarks cannot establish
long-term production capacity.

## What caused the historical 24.36 / 104.32 second stalls?

Those measurements timed COMMIT, which includes SQLite's automatic checkpoint
hook. No filesystem trace or before/after WAL measurements were captured during
those two historical calls. Their exact split among checkpoint page copying,
WAL reads, sync, and other I/O therefore cannot be recovered honestly.

The deployed engine's configuration and the production-copy reproduction
establish automatic checkpoint backlog as a concrete cause of this class of
stall. In `copy-phase.jsonl`, releasing a pinned reader followed by a **one-row
transaction** produced this measured COMMIT:

| Component | Measurement |
|---|---:|
| Whole COMMIT | 21,725.09 ms |
| Checkpoint copy phase, SQLite CKPT_START → CKPT_DONE | 21,291.81 ms |
| Main-database page writes inside that phase | 18,867.76 ms |
| WAL page reads inside that phase | 2,405.50 ms |
| Main-database sync after copying | 427.08 ms |
| WAL sync | 1.95 ms |
| New WAL writes for this transaction | 2 calls, 8,240 bytes |
| Checkpoint pages copied | 93,544; 383,156,224 bytes |
| WAL file immediately before / after COMMIT | 491,079,312 / 491,087,552 bytes |

The component intervals overlap: do not add checkpoint-copy duration to its
contained read/write timings. A separate reproduction measured a 21,074.29 ms
auto-checkpoint COMMIT, and an explicit PASSIVE checkpoint took 18,394.41 ms.
These are actual I/O timings, not injected sleeps. The pinned-reader workload
is a controlled failure scenario, not proof that the historical 104-second
call had the same WAL size or component proportions.

## Engine and connection settings

The read-only production diagnostic used SQLite **3.51.0**. Reading a PRAGMA on
a new connection does not inspect another connection's private settings. The
writer source sets WAL, foreign keys, and a 5,000 ms busy timeout; it does not
set synchronous or automatic checkpoint policy. Compile options independently
confirm `DEFAULT_WAL_SYNCHRONOUS=1`, `DEFAULT_CKPTFULLFSYNC`, and
`DEFAULT_CACHE_SIZE=2000`.

| PRAGMA | Read-only diagnostic connection |
|---|---:|
| journal_mode | wal |
| synchronous | 1 / NORMAL |
| wal_autocheckpoint | 1000 |
| page_size | 4096 |
| page_count | 12,261,295 |
| freelist_count | 0 |
| cache_size | 2000 pages, approximately 8 MiB |
| mmap_size | 0 |
| temp_store | 0 |
| locking_mode | normal |
| busy_timeout | 5000 ms |
| fullfsync | 0 |
| checkpoint_fullfsync | 1 |

The preserved benchmark baseline is the previously verified SQLite API backup:
39,268,438,016 bytes, 9,587,021 pages, 2,421,213 raw records and parsed events.
It preserves the complete physical schema, indexes, triggers, historical
retrievals, and coverage state. It is production-sized, though smaller than the
live database at this later investigation.

## Measurement method and limits

`scripts/sqlite_vfs_probe.c` is a **diagnostic-only** delegating VFS wrapper,
loaded only by the offline benchmark. It does not change SQLite I/O behavior or
log SQL bindings, message content, or keys. It measures read/write/sync/truncate
and file-control calls and the checkpoint-copy phase. The ordinary Python SQLite
library and its settings are retained for the baseline reproduction. The probe
also supports abrupt exit during a specified checkpoint page write for crash
tests; production never loads it.

`scripts/benchmark_sqlite_latency.py` records statement elapsed time by table,
real COMMIT time without double counting context-manager commits, batch duration,
WAL file sizes, and explicit PASSIVE duration. The worker records transaction
lifetime, commit changes, snapshot work, and checkpoint operations independently.
SQLite `total_changes` includes metadata and trigger side effects; the reported
rows-per-commit metric is explicitly labeled accordingly.

VFS reads expose actual page I/O with mmap disabled. They are not an exact
`SQLITE_DBSTATUS_CACHE_MISS` counter. The deployed Python binding does not expose
that API. SQL execution timing includes index and trigger work; there is no
reliable per-index/per-trigger stopwatch in this binding. This report does not
invent that attribution. Snapshot file I/O is distinct from snapshot-table SQL.

## WAL and checkpoint strategy

SQLite's default automatic checkpoint executes on the thread doing COMMIT.
A long-lived reader can prevent checkpoint completion and WAL reuse. Once that
reader ends, the next tiny commit can inherit a very large page-copy job.
See [SQLite WAL operation and performance](https://www.sqlite.org/wal.html).

The persistent worker now uses:

- Exactly one evidence/DML writer; four tail readers and one export reader remain.
- `synchronous=FULL`, `wal_autocheckpoint=0` on that writer.
- A single checkpoint-only maintenance thread and connection, starting with PASSIVE and
  busy timeout zero. It performs no evidence DML or schema migration.
- A 4 MiB soft WAL threshold, a five-second time trigger, and at least one second
  between attempts. No checkpoint is admitted ahead of fetched tail pages or an
  active writer turn.
- Soft-threshold admission control: finish the already-fetched bounded pages
  before admitting a fresh burst, creating a maintenance slot. Readers may
  continue while ordinary maintenance is active.
- A 128 MiB **high watermark, not an absolute byte cap**. New tail/export
  admission stops; only already-admitted tails and critical failure bookkeeping
  may drain. Export/status writes cannot grow WAL indefinitely behind a pinned
  reader. Overshoot includes the finite admitted pipeline, not unlimited new
  traffic.
- A high-water maintenance turn retains a writer gap through completion so
  concurrent commits cannot prevent WAL recycling forever. The scheduler stays
  responsive; already-admitted reader work remains separate. After PASSIVE copies
  every frame, a high-water turn attempts RESTART with **busy timeout zero**.
  This checks that readers allow reuse, rather than treating copied frames as
  proof of reset. A busy result keeps admission paused and is retried after the
  cooldown. No FULL/TRUNCATE checkpoint or reader-wait loop is introduced.
- `journal_size_limit=4194304` lets SQLite trim unused WAL allocation only during
  its safe reset. There is no hot FULL/TRUNCATE checkpoint and no manual WAL
  unlink, truncation, or replacement.

PASSIVE is non-blocking with respect to waiting for lock holders; it is **not**
a bounded-duration I/O operation. Its result is checked for incomplete progress,
busy state, or error. Pending work survives incomplete attempts; retries are
cooled down. If a reader never releases its snapshot, finite disk and unlimited
lossless ingestion cannot both be guaranteed. The worker exposes BLOCKING WAL
pressure and stops new admission rather than exhausting disk or advancing a
cursor without evidence. Operator resolution of that reader/storage condition
is then required.

A complete checkpoint does not necessarily shrink the physical WAL file.
Telemetry distinguishes physical capacity from the logical log/checkpoint frame
counts returned by SQLite. PASSIVE completion alone does not prove that readers
have released the locks needed to recycle the WAL. Capacity reuse, concurrent commits during checkpoint,
and the high-water drain/recycle transitions have regression coverage.

## SQLite version safety

SQLite documents a WAL-reset race involving concurrent checkpoint and writer
connections through 3.51.2. The fix is in 3.51.3+, with backports 3.50.7 and
3.44.6. See [the official WAL-reset description](https://www.sqlite.org/wal.html#walreset).

`scout_checkpoint.concurrent_safe()` gates concurrent checkpoint/write admission
on those versions. The installed 3.51.0 build uses serialized maintenance and
reports `serialized_unpatched_sqlite`. No claim is made that the existing
single-writer automatic-checkpoint deployment suffered this race.

A temporary SQLite 3.51.3 library was built from the official amalgamation and
selected **only for benchmark subprocesses** using `DYLD_LIBRARY_PATH`.
Production's Python environment and system library were not modified. This is
not a production dependency installation method or a launchd change.

## Transactions, indexes, and triggers

Batch sizes 1, 5, 10, 25, 50, 100, and 200 were exercised through Scout's real
raw → derived → compatibility pipeline. Each ingestion batch has multiple
commits; a nominal record count is not a single-transaction size.

With automatic checkpointing disabled and FULL synchronous, measured per-commit
results were:

| Records in ingestion batch | Median ms | p95 ms | Maximum ms |
|---:|---:|---:|---:|
| 1 | 0.100 | 5.058 | 7.940 |
| 5 | 0.163 | 0.176 | 0.182 |
| 10 | 0.221 | 0.377 | 0.380 |
| 25 | 0.397 | 0.510 | 0.597 |
| 50 | 0.659 | 0.777 | 1.117 |
| 100 | 2.570 | 2.955 | 4.348 |
| 200 | 1.821 | 4.771 | 6.222 |

There is no demonstrated nonlinear record-count knee in this small sample.
The demonstrated nonlinear cost is accumulated checkpoint debt: a one-row
transaction can take over 21 seconds. Quantiles use the lower empirical rank;
these short runs do not estimate rare production tails.

The existing 25 ms adaptive write-turn budget remains. The next batch now also
shrinks aggressively after commit >250 ms, checkpoint >1 s, or tail queue age
>1 s. Commit feedback uses the slowest commit in the entire writer turn, not
merely the last commit. Growth remains limited to 2× per observation, with a
1–200-record range. Evidence ordering and coverage finalization are unchanged.

`dbstat` found these large objects:

| Object | Allocated bytes |
|---|---:|
| evidence_retrievals | 23,503,499,264 |
| raw_network_records | 4,857,417,728 |
| evidence_records | 2,614,202,368 |
| messages | 1,513,771,008 |
| observed_events | 1,329,176,576 |
| compatibility_evidence_links | 862,470,144 |
| retrieval_time index | 833,134,592 |
| raw composite unique index | 396,918,784 |
| raw_did index | 274,915,328 |

Retrieval history dominates storage. Raw/event/hash and compatibility indexes
add substantial page footprint, but size alone does not prove which index
caused a particular stall. Same-column indexes on raw and observed/retrieval
tables are on different tables, not redundant duplicates. The raw composite
unique index supports exact raw/hash linkage and cannot simply be dropped.
No index was dropped, deferred, rebuilt, or changed.

The query audit separates candidates from required ingestion lookups:

| Index group | Current purpose / decision |
|---|---|
| Raw/event unique and composite linkage keys | Identity, foreign keys, immutability and exact provenance; retain |
| `raw_position`, `raw_room_sequence` | Coverage/gap checks and compatibility-link lookup; retain |
| `event_content_hash`, `event_template` | Prior-content and template duplicate classification during derivation; retain |
| `raw_did`, `event_class` | DID reporting and filtered event feeds; secondary read-path indexes, not demonstrated latency culprits |
| `raw_time`, `retrieval_time` | Time reporting candidates for a separate usage/query-plan review; current `julianday(column)` predicates do not provide a simple bare-column range seek |

No report index is proven safe to defer across every supported consumer, and
no individually dominant maintenance cost was established. In particular,
changing reporting indexes is not justified by the measured COMMIT stall: its
21.3-second copy phase executes no index-maintenance SQL. A later index proposal
needs consumer/query-plan evidence plus provenance and report regressions.


Snapshot immutability triggers compare existing row fields and enforce checkpoint
bounds. Across 100 existing-row no-op checkpoint updates on a copy, total
statement latency including lookup and protections was 0.091 ms median and
0.247 ms maximum. This does not isolate trigger CPU from lookup CPU or benchmark
new snapshot file creation. Link-trigger query plans use `raw_room_sequence`
plus a small ordering operation; raw identity guards use indexed lookups.
No trigger executes inside the measured checkpoint-copy phase. All immutability
and linkage triggers remain intact.

## Filesystem and backup conditions

The host uses an internal APFS SSD, FileVault enabled, SMART reported Verified.
The diagnostic inspection found about 135 GB free in the APFS container.
Spotlight reported disabled; no Time Machine local snapshots were listed.
These checks do not establish the absence of every possible background scanner
or other source of I/O contention. A later validation-time memory check showed
24 GiB RAM and 4,718 MiB swap in use (of 6,144 MiB allocated). This is evidence
of memory/storage load during development, not a measurement taken during the
historical 104-second stall; no production cache tuning is inferred from it.

The production backup's allocated-block count was approximately its logical
size; it was not a tiny sparse file masquerading as a 39 GB database. Disposable
benchmark copies used APFS cloning. Shared extents mean summing `du` across clones
can overstate unique physical allocation; copy-on-write can itself affect writes.
Backups and export snapshots share the production volume. Their mere presence
does not prove ongoing interference; active scans/copying contend for bandwidth.
The earlier smoke `soak-status` took 320.6 s. Some offline worker runs here also
had a production-copy integrity scan active on the same volume; results include
that workload, rather than representing an isolated drive benchmark.

A small temporary-file test measured 1 MiB writes, fsync, and macOS F_FULLFSYNC:
fsync was 0.22–0.71 ms and F_FULLFSYNC 3.31–11.71 ms. This does not explain or rule
out occasional long syncs on a large database. The reproduced 21.7-second stall
was dominated by page copying, not its 0.43-second final sync.

No backups or evidence snapshots were deleted. Consider separately reviewed
archival/storage capacity planning for retrieval history and backups; do not
remove evidence or immutable provenance as a latency shortcut.

## Durability and recovery

The prior Apple WAL default was NORMAL, which can lose recently committed
transactions after power loss while remaining consistent. The corrected worker
uses FULL, adding a WAL sync to each commit before acknowledgment. Ordinary
process-crash recovery remains WAL-based. Hardware guarantees still depend on
the platform's sync implementation; `fullfsync` and `checkpoint_fullfsync` are
not weakened. See [SQLite synchronous semantics](https://www.sqlite.org/pragma.html#pragma_synchronous).

Raw evidence commits before derived/linkage work and coverage movement. There
is still one DML owner, one process singleton flock, and no sharing of connection
objects across owner threads. Maintenance never signs, fetches, posts, or opens
identity material. Failed/incomplete checkpoint work does not advance coverage.

Shutdown waits for bounded in-flight reader/writer work, joins maintenance, then saves final
status and closes the writer. Existing shutdown semantics do not finish every
queued page; incomplete pages leave coverage/resume state behind for replay.
No forced FULL/TRUNCATE checkpoint is requested.
SQLite may checkpoint during last-connection close; that close can still be slow
and is not force-killed to shorten shutdown. A crash leaves SQLite's WAL recovery
path intact. Backup/restore must preserve the DB and required WAL/snapshot data.

## Diagnostics

New fields include `sqlite_commit_ms`, `sqlite_max_commit_ms`,
`sqlite_checkpoint_ms`, `sqlite_max_checkpoint_ms`, `sqlite_checkpoint_mode`,
`sqlite_wal_bytes`, `sqlite_wal_pages`, `sqlite_wal_high_water`,
`sqlite_checkpoint_pending`, `sqlite_batch_size`, `sqlite_rows_per_commit`,
`slow_commit_count`, and `slow_checkpoint_count`. Connection settings, WAL sizes
around commits, transaction duration, checkpoint frame counts, errors, pressure,
and concurrency mode are also exposed in the existing lightweight sidecar.

Commit health is DEGRADED above 250 ms and BLOCKING above 10 s. Checkpoint health
is DEGRADED above 1 s and BLOCKING above 10 s. Active operations are included,
so a stuck commit becomes BLOCKING before it returns. The read-only diagnostics
CLI still does not open SQLite or load keys. Existing status commands remain
read-only but can be expensive; use sidecar diagnostics for frequent sampling.

## Validation and final benchmark

Measured results are recorded below. All artifacts
are under `/private/tmp/scout-sqlite-latency`; no production PASS is inferred.

### Five-minute replay on the installed engine

The **final code**, with the installed Apple SQLite 3.51.0, completed the same
five-minute production-copy workload using serialized maintenance. This is the
engine on which the complete 364-test suite passes.

| Metric | Installed engine, serialized maintenance |
|---|---:|
| Elapsed including orderly shutdown | 302.13 s |
| New raw records committed | 50,404 |
| Persistence throughput | 166.83 raw records/s |
| Commit observations | 17,359 |
| Commit p50 / p95 / max | 0.205 / 0.539 / 41.296 ms |
| Checkpoint turns | 256 |
| Checkpoint p50 / p95 / max | 132.514 / 254.217 / 1,589.003 ms |
| Maximum sampled pending-tail age | 3.147 s |
| Maximum completed full-page persistence age | 3.864 s |
| WAL allocation high-water | 50,721,352 bytes |
| Runtime errors / required safety counters | All zero |

The timed stop occurred with two partly persisted pages: 50,600 generated
records, 50,404 committed. The pending input was 78 lobby and 118 faucet records.
All nine rooms have contiguous newly inserted sequence ranges. Lobby/faucet
completed-page high-water marks (32581664 / 5142498) and coverage/resume cursors
(32535486 / 5120178) stayed behind the incomplete pages. No throughput credit
is given to the pending 196 records.
As with the concurrent replay below, these are finite offline tail-only runs,
not production qualification. Different queue/batch histories and shared-volume
I/O mean these runs are not a controlled proof that serialization always wins.
They do show that the local correction can be reviewed **without changing the
installed engine**. Serialized checkpoints still delay DML persistence for their
duration; scheduler/read execution remains separate. A rare slow device can
therefore still hurt freshness even though COMMIT no longer owns the checkpoint.

### Five-minute final worker replay on the diagnostic patched engine

The final run used patched SQLite 3.51.3 on a clone of the same production backup,
with the actual Runtime, nine configured rooms, production record templates,
real signature preparation and persistence, and simulated 100 ms GET response
latency. Sequences were advanced **only in the offline fixture**; no room data
was posted. Lobby/faucet supplied 200-record pages. This run isolates tail
persistence: export backfills were disabled in the benchmark settings, not in
production. Existing mixed tail/export regression tests also pass.

| Metric | Final measured result |
|---|---:|
| Elapsed including orderly shutdown | 302.41 s |
| New raw records committed | 44,599 |
| Persistence throughput | 147.48 raw records/s |
| Commit observations | 20,221 |
| Commit p50 / p95 / max | 0.151 / 0.713 / 59.232 ms |
| Maintenance turns (PASSIVE, RESTART when needed) | 243 |
| Checkpoint p50 / p95 / max | 87.259 / 434.812 / 1,776.772 ms |
| Maximum sampled pending-tail age, 1 s samples | 6.944 s |
| Maximum completed full-page persistence age | 7.109 s |
| WAL allocation high-water, tracked by coordinator | 160,581,152 bytes |
| Runtime errors | 0 |
| All nine required safety/error counters | 0 |

The fixture generated 44,600 records. The timed stop left the final lobby
record (32578264) uncommitted while its page was partly persisted. The copy
contains the preceding 26,399 new lobby records contiguously; completed-page
observed high-water remained at 32578064; the coverage/resume cursor remained
32535486 because pre-existing export recovery is still required. This is pending
replay after orderly stop, not
an assertion that all generated records committed. Throughput counts only
actual raw inserts. Full integrity checks the committed database.

WAL allocation repeatedly fell after safe recycling; the maximum is above the
128 MiB admission watermark because the already-fetched bounded pipeline is
allowed to drain. It is not an assertion of a hard 128 MiB file-size limit.
The completed-page figure is a better conservative freshness measure than the
one-second queue samples, which can miss brief peaks. Thus these results meet
the requested **commit** targets, but do not prove every preferred room-age
threshold: even this replay had a page take 7.109 seconds. Do not translate the
147 rows/s measured mix into a guaranteed sustainable production message rate.

An earlier two-minute same-engine 3.51.0 run with serialized maintenance measured
commit p95 0.516 ms / max 29.591 ms, checkpoint max 1,399.749 ms and sampled tail
age max 4.505 s. It predates the final WAL-pressure refinements and is not a
substitute for requalifying the final code on an approved deployment runtime.

### Tests and integrity

**364 tests passed** on the installed Apple SQLite 3.51.0 (337 baseline plus
27 new cases). The optional full-suite run using the temporary 3.51.3 library
returned **363 passed, 1 failed**: `test_read_only_status_bytes_unchanged`.
The same single test fails on unchanged `70a7af3` under that library. Only the
`-shm` digest changes; DB and WAL digests remain identical. SQLite read-only
connections can update WAL shared-memory bookkeeping. The existing test and
production read-only connection code were deliberately retained. Thus the
temporary library is useful for diagnostic measurements but is **not a
qualified drop-in production runtime**. Resolve and review this compatibility
contract before any patched runtime rollout; do not silently relax the test or
use `immutable=1` against a live database to make it pass.

New cases cover version
gating; threshold/time scheduling; urgent-tail priority; maintenance thread
ownership; readers continuing during a delayed checkpoint; partial/busy/error
results; retry cooldown; concurrent dirty epochs; hard-pressure admission;
recycled allocation; readers allowing PASSIVE copy while preventing RESTART;
nested active checkpoint BLOCKING status; draining admitted tails; writer gaps for recycling;
aggressive batch shrink and cautious growth; exact commit counting; active
>10-second BLOCKING status; and pending-WAL shutdown.

NORMAL and FULL crash tests terminate the test process during the **fifth actual
checkpoint database-page write**, reopen the database, and check physical
integrity, foreign keys, and all 1,000 raw/parsed links. These test process-crash
recovery, not physical power-cut behavior. The original raw-first crash/restart,
coverage, immutable snapshot, and mixed tail/export tests remain passing.

Self-test, compilation, and whitespace checks pass. The final full
production-copy evidence-integrity results are recorded below.
The final verification invokes the unchanged `scout_evidence.integrity`
predicates on a read-only, quiescent copy with a 256 MiB read cache and 1 GiB
mmap ceiling, and additionally runs SQLite `integrity_check`. These are
verification-connection settings only; ingestion benchmarks retain the settings
reported above. Earlier default-cache CLI checks on `manual-full.sqlite` and
`final-runtime.sqlite` were stopped as redundant once the final-copy checks
were running, to reduce shared-volume contention. They produced no completed
verdict and are not counted as PASS. Their unfinished artifacts are retained.

### Completed final-copy integrity

`restart-integrity.json` reports **PASS** for 2,465,812 raw records and the same
number of parsed events. Orphaned events, hash mismatches, raw identity
mismatches, missing events, sequence conflicts, unlinked compatibility records,
source-gap errors, coverage-integrity errors, and foreign-key errors are all
**zero**. SQLite's separate full physical `integrity_check` returned **`ok`**.
The single historical signature-failure record is retained; it is not a new
benchmark safety action or an integrity mismatch. This check included all
806 preserved snapshots and 18,379,256 processed snapshot records.

`serialized-integrity.json` independently reports **PASS** for the installed
Apple SQLite 3.51.0 replay: **2,471,617 raw records and 2,471,617 parsed events**.
Every required integrity error count is zero, including orphaned events, hash
mismatches, coverage errors, source-gap errors, and foreign-key errors. Raw
identity mismatches, missing events, sequence conflicts, and unlinked
compatibility records are also zero. The same single historical signature
failure remains. This run used the unchanged full evidence-verification
predicates, including every preserved snapshot; it did not repeat the separate
physical SQLite scan already completed on the other final production-size copy.

Development validation is complete. The installed-engine serialized candidate
is ready for review, **not deployed or production-qualified**. No benchmark or
verification process remains running. The optional patched-library read-only
compatibility failure remains explicitly unresolved; it does not affect the
364-pass installed-engine suite.

## Reproduction commands

All commands below target disposable local copies. Keep the verified baseline
unchanged. Do not substitute the production database path.

```sh
clang -shared -fPIC -O2 scripts/sqlite_vfs_probe.c -lsqlite3 \
  -o /private/tmp/scout-sqlite-latency/probe.dylib
cp -c /private/tmp/scout-sqlite-latency/baseline.sqlite \
  /private/tmp/scout-sqlite-latency/reproduce.sqlite
.venv/bin/python scripts/benchmark_sqlite_latency.py \
  --db /private/tmp/scout-sqlite-latency/reproduce.sqlite \
  --output /private/tmp/scout-sqlite-latency/reproduce.jsonl \
  --repeats 25 --pin-reader
```

The official diagnostic-only 3.51.3 source archive was
`https://www.sqlite.org/2026/sqlite-amalgamation-3510300.zip`, SHA-256
`acb1e6f5d832484bf6d32b681e858c38add8b2acdfd42ac5df24b8afb46552b4`.
The temporary library used `SQLITE_THREADSAFE=1`,
`SQLITE_DEFAULT_WAL_SYNCHRONOUS=1`, `SQLITE_DEFAULT_CACHE_SIZE=2000`,
`SQLITE_DEFAULT_CKPTFULLFSYNC=1`, and `SQLITE_ENABLE_DBSTAT_VTAB`. This reproduces
the relevant settings, not every Apple vendor build option.

```sh
cp -c /private/tmp/scout-sqlite-latency/baseline.sqlite \
  /private/tmp/scout-sqlite-latency/replay.sqlite
SCOUT_BENCH_SECONDS=300 \
DYLD_LIBRARY_PATH=/private/tmp/scout-sqlite-latency/patched \
  .venv/bin/python scripts/benchmark_worker_persistence.py \
  /private/tmp/scout-sqlite-latency/replay.sqlite
```

Artifacts include settings, schema/dbstat, SQL/VFS measurements, batch-size
results, filesystem sync samples, `serialized-runtime-results.json` and
`restart-runtime-results.json` with corresponding samples for the final replays,
tests, and
integrity outputs. The initial `auto.jsonl` was superseded by `auto-fixed.jsonl`
after correcting nested context-manager timing in the **benchmark**; use the
latter for distributions. The production timing wrapper has a corresponding
regression test preventing double counting.

## Production rollout plan — not executed

1. Review this change and the benchmark limits, including pinned-reader
   backpressure and the actual 7.109-second page maximum. The installed engine with serialized
   maintenance is the fully test-passing candidate. Any concurrent alternative
   requires a supported patched runtime and resolution of the shared-memory
   read-only test compatibility; do not deploy the temporary
   `DYLD_LIBRARY_PATH` benchmark setup as a dependency-management shortcut.
2. In a later authorized maintenance window, stop only `com.flop-scout.worker`,
   verify process/flock quiescence, and take a SQLite API backup plus required
   snapshot/config artifacts. Keep Bench/Router unchanged and the old poller
   unloaded. Verify backup and production schema/evidence integrity.
3. Deploy reviewed code/runtime with the existing state and DID. No schema or
   index migration is introduced. Start only the canonical Scout service.
4. Inspect fresh diagnostics: FULL synchronous, auto-checkpoint zero, PASSIVE/RESTART
   mode as appropriate, correct version/concurrency gate, WAL recycling, healthy commit status,
   bounded queues, and all safety counters zero. Treat any >5-second commit,
   repeated high-water stalls, checkpoint error, or lost tail freshness as a
   blocker, even if the scheduler heartbeat is healthy.
5. Repeat smoke and 30-minute full-stack qualification only when separately
   authorized. Preserve real 0/10/20/30 sampling times. Large live integrity/status
   readers can pin WAL or contend for I/O and force backpressure; explicitly
   review how to obtain coherent integrity snapshots without turning those
   checks into sustained ingestion starvation. Do not quietly weaken integrity
   requirements or assume the existing expensive commands are harmless.
6. No formal soak until every actual qualification gate passes. Production-scale
   simultaneous export recovery and long-running readers still need operational
   validation; the tail-only replay does not establish that result.

## Rollback plan — not executed

Stop only Scout and verify the singleton is released. Preserve the database,
WAL, snapshot files, and new evidence. Return the reviewed code/runtime to the
known `70a7af3` deployment and restart only Scout after schema/integrity checks.
The checkpoint and synchronous settings are connection-local; the old worker
will use its prior defaults. No data/index/schema rollback is required. Do not
restore an older database over newly collected evidence merely to roll back
code, and never delete a WAL file manually. Leave healthy Bench and Router
running; keep the old Scout poller unloaded.

### Additional statement-cost observations

On the new-record FULL benchmark, raw inserts averaged 0.598 ms (max 2.898 ms),
event inserts 0.065 ms (max 1.153 ms), evidence-record inserts 0.258 ms
(max 1.746 ms), and compatibility message inserts 0.019 ms (max 1.856 ms).
These include their applicable indexes/triggers; they do not individually time
every index. A separate **exact-record re-read** benchmark exercised 1,173
retrieval-history inserts: mean 0.006 ms, max 0.600 ms. Its COMMIT max was
2.772 ms. Existing-event replay did not insert new events. Compatibility-link
trigger work is included in its parent statements, rather than falsely
reported as a separately measured zero. Snapshot/coverage tables were retained
and exercised by the targeted trigger test and real Runtime tests respectively.

Read-only compatibility note: the installed Apple SQLite build could not open
one closed WAL-format copy without sidecars using `mode=ro`; the patched
benchmark engine could. Final-copy integrity uses that same patched engine.
`immutable=1` was used only for small measurements on known quiescent copies,
never on the live production database. The production read-only CLI architecture
has not been replaced with immutable/live-DB access or writable status queries.
