# Persistent worker global-stall correction — not deployed

## Production evidence and root cause

Read-only inspection of the production evidence database found 200-record tail
persistence cycles lasting 104.48, 110.92, 155.22 and 165.30 seconds. One cycle
lasted 465.28 seconds (01:25:35–01:33:20 UTC on September 7). These timestamps
bracket `service_poll_room` processing; HTTP had already returned to the reader
future before that function was called by the worker. This proves that network
export download alone cannot explain the global stalls.

A read-only macOS `sample` of the existing worker (PID 25490, September 7
01:41:31 UTC, three seconds, 262 samples) showed the main thread inside SQLite
inserts/index/page I/O, automatic WAL checkpointing and filesystem syncs during
commit, and signature verification. In one subtree, 39 samples were in
`sqlite3WalDefaultHook -> sqlite3_wal_checkpoint_v2`, including 34 filesystem-sync
samples. Production had 8,729,719 pages of 4,096 bytes, about 35.76 GB, at inspection.
The sample is retained at `/private/tmp/scout-global-stall-sample.txt`.

The architectural cause is confirmed: the scheduler thread synchronously ran the
whole evidence pipeline, including SQLite commit/checkpoint I/O. No asyncio loop
exists. A synchronous 200-record limit did not impose a time bound. The previous
fairness model assigned milliseconds to this work and therefore missed production
I/O behavior. Large export revalidation/parsing was another synchronous path.

The short native sample cannot attribute every historical 100–465-second incident
to a particular SQL statement or distinguish disk contention from every other
cost. New operation timings are required during the next approved production
qualification. No profiler or instrumentation was injected into the live Python
process; `sample` only read its stacks. No production database changes or restarts
were performed.

## Complete execution map

| Operation | Previous persistent worker | Corrected persistent worker |
|---|---|---|
| Deadline selection, queue admission, retry timestamps | Main scheduler/SQLite coordinator | Main scheduler; cached metadata and bounded futures only |
| Tail HTTP read and response JSON decoding | Four reader threads | Same four reader threads |
| Export HTTP streaming, temporary writes, fsync, rename | One export reader | Same single export reader |
| Initial export validation/hash/JSON parsing | Export reader | Export reader |
| Revalidation before persistence; resumed-file scanning | Main coordinator | Export reader |
| Export batch JSON decoding | Main coordinator | Export reader, bounded batches |
| Signature verification | Main coordinator, including repeated compatibility verification | Reader-side preparation; exact-record cached verdict reused by writer |
| Raw identity/hash/envelope construction | Main coordinator | Bounded SQLite-owner turn; preparation also computes exact cache keys |
| Event derivation, duplicate analysis, compatibility links | Main coordinator | Dedicated SQLite owner; bounded record turns |
| SQL inserts, indexes/triggers, transaction commit/checkpoint | Main coordinator | One dedicated SQLite owner |
| Coverage computation, gap reassessment, checkpoint finalization | Main coordinator | SQLite owner, measured separately |
| Schema verification and writer initialization | Main before scheduling | SQLite owner during startup; main heartbeat remains responsive |
| Room/coverage metadata queries | Main on each scheduling pass | SQLite owner; main consumes returned copies |
| Scheduler telemetry formatting | Main plus SQLite commit | Small in-memory main snapshot; DB copy only when writer is available |
| Watchdog/slow-operation telemetry file | Absent | Dedicated watchdog thread, no SQLite dependency |
| Snapshot file close during orderly shutdown | Main/coordinator | Reader cleanup during operation; final closes only after reader quiescence |

There is no asyncio event loop or `asyncio.to_thread`. The logical scheduler loop
uses controlled executors. Reader concurrency remains **four tails plus one
export** by default; it was not increased. There is one additional SQLite-owner
thread and one watchdog thread. SQLite thread checks remain enabled. The
process-wide Scout singleton flock remains held for the worker lifetime; it
prevents a second Scout writer process. It is not held/released per record.
The legacy synchronous `Coordinator`/single-sweep helper remains for bounded
manual paths and compatibility tests; production `worker run` uses `Runtime`.

## Instrumentation and watchdog

`scout_diagnostics.py` records nested active operations, elapsed durations,
maximums, counts and totals. It retains at most 64 recent slow operations and
32 stall events; status shows the ten slowest retained operations. It records
operation labels and room names, never SQL bindings, room message bodies or keys.

A watchdog wakes every 250ms and checks main-scheduler heartbeat age independently
of the writer. `event_loop_lag_ms` is lateness beyond the 250ms heartbeat allowance;
`event_loop_max_lag_ms` preserves the maximum. HEALTHY means heartbeat age <=500ms,
DEGRADED means >500ms through 2s, and STALLED means >2s. A stall emits a bounded
`EVENT_LOOP_STALL` event, not a crash. Watchdog wake-up lag is separately exposed
so GIL/process scheduling pauses can be distinguished from a blocked SQLite owner.
Worker lifecycle is STARTING/RUNNING/STOPPING/STOPPED.

Status includes:

- `scheduler_tick_age`, `scheduler_tick_duration` (last scheduler body duration)
- `event_loop_lag_ms`, `event_loop_max_lag_ms`, `event_loop_health`
- `sqlite_queue_wait_ms`, `sqlite_max_queue_wait_ms`, `sqlite_write_duration_ms`,
  `sqlite_max_write_duration_ms`; detailed commit/statement timings
- `export_fetch_duration_ms`, `export_parse_duration_ms`, `export_persist_duration_ms`
- `tail_fetch_duration_ms`, `tail_persist_duration_ms`, plus full-page persistence
  duration and maximum
- `snapshot_write_duration_ms`, signature, derivation and coverage-operation timings
- `tail_read_queue`, `tail_persist_queue`, `backfill_queue`, `sqlite_queue`,
  `oldest_tail_queue_age`, `oldest_backfill_queue_age`
- `active_operation`, `current_active_operation`, `current_active_room`,
  `current_active_operation_started_at`, and `slowest_recent_operations`
- `backfill_failures_by_class`, `backfill_failures_by_room`
- `sqlite: {queue_depth, max_wait, max_write_duration}` and existing room SLA metrics

Duration fields describe the latest named operation/turn; `_max_duration_ms`,
`_total_duration_ms` and `_count` accompany instrumented operations. Nested durations
are inclusive and must not be added together. Active timestamps are Unix seconds.
Backfill failure-class counters are explicitly current-runtime scoped; cumulative
historical evidence counters remain separate.

The watchdog writes a bounded atomic JSON sidecar at
`STATE_DIR/run/worker-diagnostics.json`. Diagnostic telemetry is not evidence and
is not fsynced; evidence/snapshot durability remains unchanged. Readers expose
file age and continue aging the heartbeat if the worker stops. An unavailable
sidecar is UNKNOWN, never implicitly healthy.

Use the new lightweight read-only command when SQLite or full count queries are
slow. It does not open SQLite, initialize home, load identity, or access network:

```sh
/Users/greg/Dev/flop_scout_v02/.venv/bin/python /Users/greg/Dev/flop_scout_v02/flop_scout.py worker diagnostics --state-dir /Users/greg/.flop_scout
```

`service status` and `evidence soak-status` also expose these fields, but their
existing evidence-count queries can themselves be expensive on a large database.

## Persistence and preparation correction

`Runtime.step` never waits on a not-yet-completed reader or writer future. Tail
network/preparation admission is bounded to four futures; fetched/active pages
are bounded to twice configured tail concurrency, one outstanding page per room.
There is one export stream, one prepared export batch, and one admitted SQLite
turn. Export cleanup finishes before admitting another slow-reader operation.
Pending backfills remain one entry per configured room and retain FIFO turns.

Completed tail pages have latency priority. A partially persisted page rotates
behind other already-fetched pages. After at most 16 tail turns, one ready export
turn may run so continuous tails cannot eliminate recovery progress. Failures
are queued as critical state transitions and use per-source scheduled backoff;
there is no central retry sleep. The scheduler's 10ms idle wait is interruptible.

Both tail and export persistence start at one record per turn and adapt toward a
25ms measured writer budget, capped at 200 records. Batch sizes grow at most 2x
per observation and shrink immediately after a cost increase. A modeled workload
where 200 export records would take 30 seconds therefore starts with one 150ms
record rather than blocking for an initial 200-record turn. Raw-first commit,
derived/link creation, compatibility indexing and durable checkpoint ordering
are retained. Coverage advances only after all page evidence is durable.

Export JSON parsing and signature preparation run on the export reader. Tail
signature preparation runs on the tail reader. Cached verification is keyed by
room and the exact serialized raw record; changed signed content cannot reuse a
verdict. Raw IDs, hashes, classification and signature semantics are unchanged.
Full export validation still checks endpoint/generation, framing, bounds and
hash. Streaming consumption independently checks final hash/count before export
coverage finalization. Resume skips/reads occur off the scheduler and writer.

The SQLite owner re-reads current coverage at export finalization, preserving
same-room tail progress and generation isolation. No multi-writer connection,
weaker synchronous mode, disabled integrity check, or schema version change is
introduced. Automatic SQLite WAL checkpoint behavior remains enabled and timed.

## Snapshot I/O

Downloads were already streamed to a temporary file and fsynced on the export
reader. The former extra validation and batch parsing on the main thread were
moved off it. Canonical snapshots now retain their inode/mtime when an identical
snapshot is fetched again: the existing file's hash must match before the new
temporary duplicate is discarded. An existing mismatched file fails closed.
No giant JSON serialization or full-file copying is added. A new capture still
requires a bounded download and validation; unchanged content cannot safely be
assumed before reading it. Evidence-file fsync guarantees remain intact.

## The 16 qualification failures

Read-only audit matching failed-count increments 26 through 42 found:

| Room | BACKFILL_UNRESOLVED outcomes |
|---|---:|
| lobby | 6 |
| tclk-offers | 4 |
| faucet | 3 |
| kibble | 3 |

They occurred from 2026-09-07 00:27:48 through 01:34:02 UTC. All 16 snapshots were
nonempty and consecutive. Every recorded coverage cursor reached or exceeded
that snapshot's last sequence. Under the existing finalization conditions, their
remaining failure was pending coverage beyond the captured export, not failure
to parse/persist that export. They map to **COVERAGE_CONFLICT**, with the historical
counter's UNRESOLVED meaning preserved. No failures are relabeled as successes.

New runtime failures distinguish HTTP_TIMEOUT, HTTP_429, HTTP_503,
GENERATION_MISMATCH, EXPORT_INCOMPLETE, SNAPSHOT_IO_ERROR, SQLITE_BUSY,
SQLITE_ERROR, COVERAGE_CONFLICT, PARSE_ERROR, WORKER_SHUTDOWN and OTHER. Failure
handling does not reset unrelated deadlines or create immediate retry loops.

## Validation and results

The complete suite has **337 passing tests**: 308 baseline plus 29 new regression
cases. Self-test, compilation and whitespace checks pass. Tests use temporary
state and block live network. Threaded tests run the real persistence pipeline
with fixture readers and assert a single distinct SQLite writer thread, reader
separation, raw/event/export integrity PASS, zero safety counters, exact cache
binding, checkpoint resume without redownload, generation-safe interleaving and
unchanged canonical snapshots.

A deterministic 2,400-second timing model exercises the actual Runtime admission,
futures, queue selection and adaptive-budget logic. The storage timing model is
explicitly synthetic; it does not claim to benchmark 840,000 real SQLite inserts.
Each export contains 40,000 modeled records and has 30s parsing, 30s snapshot I/O
and 30s verification delay on the slow executor. Slow regions cost 150ms per
export record before returning to normal cost. Lobby/faucet supply 200-record
tails continuously. Separate threaded gate tests inject 30 simulated seconds
inside parse, snapshot-write, verification and SQLite operations.

| Room | Maximum modeled successful-poll age |
|---|---:|
| lobby | 1.38s |
| faucet | 2.32s |
| technocore | 20.26s |
| kibble | 20.26s |
| tclk-offers | 30.26s |
| consensus_layer | 60.25s |
| quiet | 60.24s |
| mb-flop-scout | 60.25s |

- Main-loop maximum lag: **0ms beyond the 250ms allowance** (10ms controlled ticks).
- Maximum modeled SQLite turn: **152ms** (one slow record plus commit cost).
- Maximum fetched-tail queue age: **170ms**.
- Maximum pending backfill age: **901.08s**; long jobs delay later backfill turns,
  while tail observation remains current.
- Maximum tail persistence queue: **4 pages**; SQLite pending queue: **4 jobs**.
- Reader/writer admitted work: at most 4 tail jobs, 1 export job, 1 SQLite job.
- Backfills: **21 completed**, **840,000 modeled records** processed.
- All room maxima remain below 2x target: no STARVED or sustained DEGRADED source
  in the timing model. Integrity PASS/zero safety are separately established by
  the real threaded persistence fixtures, not inferred from this model.

## Hard limits and remaining production uncertainty

A single SQLite call or fsync cannot safely be preempted. If one commit takes
30 seconds, the scheduler and watchdog remain responsive, but queued persistence
still waits for the one owner. A fault test explicitly verifies this condition:
writer duration >=30 simulated seconds, scheduler lag below 500ms, queued tails
visible, and integrity PASS after shutdown. Adaptive record limits cannot make
an indivisible I/O operation faster. Consequently these changes do **not** prove
that production storage can sustain the requested cadence or qualify the stack.

Likewise, a CPU extension holding the GIL can delay all Python threads; watchdog
wake-up lag exposes that case. Export validation/finalization remains finite
but can be costly; final coverage queries remain on the SQLite owner. Existing
large raw/retrieval data is preserved, not compacted or deleted. Full integrity
scans and backups can contend for disk bandwidth. Diagnose measured production
operation timings before changing durability, reader concurrency or retention.

Shutdown stops admission, cancels queued reads, waits for bounded running work
and the admitted writer turn, and preserves committed checkpoints. It does not
force-kill the SQLite owner or discard evidence to shorten shutdown.

## Later deployment plan — not executed

1. Review this change, the new runtime path and the operation timings. Do not start
   soak. Keep Bench and Router unchanged and the old Scout poller unloaded.
2. In a separately approved maintenance window, stop only `com.flop-scout.worker`.
   Verify its process/flock are gone, then take a consistent SQLite backup plus
   export snapshots using the existing migration runbook.
3. Run schema-status and verify-integrity, both PASS. This correction adds no
   physical schema migration. Start only the existing Scout launchd worker.
4. Immediately inspect `worker diagnostics`: RUNNING lifecycle, fresh heartbeat,
   one SQLite owner, bounded queues, and operation timing populated. Check that
   ordinary tails continue while export preparation is active.
5. Repeat full-stack qualification at 0/10/20/30 minutes. Capture lightweight
   diagnostics frequently between checkpoints, not only after expensive integrity
   scans. Require every room's successful-tail count to increase, no STARVED or
   sustained DEGRADED room, loop lag under the documented allowance, bounded queue
   ages, explained failure-class deltas, integrity/schema PASS and zero safety,
   cursor-regression and database-error counters.
6. If long commits/checkpoints remain, stop qualification and report their measured
   durations/queues. Do not weaken durability or add SQLite writers to mask them.
7. Only after a separate reviewed qualification PASS may formal soak be considered.
   No deployment, launchd change, restart, commit, push or soak occurred here.

Validation artifacts are saved at
`/private/tmp/scout-global-stall-validation-sljtrizs`: the read-only production
stack sample, modeled 40-minute results, and separate real threaded fixture
integrity/safety outputs. That real fixture contains 502 raw records and 502
parsed events, with all integrity error counts and safety counters zero.
