# Persistent worker fairness correction (not deployed)

## Root cause and reproduction

The old scheduler chose `(fixed priority, due time, room)` and selected an export
*instead of* a tail whenever coverage needed backfill. There was one export slot.
All other backlogged rooms were skipped while that slot was occupied. A completed
high-priority job could requeue ahead of every older low-priority deadline. Tail
backlog also reset the shared due time to now. Export completion updated the same
health timestamp and cadence as tail polling, so export activity could look like
fresh tail observation.

A deterministic temporary-database reproduction ran the unmodified scheduler
for 2,400 simulated seconds. All rooms required export; completing a job left
more backlog. Lobby received 2,400 export turns; faucet, technocore, kibble,
tclk-offers and consensus_layer received zero. Their deadlines stayed at zero.
`test_legacy_fixed_priority_export_admission_starves_for_forty_minutes` freezes
that admission-policy reproduction without waiting in real time.

The SQLite writer was already serialized and export ingestion already yielded
at 200-record checkpoints. Those properties did not prevent starvation at
admission. The old active-room set also excluded a source from polling throughout
its export download/processing, and export failures changed its tail backoff.

## Scheduling policy and bounds

Tail reads now use earliest-deadline-first. Configured priority breaks ties only.
A source whose deadline is old outranks any source that just became due. A
completion gives that source a future deadline; it cannot jump ahead of an older
waiting source. The finite configured room set, one outstanding tail per room,
and bounded admitted futures prevent newly arriving work from overtaking old
work indefinitely, assuming admitted reads and persistence operations finish.
This is fairness under finite service time, not a promise that requested
cadences are attainable on an overloaded machine.

The normal cadence is measured from successful persistence completion. Tail
failure applies per-source backoff and honors Retry-After. Backoff makes that
source temporarily ineligible; it changes no other source's deadline.

There are independent fast and slow readers:

- Up to `--concurrency` tail futures, one per room, with at most 200 records each.
- One extra export reader and at most one downloaded/processing export snapshot.
- At most one pending backfill entry per configured room; FIFO insertion order.

Thus default concurrency 4 now means at most **five network reader threads**:
four tail readers plus one export reader. At concurrency 1 a stuck export still
cannot occupy the tail slot. ThreadPoolExecutor's internal unbounded queue is
not filled without bound: submission is capped explicitly by those limits.

Backfill does not change tail deadlines or tail freshness. Tails may observe the
same source during its export. An export finish/failure removes its FIFO entry;
if more work remains it rejoins the back on discovery. A cooling-down or
refresh-blocked entry is skipped without moving it behind newcomers. FIFO order
and export retry state are saved in operational status and restored on restart.
Repeated lobby/faucet exports therefore cannot monopolize eligible backfill
turns. Failed export work remains discoverable from durable coverage state and
cannot remove a room from tail scheduling.

## SQLite interleaving and epoch safety

Only the coordinator thread uses the SQLite connection. Reader threads return
responses/files and never persist them. Each loop persists admitted completed
tails first, then advances the export iterator by **one 200-record batch**.
Already-admitted tails receive priority over export persistence, but a bounded
batch is still allowed while tail network reads are in flight so recovery can
progress too. A new loop schedules overdue tails before the next batch.

Because same-room tails can now arrive between export batches, export
finalization re-reads current coverage state instead of overwriting new cursors
or high-water marks with values cached at export start. If a tail moves to a new
generation, old-generation export provenance remains separate and cannot reset
the active compatibility cursor to the old epoch.

Shutdown stops admission, cancels queued futures, closes active export iterators
and preserves committed snapshot checkpoints. Running GETs remain bounded by
existing transport timeouts. Restart resumes the captured snapshot. No extra
SQLite writer, raw-evidence rewrite, schema DDL, or logical version bump is added.

## Status and qualification

Operational scheduler data uses the existing `evidence_settings` table under
`worker_scheduler_v1`, not new physical schema objects. Writer telemetry updates
at completion and at most once per second during scheduling/batch processing.
Existing `service status` and `evidence soak-status` expose it through coverage
metrics; status readers perform no writes.

Each configured room appears in `scheduler_rooms` with:

- `target_interval_seconds`
- `last_poll_started` (most recent attempt)
- `last_poll_completed` (most recent successfully persisted tail)
- `polls_completed` (successful tail count, preserved across restart)
- `current_poll_age`, `overdue_seconds`, `overdue_ratio`
- `max_observed_poll_age`, `next_due`, backfill retry/failure fields
- `health`

Failed attempts and export completions do not reset freshness. Before the first
successful tail, age grows from startup (or the previous persisted successful
tail). On first deployment, old `evidence_room_health` timestamps may have been
export completions: require fresh tail-count progress before trusting qualification.

Age is wall-clock seconds since the last successful tail. Overdue seconds are
`max(0, age - target)`; overdue ratio is overdue seconds divided by target.
HEALTHY means age <= 2x target, DEGRADED means >2x through 5x, and STARVED means
>5x. Exactly 40-minute ages are STARVED at all default cadences. Backoff does not
hide degraded observation: a room honoring a long Retry-After may still report
STARVED. This describes observation freshness, not necessarily a fairness defect.

Top-level fields include `scheduler_health`, `rooms_overdue`, `rooms_degraded`,
`rooms_starved`, `max_poll_age_seconds`, `max_overdue_ratio`,
`scheduler_queue_depth`, `backfill_queue_depth`, `oldest_pending_tail_age`,
`oldest_pending_backfill_age`, `tail_inflight`, `export_inflight`, and
`scheduler_status_age`. Queue gauges describe the last coordinator snapshot;
due-tail depth includes overdue in-flight tails. Age fields continue growing
on read even if the worker dies, and `scheduler_status_age` exposes stale
telemetry. Absence of worker telemetry reports UNKNOWN, not HEALTHY.

A later 30-minute qualification must show every configured room's tail count
increasing repeatedly; no STARVED rooms; no sustained DEGRADED rooms across
checkpoints; fresh telemetry; backfill progression without unexpected new
failures; schema and evidence integrity PASS; zero coverage integrity errors,
cursor regressions, database errors, and safety counters. Stable message counts
in a genuinely quiet room are acceptable if tail poll counts/timestamps advance.

## Validation and measured simulation

**308 tests passed** (290 baseline plus 18 fairness regression cases). Self-test,
compilation of relevant modules, and `git diff --check` passed. All tests used
temporary state and fixture readers; no production DB writes or live network
requests were used. Existing old-priority and export-excludes-tail tests were
updated to assert the new required behavior.

The controlled 2,400-second run used two tail slots, 0.2s tail latency, 0.5s export
latency, 80 simulated 200-record batches per export, 5ms persistence cost per
step, and permanently backlogged sources. The persistence cost is modeled;
separate tests exercise real raw/event/export persistence and integrity.

| Room | Target seconds | Maximum poll age seconds | Successful tail polls |
|---|---:|---:|---:|
| lobby | 1 | 1.445 | 1,897 |
| faucet | 2 | 2.505 | 1,059 |
| technocore | 20 | 20.595 | 119 |
| kibble | 20 | 20.310 | 119 |
| tclk-offers | 30 | 30.385 | 80 |
| consensus_layer | 60 | 60.425 | 40 |
| quiet | 60 | 60.510 | 40 |

There were 480 export turns; each complete group of seven turns served all seven
rooms. All rooms stayed below their starvation thresholds. Tests also cover
heavy persistence/reader pressure, a stalled export at concurrency 1, isolated
429 backoff, export failure/requeue, restart FIFO/retry restoration, SLA boundary
values, stale status, same-room cursor/high-water preservation, generation changes,
and shutdown after a real 200-record checkpoint followed by successful resume.

## Known limits

Real latency, export validation/finalization cost, SQLite work and machine sleep
can exceed cadence targets. Record batches are capped at 200; there is no hard
wall-clock preemption inside one SQLite operation. Whole-file validation and
final provenance/coverage queries still run synchronously on the coordinator
and are bounded by existing export limits, not a millisecond budget. Metrics
make these stalls visible; the simulation does not establish production timing.
One very large export may delay other backfills until its finite job finishes,
but cannot repeatedly re-enter ahead of other pending sources. Only one export
is downloaded/processed at once; this favors bounded memory and simple recovery.
Wall-clock changes can distort displayed ages; admission uses monotonic time.
Operational max ages and successful-poll counts survive restart and should be
compared by deltas during qualification. Snapshot queue gauges can be stale when
the worker is stopped; always inspect scheduler_status_age.

## Later production deployment plan — NOT EXECUTED

1. Review the changes and confirm the five-reader default is acceptable. Confirm
   Bench/Router remain healthy, Router SHADOW, and the old Scout poller unloaded.
2. In a separately approved window, boot out **only** `com.flop-scout.worker`.
   Verify no Scout worker/poller process and no singleton flock owner remains.
3. Take a consistent SQLite backup plus export snapshots, following the existing
   schema-reconciliation runbook. This change adds no physical schema migration.
4. Run read-only schema-status and verify-integrity against production, both PASS.
   Bootstrap only the existing `com.flop-scout.worker` plist; do not modify launchd
   configuration, run `flop-start`, or start duplicate workers.
5. Record the new PID, all-room tail counts, scheduler fields, coverage/high-water
   values, backfill counters and safety counters. Verify same-room tail activity
   while exports are processing and FIFO backfill progress.
6. Repeat full-stack qualification at 0/10/20/30 minutes using the criteria above.
   Leave Bench and Router untouched. Any STARVED room or stalled tail count blocks
   the soak even when evidence integrity passes.
7. Only after a reviewed qualification PASS may a separate formal 24-hour soak
   start with full baselines. No deployment, restart or soak was performed here.
