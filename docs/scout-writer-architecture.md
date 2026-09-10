# Scout writer ownership

Scope: canonical Scout runtime only. No protocol, schema/index, projection,
Router, Bench, Sentinel, identity, or network-write behavior changes.

## Tail critical path

1. Tail reader completes the configured GET and extracts at most 200 records.
2. That reader verifies signatures, hashes and serializes raw provenance,
   classifies events, normalizes templates, and compiles compatibility INSERT
   parameters. Preparation uses no SQLite connection or identity key.
3. Scheduler harvests the prepared page. Its runnable timestamp determines
   rotation among tails. One admitted page per active room bounds admission.
4. Sole SQLite owner persists one adaptive chunk (at most eight records), using
   one FULL transaction for raw rows, derived events and compatibility inserts.
   State-dependent duplicate lookups, watch membership, indexes and triggers
   execute here. Prepared persistence avoids rereading full raw payloads.
5. Commit returns before the offset/insert count is handed back. Scheduler
   requeues the continuation behind already-waiting tails. Backfill gets a turn
   after two seconds of runnable contention, with at most four input records.
6. After all page records commit, coverage scans yield every 32 sequence
   positions. Export gap reassessment yields after four gaps. These continuations
   retain their scan position in the owner; committed evidence and export offsets
   survive restart. A restarted tail replays deterministic raw identities from
   its unchanged durable cursor, then recomputes any unfinished coverage scan.
7. Finalization proves every page raw/event link, updates coverage and the room
   cursor, records poll health/accounting, and commits. Only then does the
   scheduler mark the page complete and admit its next read.

## Work that still owns SQLite

Record binds, indexed inserts and lookups, duplicate group selection against
committed state, watch membership, metrics, all index/trigger maintenance, FULL
commit/fsync, bounded coverage and reassessment queries, final page link checks,
coverage/cursor/poll accounting and health writes, and metadata/status writes.
Small state-dependent summaries and their JSON formatting also remain here.
Optional projection capture hooks are unchanged and are not enabled by the
canonical Scout LaunchAgent; their performance is outside this qualification.

GET, export download/spool/hash validation, signature verification,
classification, raw provenance, compatibility parsing, normalization and content
hashes run on reader executors. PASSIVE checkpoint work uses the existing
checkpoint executor. On the installed unpatched SQLite it still blocks writer
admission for safety; moving threads does not remove that maintenance delay.

The former 100 ms quantum was a post-batch check: an unexpectedly expensive
batch could exceed it arbitrarily, and oldest-page selection could repeatedly
award the next turn to the same page. Shared batch feedback also let unrelated
small pages distort busy-room throughput. Chunk caps, per-room feedback,
rotation and resumable finalization address those architectural causes.

Bounds are on submitted work, not a hard OS I/O deadline. SQLite statements and
FULL fsync cannot be safely preempted to promise latency on a stalled disk.
Checkpoint, commit and full ownership timings are measured separately. The
writer p95 uses an all-turn 1 ms histogram (not only slow samples); queue metrics
retain both per-turn maximum and cumulative per-page waits.

Validation results are reported after offline tests and the single authorized
15-minute canonical-worker check. No commit or push is performed.

## Qualification result

Offline: 340 regression tests passed on the production Python/SQLite engine;
then six focused tests passed for final continuation changes (including the
adversarial slow page, restart replay, bounded coverage and gap reassessment).
`git diff --check` passed.

One canonical-worker live check ran for 900.054 seconds after a graceful Scout-only
restart. There were 901 completed tail pages in the process diagnostics. Writer
hold p95/max: 21/186.833 ms; maximum internal queue wait: 1689.641 ms (cumulative
per-tail-page maximum: 544.655 ms); commit maximum: 46.466 ms; checkpoint maximum:
417.078 ms. No event-loop lag, restart, stale diagnostics or acceptance failure
was observed. The worker remains RUNNING. Machine-readable results are in
`scout-writer-live-check.json`; full samples are at
`/private/tmp/scout-writer-live/samples.jsonl`.
