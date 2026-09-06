# Coverage correction and observation worker

This document supersedes v2 claims that room-read `first_seq` proves retention
loss. The live server selects the newest matching records, caps the window at
200, and presents them oldest-first. `since` is a filter, not forward pagination.
`first_seq` and `last_seq` describe that selected window. The inspected source
assigns room-local sequences. The official full retained export is the recovery
mechanism. Protocol comparison used the official repository, llms.txt, auth.md,
patterns.md, and read-only captures from 2026-09-06.

## State and durability

Schema v3 adds:

- `source_coverage_state`: coverage cursor, persisted observed high water, server
  tail high water, pending interval, status and backfill history per generation.
- `evidence_export_snapshots`: exact file hash/path, captured metadata, bounds,
  validated generation, batch checkpoint and processing state.
- `evidence_retention_losses`: immutable confirmed loss with full-export and raw
  record references, plus the explicit consecutive room-sequence contract.
- `evidence_gap_reassessments`: immutable assessments referencing original v2 gap
  rows and validated exports. Original gap rows are never rewritten/deleted.
- `evidence_coverage_events` and `evidence_room_health`: local operational history
  and scheduling/backoff state.

On first use, v3 imports the prior durable checkpoint as a baseline. Where old
v2 gaps exist, coverage starts no later than the earliest gap's prior durable
position; the former jumped position remains an observed high water. This is a
new coverage baseline, not a regression of an established v3 cursor. Status
readers never initialize/migrate schemas. Existing generation state is retained.
A generation change uses its own state and records the first validated export
as a new generation baseline; it does not invent loss from sequence 1 across
an unknown epoch boundary.

One tail response is saved through the raw-first pipeline, followed by linked
events. Coverage advances only through consecutive persisted COMPLETE records
with matching links. A hole requires BACKFILL_REQUIRED, not a confirmed loss or
ordinary read failure. Missing generation remains UNRESOLVED. Conflicting
generation or regressed server metadata remains a read failure. High-water
positions are separately exposed.

Export GET uses only `https://technocore.chat/r/<configured-room>/export`, blocks
redirects, requires HTTP 200, and downloads to a temporary file in the local
state directory. It has a 32 MiB cap, 1 MiB line cap, 100,000-record cap, 20-second
socket timeout and 120-second download deadline. EOF/framing, content length
when present, final newline, JSON structure, ordering, room fields when present,
and required X-Room-Generation are checked. Room identity otherwise comes from
the exact fixed request endpoint because native export records omit room.
Malformed message text/signatures can remain evidence; missing/unusable sequence
or invalid JSON prevents the export from proving coverage. Sparse exports never
prove a retention boundary.

The complete file is fsynced and retained under a deterministic identity.
Processing uses 200-record batches, each following raw commit, derived/linkage
commit, compatibility indexing, then checkpoint commit. Raw identity is shared
with tail observations, so replay and overlapping snapshots deduplicate. Capture
time is retained separately from processing time. Existing snapshots resume at
the committed batch checkpoint after restart. A failed/uncommitted batch is
replayed safely. Coverage remains old throughout incomplete processing.

Only after all required evidence is persisted can a complete, consecutive,
matching-generation export establish confirmed unavailability before its first
record. Confirmed loss is committed before crossing that interval. Reassessment
is durable before final coverage movement. A crash therefore leaves old coverage
with replayable evidence, or advanced coverage backed by durable records/proof.
No missing network messages or fake observed events are manufactured.

Successful backfill reports CURRENT_AFTER_BACKFILL; subsequent ordinary polls
report CURRENT. Confirmed recovery reports CONFIRMED_RETENTION_LOSS for that
cycle; its provenance remains visible after operational continuity returns.
Unknown or insufficient evidence remains UNRESOLVED.

## Scheduling and configuration

`python flop_scout.py worker run` is one process, one identity configuration and
one singleton `fcntl.flock` shared with manual `service-poll`. Observation never
loads the private key. The worker runs up to four network reader threads by
default (configurable 1..8). Only the coordinator thread owns SQLite. Pending
results are bounded by concurrency. One export download/processor is active at
a time, with other capacity available for tail reads. Export batches yield back
to the coordinator so other completed tails can be saved between batches.

Initial defaults:

| Room | Interval | Priority |
|---|---:|---:|
| lobby | 1 s | 0 |
| faucet | 2 s | 1 |
| technocore | 20 s | 2 |
| kibble | 20 s | 2 |
| tclk-offers | 30 s | 3 |
| Other configured rooms | 60 s | 10 |

Lower priority numbers run first. Optional collection settings are
`poll_interval_seconds`, `priority`, and `export_backfill_enabled`. Per-room
`~/.flop_scout/polling.json` overrides collection/default settings; an example is
`polling.example.json`. Unknown rooms/settings are rejected. `--config` selects
an alternative local file. Only configured watch rooms are polled.

429, 503, timeouts and other failures receive per-room exponential backoff;
Retry-After is honored, including HTTP dates. Backoff survives worker restart.
Successful reads return to normal cadence. Export failure preserves pending
coverage instead of skipping it. A manual `service-poll` is a bounded concurrent
tail sweep plus at most one required export per room, not the persistent worker.

SIGTERM/SIGINT stop scheduling and drain bounded running reads; unfinished export
processing resumes later. Launchd KeepAlive is a deployment option, not installed
by this task. The process never creates extra identities or independent writers.

## Status, feed and reports

`service status` and `evidence soak-status` expose coverage/observed/server
high waters by source; pending and unresolved sources; backfill starts,
completions, failures and newly inserted records; confirmed losses; distinct
false-positive reassessments; and per-room age, duration, observed rate, next due,
failures and error. A completed backfill's inserted count includes all previously
unseen retained records, including records before an imported baseline.
Original v2 counters remain explicitly labeled historical classifications.

`report daily` includes TAIL WINDOWS OBSERVED, BACKFILLS REQUIRED, BACKFILLS
COMPLETED, CONFIRMED RETENTION LOSSES, FALSE-POSITIVE HISTORICAL GAP REASSESSMENTS,
and UNRESOLVED COVERAGE. The unresolved list is current outstanding state;
activity counts use the selected UTC day. The original gap section is labeled
HISTORICAL GAP CLAIMS. No unobserved message count is inferred.

`evidence provenance` emits separate typed coverage/backfill/loss/reassessment
records. The normal evidence feed remains exclusively raw-linked observed
messages. `evidence verify-integrity` also checks export file hashes, generation,
processing checkpoints/linkage, and loss/reassessment identities and references.
Missing snapshot files fail integrity; include them in backups.

## Later reassessment command — not executed against production

Use reviewed complete captures and their original metadata. A metadata file must
identify the exact export `endpoint` (or captured `url`), captured HTTP `headers`
including X-Room-Generation, and `complete: true`. Existing diagnostic captures
include SHA-256 and byte count; these are verified when present. Set complete
only after confirming the capture reached EOF without clipping, including the
capture tool's bound and Content-Length/framing. An HTTP 200 alone cannot attest
that a local capture tool saved the whole body.

Dry-run validates the file and prints its snapshot identity without opening a
writer connection:

```sh
/Users/greg/Dev/flop_scout_v02/.venv/bin/python /Users/greg/Dev/flop_scout_v02/flop_scout.py reassess-gaps technocore --export-file /absolute/reviewed/export.jsonl --metadata-file /absolute/reviewed/export.metadata.json --generation 0 --db /absolute/copy/observer.sqlite
```

After reviewing the result, append `--apply` to ingest the reviewed capture and
append reassessments to that explicit local DB. The command acquires the same
singleton lock, copies the capture into the DB's adjacent evidence directory,
and makes no network request. Use a temporary database copy for review before
performing this later against production.

A full interval present in the export yields FALSE_POSITIVE_TAIL_WINDOW. A
matching snapshot whose retained start is later yields CONFIRMED_RETENTION_LOSS
**as of export capture time**; it does not prove loss at the original gap's
detection time. Otherwise the assessment is UNRESOLVED. Assessments are
idempotent per original gap, snapshot and assessment, and append-only. No prior
provenance is rewritten.

## Production deployment plan only

No production DB migration, wrapper install, launchd change, restart or soak was
performed during implementation.

1. Review code, temporary fixture integrity, polling settings and the provided
   `com.flop-scout.worker.plist`. Its paths target this workstation.
2. During a later approved maintenance window, quiesce the old StartInterval job
   and manual polls. Wait for active work; preserve a consistent SQLite backup
   including WAL as appropriate and the complete evidence/snapshot directory.
3. Test schema migration and export reassessments on a temporary copy first.
4. Install reviewed polling configuration at `~/.flop_scout/polling.json`.
5. Replace the old periodic job with the provided KeepAlive worker job during the
   approved rollout. Do not leave the old schedule active; it would contend with
   the worker's singleton lock. Preserve the same state directory and DID.
6. The first authorized writer migrates only local schema; all network traffic
   remains observation GETs. Verify status, backfill progress and evidence
   integrity, then decide separately whether to start a formal soak.

Files for later installation (commands are not run by this task):

```sh
/usr/bin/install -m 600 /Users/greg/Dev/flop_scout_v02/scripts/polling.example.json /Users/greg/.flop_scout/polling.json
/usr/bin/install -m 644 /Users/greg/Dev/flop_scout_v02/scripts/com.flop-scout.worker.plist /Users/greg/Library/LaunchAgents/com.flop-scout.worker.plist
```

The old installed service-poll wrapper can remain available for manual use when
the worker is stopped; both entry points share the singleton lock. This plan
intentionally contains no automatic bootout/bootstrap or start command.

## Limits

Cadences are targets, not lossless guarantees. Network latency, processing cost,
queueing, bursts, machine sleep and downtime may exceed tail-window capacity.
Exports are necessary for recovery; they cannot retrieve already expired history.
SQLite batches reduce contention but the coordinator still spends finite time
parsing/indexing each batch. Large retained exports are re-downloaded when a
newer snapshot is required. Exact snapshots and audit rows consume disk and have
no automatic deletion policy. The socket timeout may delay shutdown of an
in-flight read. Unknown generation/invalid or sparse snapshots fail closed.
Schema-v3 imported checkpoints without historical gap records remain trusted
baselines; this change does not fabricate an audit of unrecorded older history.
