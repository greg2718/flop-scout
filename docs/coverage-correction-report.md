# Coverage correction implementation report

## Root cause / correct server semantics / old incorrect model

Technocore selects the newest matching records, caps them at 200, and returns
that window oldest-first. Its first_seq is the first returned record. The old
Scout code treated it as a retained-history floor, while tests modeled earliest
records after since. Both the loss classification and forward-pagination
assumption were wrong.

## New coverage and tail observation model

Coverage cursor, persisted observed high water and current server tail high
water are independent. Tail records are retained immediately; missing contiguous
coverage produces BACKFILL_REQUIRED. No confirmed loss originates from a tail
read. Imported v2 gap jumps are not grandfathered into v3 coverage. The legacy
high-water alias stays intact while the separate coverage checkpoint is rebuilt.

## Export algorithm / true retention-loss criteria

Fixed official GET endpoints download bounded complete snapshots. Validation
checks response completion, source endpoint, room where encoded, generation,
ordering, size and captured hashes. Batches of 200 records use the shared raw
identity and existing raw-first/derived pipeline. Durable batch checkpoints allow
restart without duplicate raw rows. The coordinator interleaves tail persistence
between export batches.

A full consecutive matching-generation export can establish a retained lower
boundary, under the verified room-local sequence contract. Confirmed loss is
recorded before coverage crosses an unavailable interval. Generation reset is
handled as a new baseline, not inferred loss from a prior epoch. Sparse,
incomplete and ambiguous exports remain unresolved.

## Historical gap reassessment

Original gap rows stay immutable. Reassessments append FALSE_POSITIVE_TAIL_WINDOW,
CONFIRMED_RETENTION_LOSS or UNRESOLVED with snapshot references. Later absence is
explicitly scoped to the export capture time, not the old detection time.
`reassess-gaps` offers dry-run validation and explicit local `--apply`, using
reviewed files only. It was exercised against a temporary DB, never production.

## Concurrency / cadence / worker / SQLite serialization

`worker run` owns the shared singleton flock and one SQLite coordinator. Up to
four network readers run concurrently; one export pipeline runs at a time.
Defaults: lobby 1s, faucet 2s, technocore/kibble 20s, TCLK 30s, other rooms 60s.
Per-room priority, cadence and backfill enablement are configurable. Backoff
persists across restart and honors Retry-After. Export rejection triggers a tail
refresh to discover generation changes rather than retrying the wrong epoch
forever. SIGTERM/SIGINT stop scheduling and drain bounded reads.

## Status / reports / evidence feed

Added coverage/high-water maps, pending/unresolved sources, backfill counters,
confirmed-loss and false-positive metrics, and per-room health/timing/rate/due
information. Daily provenance distinguishes tail observations, backfills,
confirmed loss, reassessment and unresolved coverage. Typed provenance is
exported separately from the unchanged raw-linked observed event feed.

## Test fixtures replaced / tests added and removed

Earliest-after-since mocks now model newest matching records. Actual captured
10/50/200 JSON bodies exercise the production window behavior. Twenty-nine v2
recovery test cases were replaced by 77 coverage/backfill/worker cases; remaining
valid raw, signature, lock, safety, compatibility and generation tests continue
passing. Some existing test names/expectations were corrected to describe tails.
The suite explicitly blocks live sockets and allocates temporary state before
Scout import.

## Validation

- Full suite: **271 passed**.
- Ed25519 local self-test: **PASS**.
- Compilation of Scout, evidence, coverage and worker modules: **PASS**.
- `git diff --check`: **PASS**.
- Example KeepAlive plist parsing/structure: **PASS**.
- Deterministic reader concurrency, serialized writes, batch interleaving,
  process shutdown and singleton contention: **PASS**.
- Actual subprocess exit during backfill followed by replay: **PASS**.

CLI integrity against populated temporary scenarios:

| Scenario | Raw / events | Coverage | Observed | Losses | Result |
|---|---:|---:|---:|---:|---|
| Tail only | 51 / 51 | 100 | 200 | 0 | PASS |
| Export recovered, then CURRENT | 200 / 200 | 200 | 200 | 0 | PASS |
| Confirmed retention loss | 300 / 300 | 1099 | 1099 | 1 | PASS |
| Historical reassessment | 200 / 200 | 200 | 200 | 0 | PASS |
| After process crash | 251 / 251 | 100 | 500 | 0 | PASS |
| After restart | 500 / 500 | 500 | 500 | 0 | PASS |
| Offline import/reassessment CLI | 200 / 200 | 200 | 200 | 0 | PASS |

All integrity error counts and safety counters were zero. Reassessment fixtures
had one false-positive assessment. Temporary validation outputs are at
`/tmp/scout-coverage-validation-ubwd5n_8/results.json` with per-scenario JSON files.

## Files / deployment plan / limitations

Core changes: flop_scout.py, scout_evidence.py, new scout_coverage.py and
scout_worker.py. Tests: corrected existing files, test_coverage_backfill.py,
coverage_test_support.py, conftest.py and captured tests/fixtures. Documentation:
README.md, evidence-feed.md, corrected POLL_RECOVERY.md and COVERAGE_WORKER.md.
Deployment artifacts: polling.example.json and com.flop-scout.worker.plist.

See scripts/COVERAGE_WORKER.md for the reviewed-file reassessment command and
later maintenance-window deployment plan. The plist is a template only; no
launchd changes were made. Existing periodic scheduling must be quiesced before
installing the persistent worker, and migration/reassessment should be reviewed
on a consistent temporary DB copy first.

Cadences are targets, not guarantees. Bursts, latency, processing cost and offline
periods can overrun tails; export backfill remains required. Already expired
history is unrecoverable. Captured exports and provenance need disk and backups;
there is no automatic pruning. Unrecorded pre-v3 history is not retroactively
certified. Legacy opportunity/validation summary refresh remains available
through existing one-shot commands; the persistent worker prioritizes raw/event
capture and coverage bookkeeping.

No production DB, private key, DID, deployed wrapper or launchd configuration was
modified. No network writes, claims/actions, deployment, soak, commit or push.
