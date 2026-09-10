# Production-shaped A1-LG2 dry run: stopped on TCLK linkage

`SCOUT_PRODUCTION_SHAPED_LG2_PROJECTION_VALID = NO`

`ROUTER_PRODUCTION_SHAPED_HANDOFF_READY = NO`

**No valid projection or publication was produced.** The unchanged, synthetically
qualified LG2 producer stopped at source event **214**, after mapping 213 records
and staging the first 200, with `Authenticated TCLK transition lacks resolvable linkage`.
Qualification stopped immediately. No incomplete output was supplied to Router.

[Machine-readable evidence](router-projection-v2-lg2-production-dry-run.json)
contains the capture checks, counts, bounded structural census, sanitized failure
stack, timing limitations, code/review hashes and diagnostic scripts. No raw message
text, offer/contract identifiers, signatures or signing identity file contents are included.

## Warehouse and consistent capture

| Measurement | Result |
| --- | ---: |
| Live source path | `/Users/greg/.flop_scout/observer.sqlite` |
| Source logical size | 52,022,870,016 bytes (48.450 GiB) |
| Source allocated size (`st_blocks × 512`) | 52,022,870,016 bytes |
| Captured source WAL | 115,392 bytes |
| APFS clone duration | 0.001582 seconds |
| Frozen-copy quick_check | PASS (`ok`), 817.28 seconds |
| Full integrity_check | Incomplete: cancelled at its 60-second budget (60.05 seconds) |
| Complete committed source event cut | 4,289,850 |

Capture UTC: `2026-09-09T13:19:32.674011+00:00`. Scout worker, Router worker and
the old Scout poller were unloaded; `lsof` reported no source DB handles. APFS
cloned the DB and every present WAL/SHM sidecar into a new private temporary root.
Device/inode/size/mtime/ctime and sidecar SHA-256 stayed unchanged across capture.
No live SQLite connection or read transaction was opened. Only the clone was
checkpointed and converted to standalone DELETE-journal form.

The committed WAL adds one page to the standalone frozen file: 52,022,874,112
bytes. Its validation is independent of Router's 30-second preparation deadline.
Full integrity checking did not finish and is **not** claimed as passed.
APFS allocated-block figures can include shared extents; they are not claims of
an additional uniquely allocated 48 GiB copy. A second APFS clone received the
producer's indexes/outbox; the frozen file was kept read-only.

Fresh counts on the frozen copy:

| Table | Rows |
| --- | ---: |
| raw_network_records | 4,289,850 |
| observed_events | 4,289,850 |
| interactions | 11,908 |
| messages | 4,289,843 |
| evidence_records | 4,282,049 |
| compatibility_evidence_links | 9,460,539 |
| tclk_frames | 383,824 |
| kibble_events | 323,565 |

The DB/WAL fingerprints and all these counts match the prior frozen cut. No
warehouse growth was observed. This does not establish that every source record
satisfies projection provenance and workflow requirements.

## First failure and classification

- Event **214**, room `tclk-offers`, sequence **15,269**.
- Source `legacy_evidence`; captured generation NULL, projected meaning
  `UNKNOWN_LEGACY`; reported generation `"1"` remains non-authoritative metadata.
- The cached frame is `accept`, `TCLK_PARSEABLE`, `SIGNED_TCLK_FRAME`, with stored
  `VERIFIED_OFFLINE` status and no raw DID-mismatch flag. These statuses are not a
  new independent offline verification of the whole warehouse.
- Its structural field set includes an `offer_id` string but no `id`, `ref`, or
  `contract`. Only field names/types are reported; values and raw text are omitted.
- The mapper uses `id` for offers and `ref or contract` for other frames. Therefore
  this authenticated transition cannot supply its required initial link.
- The unmodified scalar mapper reproduces the identical failure in 0.012 seconds.
  Timing wrappers and batching are not necessary to reproduce it.

This is a **TCLK source-shape / implementation compatibility blocker**, not a
new LG2 generation conflict, SQLite corruption finding, or normalized-schema
failure. Ingestion's parseable classification checks a recognized frame type;
it does not prove complete workflow linkage. Its cache extraction uses `id`,
`contract`, and `ref`, so the original `offer_id` spelling supplies none of those
cached links. Projection applies the stricter required-root check.

The reviewed source model requires preserving unresolved transitions and prohibits
inventing issuer/root/closure authority; missing required local roots also block
publication. This run establishes that the current mapper cannot represent this
source form. It does **not** establish that treating `offer_id` as an alias would
be valid or that a unique authorized root exists. Whether the correction is an
approved alias with exact root/provenance checks or an explicit unresolved
representation needs coordinated review. No alias, fallback, drop, policy change,
or runtime correction was applied.

Relevant implementation: [workflow mapping](../scout_projection_source.py),
`tclk_workflow` lines 161–168; ingestion parser/cache extraction in
[flop_scout.py](../flop_scout.py), lines 1406–1429 and 1508–1510;
[source workflow/closure review](router-projection-v2-source-review.md).

## Safely measurable related population

A bounded read-only scan examined **342,582** linked parseable, signed/bound,
offline-verified TCLK cache/raw pairs. It applied the mapper's exact
missing-initial-link predicate and deduplicated raw IDs in a temporary skinny
SQLite table. The query uses the existing compatibility-table index, cache rowid,
and raw primary-key lookups. It completed in **46.99 seconds**.

| Frame | Captured generation | Reported generation | Structural condition | Distinct raws |
| --- | --- | --- | --- | ---: |
| accept | UNKNOWN_LEGACY | 1 | `offer_id` string; no `ref` or `contract` | 2,373 |
| receipt | UNKNOWN_LEGACY | 0 | No `ref` or `contract` | 49 |
| receipt | 0 | NULL | No `ref` or `contract` | 83 |
| **Total** | | | | **2,505** |

This is an exact **structural-predicate population**, not 2,505 independently
completed admission failures. Other checks may fail earlier on some records.
No full projection continuation was attempted after event 214. The concrete-
generation receipt population also shows that the condition is not confined to
LG2-admitted legacy evidence. Additional independent blockers may remain.

## Producer timing: failed prefix only

| Measurement | Result |
| --- | ---: |
| Temporary source index/outbox preparation | 147.851 s |
| Bootstrap attempt through failure | 113.747 s |
| Mapping, including failed batch | 84.786 s |
| Successful staging | 0.048 s |
| LG2 source-proof calls, including repeated workflow lookups | 218 |
| LG2 source-proof time | 0.035626 s |
| LG2 compact encoding time | 0.002807 s |
| LG2 logical decode/validation time | 0.005517 s |
| Build process total, excluding warehouse validation | 261.702 s |
| Build-process peak RSS | 104,235,008 bytes (99.41 MiB) |

Nested timers overlap and must not be added. Source preparation and complete-cut
checks are bootstrap work, not Router preparation. No complete records/sec,
projection-update, expiry or publication performance result exists. Initial TCLK
mapping dominates this failed prefix; it is not a valid steady-state benchmark.

The raw diagnostic's `commits` field measures connection-context finalizations,
including rollback on failure, and omits implicit DDL commits. Consequently no
commit-only p50/p95/max is asserted. All temporary DBs report DELETE journals and
no WAL files. A continuous WAL high-water was not sampled; the captured live WAL
size is separate. WAL checkpoint latency does not apply to the derived pair.

The earlier synthetic scheduler/performance acceptance remains evidence for that
synthetic workload. This failed production-shaped prefix does not validate actual
scheduler-sensitive performance. No worker was started.

## Requested completed-projection measurements

| Requested result | Status |
| --- | --- |
| Projected messages and total published relational rows | Unavailable: no complete cut |
| Projection DB/allocated size, bytes/message, bytes/relational row | Unavailable for valid output |
| Public table/index breakdown and largest indexes | Unavailable for valid output |
| LG2 reports, witnesses, generation 0/1 counts, witnesses/report percentiles | Unavailable for valid output |
| LG2 added storage and actual locator mean/p50/p95/max | Unavailable for valid output |
| Permanent/durable, active/unresolved, 30/90-day, pin/dependency retention | Unavailable without complete evaluation |
| Workflows, durable qualifications, qualification events, pins/dependencies | Unavailable for a completed projection |
| Projection watermarks | Unavailable for a completed projection |
| Publication backup, snapshot validation and SHA-256 time | Not run |
| Temporary publication root, publication ID, database content ID | None created |
| Scout validation status | Warehouse quick_check passed; projection qualification failed |
| Router envelope preclassification | **UNASSIGNED — blocked before a valid artifact** |

The partial public DB is 102,400 bytes with only its initial metadata row; the
1,945,600-byte private ledger contains 200 staged input versions and one STAGING
evaluation. These are failed-build diagnostics, **not** a zero-message production
projection or a small Router-ready artifact. Exact partial counts remain clearly
labelled in the JSON evidence.

The prior 161,073 affected legacy raws and 193,963 witnesses remain aggregate
source expectations. There is no valid new LG2 report/witness count to compare
against them. The first 200 staged records included successful legacy admission,
but the bootstrap stopped before normalization into a complete selected view.
No missing rows are attributed to selection, deduplication or legitimate expiry
without that completed evaluation.

The 100k-message / 367.76-MiB / 27.77-second Router envelope cannot classify this
failed build. No Router preparation, 30-second deadline test, or 512-MiB memory
guard test was performed, and no Router readiness is claimed.

No pin export was found in the inspected configured state trees. None was
invented or imported. The earlier pin-input clarification is unnecessary for
this stopped run; no publication was attempted. A later successful bootstrap
will still need its explicitly valid pin interchange. This experiment also
creates no unavailable historical qualification ledger or local authority proof.

## Safety, retained artifacts and stop

All final comparisons passed: live DB/WAL/SHM fingerprints and sidecar hashes,
inventoried publication pointers, Scout and Router runtime/review hashes, and
launchd state match baseline. The live `router_projection.sqlite` was absent
before and after, and no `current.json` existed in the inventoried Scout/Router
state roots. Scout worker, Router worker and old Scout poller remain unloaded;
no live DB/poller-flock handles were reported. No full live DB SHA-256 is claimed.

No runtime, Router file, policy, horizon, size ceiling, identity file, production
publication or service was changed. No network request, signing action,
deployment, commit or push occurred. No test suite was rerun because runtime was
unchanged; diagnostic scripts were syntax-checked, and the original scalar path
reproduced the failure. Report/JSON invariants and whitespace were checked.

Only these two new report files were added to the repository. The private
experiment root is retained for diagnostic review:

`/private/tmp/scout-lg2-production-fc53izqd`

It contains the frozen source, prepared clone, incomplete producer pair and
aggregate diagnostics. **It is not a Router publication root.** No production
backup or preexisting artifact was deleted. STOP: the TCLK linkage representation
must be resolved in a separately reviewed task before another qualification run.
