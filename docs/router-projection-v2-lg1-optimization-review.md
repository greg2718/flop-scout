# LG1 optimization feasibility and stop report

LG1_PERFORMANCE_ACCEPTABLE = NO
SCOUT_A1_LG1_READY_FOR_PRODUCTION_DRY_RUN = NO

**Stopped under section 15 of the request.** The fixed A1-LG1 representation
cannot meet the maximum 25% public-database overhead on the supplied LG1-heavy
shape. Even an impossible SQLite file containing only its mandatory record
payloads, with no page/tree/free-space overhead, exceeds that target. No producer,
replay format, schema, index, contract or Router change was applied. No production
state, operator identity, network, services, deployment, commit or push was used.

This is a measured feasibility rejection, not an optimized benchmark result.
Removing the obstruction would require a separately approved **wire-format**
change. Captured/report authority semantics remain fixed and were not reopened.

## Evidence and reproducibility

Machine-readable results: [optimization diagnostics](router-projection-v2-lg1-optimization-diagnostics.json).
Temporary experiments: `/private/tmp/scout-lg1-optimization-20260908/`.

Inputs were the prior fresh-process 2,000-row A1/LG1 synthetic benchmark artifacts
and the eight existing LG1 Router fixtures. All producer hashes still match
`router-projection-v2-lg1-benchmark.json`. The authoritative contract still has
SHA-256 `a845223a84d277ceca1f1eb8be893cdbf0160190e78713d1bac778917f3ad3f1`.
Existing user changes were preserved.

New files only: `scripts/analyze_lg1_storage.py`,
`scripts/profile_lg1_diagnostics.py`, this report, and its diagnostic JSON.
The first script performs read-only dbstat audits and bounded, unpublished
row-template storage experiments. The second profiles a fresh synthetic producer
and measures a 200-row mapping allocation with tracemalloc. Both require
explicit temporary paths. Neither has an implicit production path.

Example reruns, with fresh output roots:

```sh
PYTHONPYCACHEPREFIX=/private/tmp/scout-lg1-cache .venv/bin/python scripts/analyze_lg1_storage.py --root /private/tmp/lg1-storage-rerun --baseline /private/tmp/scout-lg1-benchmark-final-20260908
FLOP_SCOUT_STATE_DIR=/private/tmp/lg1-test-state PYTHONPYCACHEPREFIX=/private/tmp/scout-lg1-cache .venv/bin/python scripts/profile_lg1_diagnostics.py --root /private/tmp/lg1-profile-rerun --mode A1
FLOP_SCOUT_STATE_DIR=/private/tmp/lg1-test-state PYTHONPYCACHEPREFIX=/private/tmp/scout-lg1-cache .venv/bin/python scripts/profile_lg1_diagnostics.py --root /private/tmp/lg1-profile-rerun --mode LG1_REPORTED
```

## Root size contributors

The actual 2,000-row producer artifacts measured with SQLite dbstat:

| Object/family | A1 bytes | LG1 bytes | Added bytes |
|---|---:|---:|---:|
| Public database file | 2,789,376 | 4,620,288 | 1,830,912 |
| Public source_provenance pages | 917,504 | 2,744,320 | 1,826,816 |
| Public source_provenance record payload | 864,893 | 2,656,893 | 1,792,000 |
| Public messages pages | 823,296 | 823,296 | 0 |
| Public selection_membership pages | 319,488 | 319,488 | 0 |
| Public indexes, combined | 696,320 | 696,320 | 0 |
| Interactions / durable qualifications / qualification events | Empty in both | Empty in both | 0 |
| Private replay file | 8,200,192 | 16,392,192 | 8,192,000 |

Source provenance accounts for **99.8% of public file growth**. Its record payload
adds exactly **896 bytes per admitted raw**. Page allocation adds approximately
17.4 further bytes per raw; non-B-tree pages outside dbstat explain the remaining 4,096 file
bytes (auto_vacuum=2 and zero freelist pages in both files). Source_provenance already contained the raw ID and message provenance;
LG1 adds its required audit object to that row.

The largest positive object allocations across public and private databases are:

1. Private `input_versions`: +8,192,000 bytes.
2. Public `source_provenance`: +1,826,816 bytes.
3. Private `sqlite_autoindex_source_aliases_1`: +12,288 bytes. Same key count and
   schema; different raw hashes/insertion layout, not a new LG1 index.
4. Public non-B-tree pages: +4,096 bytes. Three private indexes
   (`input_sender`, evaluation-input uniqueness and input-version uniqueness)
   each shrink by 4,096 bytes, offsetting the private alias-index growth.
   Both private ledgers have zero freelist pages.
5. No fifth positive table/index contributor exists in this fixture. Other
   public objects and private workflow/dependency tables add zero pages.

Five largest LG1 JSON field contributions, including each field's key and value
but excluding surrounding-object punctuation:

| Required field | Bytes per row | Bytes across 2,000 rows |
|---|---:|---:|
| linked_cache_records | 259 | 518,000 |
| raw_text_sha256 | 84 | 168,000 |
| raw_record_id | 82 | 164,000 |
| migration_class | 57 | 114,000 |
| transport_lineage | 51 | 102,000 |

These are nested within the provenance payload, not additional additive tables.
The full legacy object is 875 bytes; adding its annotation key and punctuation
accounts for the 896-byte annotation delta. All JSON is already compact.

## Why the storage target cannot be met

The contract's “Wire compatibility and exact version binding” section requires
unchanged nine-table DDL and every displayed per-row LG1 key and literal. It
specifically requires the original 64-hex raw ID, exact text hash and every
concrete-generation original cache reference. No shared metadata table, numeric
enum, compressed JSON blob or manifest-only reference is permitted in their
place. Compact semantics alone do not establish wire compatibility.

For the actual producer fixture:

- Maximum permitted LG1 size at +25%: **3,486,720 bytes**.
- Sum of all LG1 dbstat record payloads alone: **4,284,282 bytes**.
- That payload-only floor is **53.6% larger than the whole A1 file** and exceeds
  the maximum budget by **797,562 bytes**, before allocating page headers,
  B-tree pointers or any unused space.

This is a lower bound, not a forecast. Repacking cannot remove required payload.
SQLite page-size/VACUUM trials on temporary copies confirmed this:

| Page size | Repacked LG1 file bytes |
|---:|---:|
| 1,024 | 4,768,768 |
| 2,048 | 5,898,240 |
| 4,096 | 4,530,176 |
| 8,192 | 4,612,096 |
| 16,384 | 4,816,896 |
| 32,768 | 5,242,880 |
| 65,536 | 5,963,776 |

Even the smallest result exceeds the +25% budget by 1,043,456 bytes. No page-size
change was adopted. Filesystem compression would not reduce the contract's
logical size_bytes and would not change this format bound.

## 1k, 10k and 100k storage results

These are **unpublished SQLite row-template storage experiments**, not end-to-end
producer or Router benchmarks. They use the exact public schema, bounded
200-row insertion buffers, equal-width stable IDs, and the same populated row
families as the supplied synthetic fixture. They repeat payload shapes rather
than assert new original source authority. They must not be used as Router
fixtures, replay evidence, or production qualification artifacts.

| Rows | A1 file bytes | LG1 file bytes | Delta | Added bytes/raw | Added index bytes/raw | Added provenance page bytes/raw |
|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 1,396,736 | 2,306,048 | +65.10% | 909.312 | 0 | 909.312 |
| 10,000 | 13,189,120 | 22,310,912 | +69.16% | 912.179 | 0 | 912.179 |
| 100,000 | 131,665,920 | 222,912,512 | +69.30% | 912.466 | 0 | 912.466 |

Growth is approximately linear in bytes per raw. Small-file fixed pages change
percent overhead; they do not remove the mandatory per-row cost. Payload-only
floors exceed the respective whole A1 files by **53.45%, 62.35%, and 62.99%**.
Thus the format obstruction persists at every requested storage scale.

No optimized 1k/10k/100k throughput, RSS, publication or validation benchmark is
claimed. There is no optimized producer after the explicit format stop. A fresh
1k instrumented producer was run solely for profiling; its timings include
profiling overhead and filesystem noise and are not performance-gate results.
161k was not run after the stop condition was established.

## Root throughput contributors

The existing unprofiled, three-trial 2k benchmark remains the valid regression
measurement: 400.40 A1 versus 317.56 LG1 rows/second, **-20.69%**. Publication:
0.0896 versus 0.6595 seconds. Independent validation: 0.0760 versus 0.1610 seconds.
No optimized result replaces those measurements.

A fresh cProfile diagnostic over 1,000 actual producer rows identifies the work:

| Operation | A1 calls | LG1 calls | LG1 cumulative seconds |
|---|---:|---:|---:|
| map_raw | 1,000 | 1,000 | 0.408 |
| _source_proof | 0 | 1,000 | 0.149 |
| from_originals | 0 | 4,000 | 0.350 |
| validate_legacy_annotation | 0 | 15,000 | 0.270 |
| canonical | 88,077 | 177,091 | 0.661 |
| contract loads | 22,025 | 43,025 | 0.659 |
| verify_ledger | 2 | 2 | 0.322 |
| stage | 5 | 5 | 0.263 |
| evaluate_sender | 1 | 1 | 1.718 |
| SQLite execute | 47,762 | 55,764 | 0.864 |

Cumulative rows overlap and must not be summed. Raw source setup is included in
the whole profile. Commit/I/O timings were noisy (A1 connection-exit time was
2.93 seconds versus 1.00 seconds for LG1); profiled throughput must not be used
to claim an improvement. Function counts, allocation traces and the independent
unprofiled benchmark provide the useful evidence.

LG1 reconstructs originals during mapping, staging, resume and retained-publication
verification. Repeated JSON serialization, strict parsing, hash reconstruction
and class/binding validation are measurable hotspots. LG1 canonical calls roughly
double; JSON encoder iterencode self time increases from 0.100 to 0.402 seconds.
The public annotation is also validated repeatedly during derived-row handling.
Qualification rule pattern matching has the same 474,000 calls in both profiles;
it is substantial common baseline work, not a newly introduced LG1 rule.

A trace of mapping 200 rows counts **1,200 A1 versus 2,200 LG1 SQL statements**:
six versus eleven per raw. The additional five indexed reads fetch links,
original cache rows, alternate candidates, retrieval proof and the event again.
One-event-per-row reading is duplicated between map_raw and source proof. These
are N+1 lookup opportunities; they are not per-record full-table scans in the
measured plans. No batch-cache rewrite was applied after the storage stop.

## Root memory contributors

The prior unprofiled peak RSS is 48.03 MiB A1 versus 60.52 MiB LG1, **+25.99%**.
For a live, bounded 200-row map result, tracemalloc measures:

| Measurement | A1 bytes | LG1 bytes |
|---|---:|---:|
| Live Python allocations | 617,372 | 2,811,165 |
| Peak Python allocations | 629,347 | 2,823,059 |
| Serialized bundle bytes | 302,276 | 1,082,196 |

The extra approximately 2.19 MB of live allocations is concentrated in raw row
materialization, the original event/cache rows and their dictionaries, and the
larger serialized provenance. The JSON containing originals subsequently expands
again on ledger reads. This establishes a concrete allocation source; tracemalloc
does not attribute the entire process-RSS delta, which also includes allocator
retention, SQLite caches and other native allocations.

No map of all 161k LG1 originals is loaded. Source mapping/staging are already
bounded to 200 rows and link inspection to 257 rows before bound rejection.
Existing complete per-sender rule groups can contain up to 100k observations;
that pre-existing common path is separate from the measured 200-row original
allocation. No different RSS/batch target is claimed without implementation.

## Schema/index audit and optimizations

**No schema/index optimization applied.** Public indexes add zero bytes. Public
uniqueness indexes and messages_coverage remain required by the exact DDL and
integrity/coverage behavior. The diagnostic JSON includes sizes of every public,
private and source object, not just changed indexes.

| LG1-relevant source index | Measured bytes | Purpose / requirement |
|---|---:|---|
| router_projection_retrieval_raw | 4,096 | LG1-added retrieval-provenance existence check; performance requirement, not a uniqueness constraint. Empty in this eligible fixture. |
| router_projection_raw_links | 335,872 | Existing covering index for raw-to-cache lookup; performance. |
| router_projection_tclk_offer | 4,096 | Existing TCLK root lookup; performance. Empty fixture table. |
| router_projection_tclk_contract | 4,096 | Existing TCLK reference lookup; performance. Empty fixture table. |
| raw_room_sequence | 53,248 | Existing alternate raw lookup; performance; no index removal. |

EXPLAIN QUERY PLAN shows indexed SEARCH for alternate candidates using
raw_room_sequence(room,seq), covering SEARCH for retrieval proof, covering SEARCH
for links, and integer-primary-key SEARCH for the exact cache row. The link
ORDER BY uses a temporary B-tree because hash lies between raw ID and cache keys
in the current index. Fanout is bounded. Reordering that performance index or
batching exact lookups could remove work, but cannot reduce public wire payload.
The enlarged private source-alias autoindex is a uniqueness index and was kept.

## LG1 storage model, duplicated data and multi-link model

The storage model is unchanged. Authority, match status, schema, migration and
lineage literals repeat in public per-row JSON because the exact contract
requires them. Contract revision and full policy object stay at manifest/state
level; they are not repeated as a whole per-row policy object. Public LG1 does
not add another message-text, sender, room or endpoint value. It does repeat the
raw ID and text hash already available elsewhere, as explicitly mandated.

Private input bundles do duplicate source data. One ordinary LG1 bundle contains
message text in five locations: projected message.text, original raw.raw_text,
original raw.raw_record_json, original cache.text and original cache.raw_record_json.
A1 has one occurrence in the same projected bundle. Other original fields such
as sender, room, nonce and hashes repeat in the preserved raw/cache originals.
An endpoint field is null here. This duplication is measured, not denied.

Private normalization/deduplicated original-record storage could preserve exact
reconstruction under a reviewed private-ledger migration. It would reduce ledger
and allocation costs but would leave the public 896-byte wire addition intact.
No such migration was implemented after the stop condition.

Identical complete canonical cache references already collapse; distinct cache
originals must remain distinct references even when their report agrees. A
single same-generation value cannot replace all required cache record hashes.
The existing two-link fixtures/tests preserve both links without adding a message,
interaction, concrete-generation domain or independent evidence. Every added
distinct cache original further enlarges the mandatory public object.

## Replay ledger cost and batching model

Both 2k trials have **2,000 input_versions rows for 2,000 distinct source IDs**.
LG1 does not create additional replay versions merely by admission. The row
bodies grow from 3,029,803 to 10,853,229 total UTF-8 bytes:

- Preserved original raw/event/cache objects: 5,821,426 new bytes.
- Serialized provenance: 1,226,893 to 3,166,893 bytes, including JSON escaping.
- Message, facts, dependency list and first-observed payload families are unchanged.

The input_versions page allocation adds 8,192,000 bytes. Existing workflow,
dependency and qualification tables add zero pages in this ordinary-message
shape; this does not predict their cost on a workflow-heavy population.

The producer still stages/applies at most 200 inputs per batch. Both 1k profiles
show five stage calls and 2,036 connection-context exits including source setup
and existing per-row derived upserts. There is no new chosen batch size or
commit-latency guarantee. Set-based mapping, original-object interning and
validation reuse need independent design/measurement once the public format
budget is resolved; source-cut consistency and invalidation must remain exact.

## Fixture parity and validation

All eight original Router fixture pointer/manifest/database hashes remain
consistent. Seven valid fixtures still pass the exact LG1 validator; the true
conflict still fails with `Competing LG1 reports`. No original fixture or producer
code was changed, so captured/report values, authority/match status, watermarks,
interaction IDs, workflow state, qualification provenance and same-operator
semantics remain unchanged. The full existing LG1 suite also exercises replay,
continuity, multi-link behavior and rejection boundaries.

- Full Scout suite: **491 passed in 50.08 seconds**.
- Self-test: **PASS**, no network write.
- py_compile: **PASS**, 44 root/scripts Python files.
- git diff --check: **PASS**.
- Producer source hashes versus prior LG1 benchmark: **unchanged**.
- Additional compact-representation/N+1 regression tests: not added, because no
  representation or lookup optimization was implemented under the stop condition.
  Existing tests were retained without weakening.

## Known limitations and production qualification readiness

The exact remaining mandatory blocker is **per-row public LG1 JSON payload**,
not index duplication or page fragmentation. The measured minimum exceeds the
storage maximum even if private memory and CPU were free. Private originals and
repeated validation explain additional actionable costs, but optimizing them
alone cannot make this request's combined targets pass.

1k/10k/100k end-to-end optimized throughput/RSS/publication/validation and 161k
experiments were not run after this decisive stop. Storage-only files are not
qualified snapshots. Profile timings are not replacements for clean benchmark
medians. No production measurements or scale extrapolations are used as readiness
claims. A later public encoding proposal would require separate contract approval
while preserving the already-fixed authority semantics; it was not implemented
or applied to Router here.

LG1_PERFORMANCE_ACCEPTABLE = NO
SCOUT_A1_LG1_READY_FOR_PRODUCTION_DRY_RUN = NO
