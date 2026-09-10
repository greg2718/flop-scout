# A1-LG2 throughput optimization

`LG2_THROUGHPUT_ACCEPTABLE = YES`

`SCOUT_A1_LG2_READY_FOR_PRODUCTION_DRY_RUN = YES`

The implemented candidate passes requested synthetic performance limits.
In the three-trial, 2,000-record comparison, update throughput changes by
+27.87%, expiry throughput by +131.50%, public storage by
+16.15%, and median peak RSS by +1.61%. The complete
161,073-record runs and all validation results are below. Production remains
unqualified; this work stops at the requested report.

[Machine-readable measurements and validation](router-projection-v2-lg2-optimization-evidence.json)
retain the raw trials, profiles, query plans, batch sweep, and unsuccessful
intermediate memory measurements.

## Scope and preserved contract

This work uses synthetic databases and fixtures under `/private/tmp`. It does not
read production databases, modify Router, contact Technocore, start services,
deploy, commit, or push. The original working tree already contained the LG2
implementation; the pre-optimization modules were copied to
`/private/tmp/scout-lg2-opt-baseline` before changes.

The authoritative normalized DDL, revision, encoding, policy, identities, and
wire format are unchanged. Captured generation remains `UNKNOWN_LEGACY`;
reported generation remains audit metadata. SHA-256, original-record binding,
generation conflicts, alternate candidates, retrieval lineage, publication
verification, qualifications, and deterministic replay retain their checks.
No LG1 annotation JSON has been reintroduced into LG2 storage.

## Root update-throughput bottlenecks and correction

The reproduced baseline identified three larger costs than compact locator
construction: per-record SQLite round trips, a transaction for each first-pass
message, and a redundant second message upsert during sender evaluation.
Repeated peer-template queries also scanned the same affected group for each
staged record. Source mapping repeated raw/event/cache reads and ambiguity
queries for each raw event.

Changes:

- `scout_projection_batch.py` reads source inputs in groups of 50. Bounded maps
  hold raw rows, observed events, full candidate link sets, and cache originals.
  Existing exact validators consume those originals. A source read snapshot
  covers each mapping call; maps are discarded between calls and cannot conceal
  a later conflict. Caller-owned transactions are preserved.
- Alternate-candidate and retrieval checks use indexed batched queries. The
  alternate search uses the raw identity index plus `raw_room_sequence`; the
  retrieval check uses `router_projection_retrieval_raw`. No index was added.
- Stage validation precedes writes. A single bounded query checks staged
  identities; identical staged inputs are skipped. Serialized private originals
  are buffered 50 at a time and rehashed before storage. The complete stage
  transaction still rolls back on a conflict.
- Changed and expired peer templates are collected with set queries after the
  complete cut is applied. Unchanged peers still participate in complete sender
  evaluation. Discovered senders are persisted in at most 200-row transactions,
  including high-fanout templates; interrupted discovery resumes idempotently.
  An unchanged `current_inputs` row is no longer rewritten.
- `WriteBatch` obtains prior normalized reports and witnesses with two indexed
  queries, checks exact report equality and witness-set continuity, and batches
  only genuinely new rows. Plain INSERT rejects unexpected conflicts; IGNORE
  does not conceal conflicting normalized content.
- First-pass LG2 writes default to 50 records. A 20 ms elapsed-work check flushes
  and commits between records. This is a soft bound: an individual operation,
  SQLite statement, or COMMIT can exceed it. Existing 200-record staging,
  replay-apply, and rule-evaluation bounds remain.
- Sender evaluation skips its redundant second full upsert only while the
  retention revision is unchanged. New permanent evidence or dependency
  retention forces the original refresh path. Capability annotations and
  qualifications are still recomputed. Direct sender evaluation remains
  conservative.
- Each LG2 database page cache is bounded at 4 MiB instead of 8 MiB. This limits
  native SQLite memory during private-proof verification. A1/LG1 retain their
  prior cache settings. DELETE journals and FULL synchronization are unchanged.
- Decoded outbox payloads and bundles are released immediately after successful
  staging, in both initial-consume and interrupted-staging resume paths. The
  next part and complete evaluation no longer overlap with unnecessary previous
  input buffers. Benchmark clients do the same before evaluation/publication;
  deallocation remains inside the measured staging interval.
- Scale testing exposed a separate expiry problem: selection/provenance deletes
  omitted the leading `entity_type` column of their composite primary keys.
  EXPLAIN showed full-table scans for every expired record. Enumerating both
  schema-allowed values (`message`, `interaction`) enables indexed searches and
  removes exactly the same rows. The corresponding membership existence check
  is indexed too. This straightforward fix applies to A1 and LG2 alike.

All source buffers are bounded; the warehouse is never preloaded. Existing
complete sender-rule groups remain whole, with their existing 100,000-record
capacity limit on private `current_inputs` rows per sender, including retained
history. The scale fixture uses two fixed synthetic public identities
so neither group exceeds that limit; it creates no private key.

## Measurement interpretation

The repeated acceptance benchmark runs each mode in a fresh process and rotates
mode order. A1 uses the same synthetic text, raw count, and cache multiplicity,
but omits reported-generation metadata that A1 cannot admit. Report/witness
normalization is the intended LG2 difference. RSS includes synthetic setup,
mapping, update, snapshot publication/verification, and expiry.

A1 retains its existing one-message first-pass transactions; LG2 uses the new
bounded batching and redundant-upsert avoidance. Common staging, group-discovery,
and indexed-expiry improvements apply to both. This compares the implemented
paths, not the best theoretical performance of an independently optimized A1.

Python/SQLite profiling is separate from acceptance timing. Cumulative Python
times overlap and must not be added. SQL execute timing excludes later cursor
iteration; cProfile includes that work in its callers. SQL call counts count a
Python `executemany` once, while trace counts expose executed SQL statements.
`total_changes` includes triggered changes. Index maintenance is included in
write-statement time: the Python SQLite API does not provide a defensible
separate index-maintenance CPU timer. No such timer is fabricated.

Full-run RSS includes the telemetry's commit/hold samples; A1 collects more of
those samples because it commits more frequently. No estimated overhead is
subtracted. The independent, repeated 2,000-record benchmark has no SQL trace
or cProfile instrumentation and supplies the primary RSS comparison. Benchmark
jobs run sequentially, but background host load is not controlled.

The batch sweep was performed before the final cache reduction. It compares
50/100/200/500 on identical 2,000-record synthetic populations. The final
50-record run and full scale run additionally measure the final cache setting.

## Source SQL operations

For 50 synthetic records, the source audit measures these SELECT counts:

| Shape | Scalar | Batched | Batched SELECTs per successful record |
| --- | ---: | ---: | ---: |
| Ordinary, no LG2 candidate | 300 | 4 | 0.08 |
| LG2, one witness | 550 | 6 | 0.12 |
| LG2, two same-generation witnesses | 600 | 7 | 0.14 |
| Conflict on the first record | 4 | 6 | Not applicable: rejected |

The batch call also opens/releases one read savepoint when it owns the read
transaction. Conflict prefetch reads a bounded group before admission, so
first-record rejection is slightly more expensive than scalar early exit; both
reject with `LG1_GENERATION_CONFLICT`. No report is written on that path. This
is an intentional tradeoff for the much more common successful batches.

The ordinary fixture has an evidence cache but no structured workflow. These
counts do not claim that every workflow-dependent event uses only four SELECTs;
its exact dependency lookups remain in place. Original binding, hashing, and
lineage validation still run on every candidate after batched prefetch.

## Bounded batch sweep

| Maximum rows | Update records/s | Commits | Commit p50 / p95 / max ms | Maximum writer hold ms | Peak RSS MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| 50 | 525.33 | 68 | 1.16 / 2.69 / 17.99 | 49.92 | 57.00 |
| 100 | 526.60 | 67 | 1.16 / 2.56 / 3.06 | 52.16 | 66.53 |
| 200 | 494.00 | 68 | 1.17 / 3.62 / 6.72 | 52.28 | 55.13 |
| 500 | 513.40 | 67 | 1.07 / 2.54 / 6.37 | 51.99 | 72.06 |

The 50-row maximum delivers 99.76% of the best sampled throughput and retains
the smallest possible buffer in this sweep. The elapsed-work check explains
why larger maxima did not meaningfully reduce commits. Individual RSS and
latency samples are not monotonic with batch size; these are measurements, not
claims that a larger batch always has a larger RSS or maximum commit.

Every sweep run used DELETE/FULL for the projection/ledger pair, with zero WAL
high-water and no applicable WAL checkpoint latency.

## Locator storage clarification

The earlier implementation report's prose incorrectly described every stored
locator as 64 bytes. Its JSON evidence and the implementation were correct:
161,073 witnesses store a 64-byte locator and 32,890 store an empty token.
Every decoded locator is 64 bytes in this synthetic legacy shape. The empty
token reversibly denotes `record_hash.hex()`; it is not a missing locator.
Average stored locator length is about 53.15 bytes. This correction changes no
schema, encoding, or prior evidence file.

## Scheduler and checkpoint scope

Projection still has a dedicated owner thread and its own projection/replay
pair. Ordinary observation does not synchronously wait for projection
publication. The pair must use DELETE journals for atomic attached-database
commits; it cannot produce a WAL in these runs. The passive checkpoint probe
returns `(0, -1, -1)` and is not a measurement of a live WAL checkpoint.

The scheduler test uses the existing controlled-clock observer coordinator,
permanent backfill pressure, all seven room classes, one SQLite writer, and
200 ms modeled persistence work. A second case adds a 750 ms persistence spike
every 100 steps. This is modeled scheduler evidence, not a
production soak or proof about arbitrary CPU/I/O contention. Existing checkpoint
and scheduler tests are retained. Production cadence, real source-WAL growth,
and production checkpoint latency still require a separately authorized dry run.

## Final repeated comparison

The exact pre-change reproduction (one 2,000-record trial) measured A1 at 401.41 records/s and LG2 at 277.10 records/s. It reproduced the prior regression before optimization.

Final medians of three rotated fresh-process trials:

| Metric | A1 | LG2 | LG2 change |
| --- | ---: | ---: | ---: |
| Update records/s | 407.49 | 521.06 | +27.87% |
| Expiry records/s | 909.60 | 2,105.75 | +131.50% |
| Public database bytes | 2,789,376 | 3,239,936 | +16.15% |
| Peak RSS bytes | 56,115,200 | 57,016,320 | +1.61% |
| Private ledger bytes | 8,200,192 | 14,438,400 | +76.07% |
| Update microseconds/record | 2,454.06 | 1,919.17 | -21.80% |

The storage gate applies to the published projection, matching the earlier LG2 storage definition. The larger private proof ledger is reported separately. No new persistent cache, schema, or index was introduced by this optimization.

Earlier 8 MiB-cache runs exceeded the RSS gate (+17.16% and +21.66% median RSS). After cache tuning, an all-multi stress trial still showed +32.06% RSS. Retained decoded input buffers were then released immediately after staging in both outbox-consume branches and the benchmark clients; deallocation remains inside measured processing time. Final primary and all-multi comparisons each use three rotated trials. All unsuccessful intermediate measurements remain in the evidence file; no favorable sample was selected in their place.

## Python and SQLite hot-path profile

These are instrumented initial-update profiles of 2,000 records, not acceptance timings. Cumulative costs overlap. A dash denotes an operation that did not exist in that path.

| Operation | Before calls | Before cumulative µs/record | After calls | After cumulative µs/record |
| --- | ---: | ---: | ---: | ---: |
| Raw/message classifier | 10,000 | 83.43 | 8,000 | 68.05 |
| Batched source prefetch/eligibility inputs | — | — | 40 | 22.38 |
| Eligibility/conflict proof including originals | 2,000 | 180.82 | 2,000 | 102.79 |
| Exact cache binding | 8,000 | 108.85 | 8,000 | 13.18 |
| Raw/cache field checks | 7,224 | 71.50 | 7,224 | 73.70 |
| Report/witness construction and proof reconstruction | 6,000 | 280.71 | 6,000 | 287.08 |
| Complete staged proof validation | 4,000 | 333.52 | 4,000 | 344.22 |
| Compact encoding | 2,000 | 21.48 | 2,000 | 21.90 |
| Logical decode/locator validation | 10,000 | 229.97 | 8,000 | 186.94 |
| Normalized sync | 4,000 | 288.61 | 2,000 | 81.64 |
| Message upsert | 4,000 | 1496.70 | 2,000 | 648.74 |
| Complete sender evaluation | 1 | 1880.62 | 1 | 1263.48 |
| All canonical serialization | 303,200 | 548.38 | 267,568 | 497.59 |
| Canonical-object SHA-256 | 17,231 | 119.82 | 15,231 | 93.39 |
| Text SHA-256 | 39,224 | 18.36 | 35,224 | 16.41 |
| Prefixed deterministic IDs | 4 | 0.03 | 4 | 0.03 |

Indexed source/conflict and prior-state SELECT execution costs are shown separately below. These are successful mixed-witness updates; rejected-conflict query counts are in the source audit above. Cursor iteration and Python validation remain in the cumulative profile, not these execute timers.

| Read component | Before calls | After calls | Before execute µs/record | After execute µs/record |
| --- | ---: | ---: | ---: | ---: |
| Immutable raw input | 2,000 | 40 | 19.80 | 1.14 |
| Observed event | 4,000 | 40 | 31.54 | 0.88 |
| Links and cache originals | 12,408 | 89 | 116.97 | 2.11 |
| Alternate-candidate conflict search | 2,000 | 40 | 13.26 | 1.72 |
| Retrieval-lineage rejection search | 2,000 | 40 | 8.13 | 0.65 |
| Prior normalized reports | 4,000 | 40 | 16.74 | 1.03 |
| Prior normalized witnesses | 2,000 | 40 | 9.98 | 0.94 |

SQL Python calls fall from 100,472 to 46,707 (50.236 → 23.354 per record). SELECT trace counts fall from 66,457 to 22,391. Physical changed-row counts are 28,427 → 28,427 (14.213 → 14.213 per record). This preserves actual data/audit writes while removing redundant lookups and transaction boundaries.

| Write component | Before calls / changed rows | After calls / changed rows | Before execute µs/record | After execute µs/record |
| --- | ---: | ---: | ---: | ---: |
| Semantic report | 2,000 / 2,000 | 81 / 2,000 | 72.59 | 3.99 |
| Distinct witnesses | 2,000 / 2,408 | 81 / 2,408 | 25.99 | 12.15 |
| Replay input versions | 2,000 / 2,000 | 40 / 2,000 | 10.09 | 8.12 |
| Evaluation input manifest rows | 2,000 / 2,000 | 40 / 2,000 | 5.46 | 3.80 |
| Current replay inputs | 2,000 / 2,000 | 2,000 / 2,000 | 12.78 | 14.39 |
| Provenance | 2,000 / 2,000 | 2,000 / 2,000 | 20.94 | 8.25 |
| Watermarks | 2,000 / 2,000 | 2,000 / 2,000 | 10.95 | 7.54 |
| Messages | 2,000 / 2,000 | 2,000 / 2,000 | 31.19 | 13.67 |
| Selection membership | 2,000 / 2,000 | 2,000 / 2,000 | 18.86 | 6.42 |
| Affected groups | 4,002 / 1 | 2,001 / 1 | 67.96 | 3.91 |

Profiled COMMIT count changes from 2,025 to 106; total COMMIT time changes from 1.130 to 0.140 seconds. Complete input hashes and replay history are still written; unchanged normalized/provenance rows are verified as no-ops by tests. Index-maintenance time is included in the write costs above, not separately attributed.

Locator selection reuses the already-computed record hash; it does not need another digest. The isolated locator microbenchmark (minimum of three 20,000-operation repetitions, separate from end-to-end timings) measured:

| Cache kind | Record hash µs | Locator selection + validation µs | Reference serialization µs | Token encoding / decoding µs | Stored / decoded bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| evidence_records | 4.294 | 0.944 | 1.852 | 0.040 / 0.037 | 64 / 64 |
| kibble_events | 4.482 | 0.927 | 1.893 | 0.036 / 0.038 | 0 / 64 |

Hash/locator selection was not the main regression. Exact canonical hashes and proof revalidation are retained; the measured gains come from reducing round trips, repeated upserts, template scans, and commits.

## Ordinary and all-multi-witness paths

The ordinary comparison is one 2,000-record pair; the all-multi comparison uses medians of three rotated pairs. Both use the instrumented full-lifecycle harness with identical source cache multiplicity within each pair. The ordinary LG2 mode has no reports.

| Shape | A1 update records/s | LG2 update records/s | Update change | Expiry change | RSS change | Public storage change | LG2 reports / witnesses |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Ordinary / no LG2 candidate | 385.75 | 702.32 | +82.07% | +151.79% | -7.91% | +0.59% | 0 / 0 |
| Every record has two witnesses | 387.60 | 463.38 | +19.55% | +115.96% | +2.16% | +20.91% | 2,000 / 4,000 |

One normalized report owns all distinct witnesses. Witness count does not create additional messages, observations, or independent reputation. Positive qualification and same-operator behavior are additionally covered by the unchanged fixtures and regression tests.

## Complete 161,073-record synthetic producer result

Both final scale processes copy an already-constructed synthetic source into a new temporary root. They run real source mapping, staging, complete evaluation, replay/provenance writes, publication, independent validation, and expiry. These are not storage-only row templates. Source construction is outside this comparison; copy/setup time is excluded from update throughput and reported separately. The corpus models witness multiplicity, not the distribution of every production text or workflow.

| Metric | A1 | LG2 |
| --- | ---: | ---: |
| Source copy/setup seconds | 1.525 | 4.390 |
| Mapping seconds | 23.334 | 33.967 |
| Staging seconds | 21.493 | 45.972 |
| Complete update seconds | 779.670 | 452.243 |
| Update records/s | 206.59 | 356.16 |
| Publication seconds | 7.826 | 83.721 |
| Independent validation seconds | 6.569 | 16.712 |
| Expiry seconds | 377.171 | 103.418 |
| Expiry records/s | 427.06 | 1,557.49 |
| Reports | 0 | 161,073 |
| Witnesses | 0 | 193,963 |
| Published database bytes | 217,927,680 | 252,952,576 |
| Private ledger bytes | 643,395,584 | 1,145,569,280 |
| Peak RSS bytes, including telemetry | 330,792,960 | 319,537,152 |
| Update SQL Python calls | 5,645,698 | 3,756,400 |
| Update physical rows changed | 1,771,830 | 2,287,942 |
| Update + publication + validation + expiry seconds | 1,171.236 | 656.094 |

Final scale deltas: update **+72.40%**, expiry **+264.71%**, public storage **+16.07%**, measured RSS **-3.40%**. Private proof-ledger storage is **+78.05%**; it is not included in the public-storage percentage. Both start from empty projection/ledger files; final byte sizes show resulting growth including fixed schema overhead.

The first large run published every expected report/witness but was interrupted during a table-scanning expiry DELETE. It has no accepted complete timing result. After indexed deletes, an intermediate full LG2 lifecycle passed; the final run above additionally includes bounded affected-group persistence and immediate input-buffer release. All completed intermediate measurements and the aborted-run explanation remain in the evidence.

## COMMIT and writer-hold results at scale

| Mode / phase | Commit count | Total commit seconds | p50 ms | p95 ms | Maximum ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| A1 / update | 162,691 | 332.456 | 0.553 | 15.189 | 1278.507 |
| A1 / publication/validation | 3 | 0.001 | 0.270 | 0.692 | 0.692 |
| A1 / expiry | 161,079 | 232.439 | 0.572 | 1.280 | 622.887 |
| A1 / whole lifecycle | 323,773 | 564.896 | 0.563 | 7.749 | 1278.507 |
| LG2 / update | 7,758 | 35.032 | 2.180 | 16.804 | 652.455 |
| LG2 / publication/validation | 3 | 0.001 | 0.234 | 0.651 | 0.651 |
| LG2 / expiry | 6,448 | 10.180 | 1.525 | 2.876 | 12.821 |
| LG2 / whole lifecycle | 14,209 | 45.212 | 2.004 | 12.669 | 652.455 |

| Mode | Update writer hold p50 / p95 / max ms | Whole-lifecycle writer hold p50 / p95 / max ms |
| --- | ---: | ---: |
| A1 | 0.782 / 15.519 / 1278.748 | 0.794 / 8.798 / 1278.748 |
| LG2 | 22.911 / 78.216 / 673.615 | 22.405 / 66.451 / 673.615 |

These figures expose the latency tail rather than treating the 20 ms work check as a hard COMMIT bound. The earlier complete LG2 run had a 723.3 ms maximum COMMIT; it is retained in the evidence. LG2 uses far fewer commits and has much lower total COMMIT time. Individual LG2 commits are generally larger than A1's; production disk contention is not qualified here.

Both final projection/ledger pairs report DELETE journals, zero WAL high-water, and passive checkpoint results `(0, -1, -1)`. Actual WAL checkpoint latency is **not applicable** for these pairs. The tiny probe duration is not represented as a checkpoint performance measurement.

## Scheduler, semantic parity, and validation

The controlled-clock scheduler runs 600 seconds with permanent backfill pressure and all seven room classes. Both the steady 200 ms writer-cost case and periodic 750 ms spike case preserve one writer, serve every room, and stay within configured cadence plus the tested three-second allowance.

| Room | Steady-model maximum poll gap s | Spike-model maximum poll gap s |
| --- | ---: | ---: |
| consensus_layer | 60.85 | 60.90 |
| faucet | 3.90 | 3.65 |
| kibble | 21.25 | 21.45 |
| lobby | 3.40 | 2.70 |
| quiet | 61.70 | 62.50 |
| tclk-offers | 31.35 | 31.85 |
| technocore | 21.35 | 21.75 |

All nine Router fixtures have identical public logical rows and unchanged ACCEPT/REJECT outcomes. The comparison includes reports, witnesses, captured/reported generations, watermarks, interaction IDs, qualifications, and same-operator semantics; private workflow rows also match. The source-binding, original-proof reconstruction, staged-proof validation, and continuity functions are AST-identical to their pre-optimization versions.

Validation: **584 tests passed** (545 retained plus 39 targeted cases), local self-test passed, **55 Python files compiled**, `git diff --check` passed, and changed untracked Python files passed separate whitespace checks. Targeted tests cover source snapshots, query counts, conflicts, witness deduplication, no-op replay, cancellation, expiry/index plans, fanout transaction bounds, and scheduler spikes.

Normative LG2 DDL remains byte-identical to Router's copy: `b3e39648e0019f490b19bd15a1e36a0e93a05261d7d0c55fce6bdb8e085356e8`.

[Final fixture index](/private/tmp/scout-lg2-opt-buffer-fixtures/index.json) · [Validation logs](/private/tmp/scout-lg2-opt-buffer-validation/validation.json) · [Optimization-only production-code diff](/private/tmp/scout-lg2-opt-production-code.diff)

## Remaining limits

- No production data, live observer WAL, network, or production soak was accessed. Readiness here is for the requested subsequent dry run, not deployment.
- Large-scale and ordinary shape comparisons are single trials; primary and all-multi comparisons each use three rotated trials. Background host load and measurement-buffer overhead remain visible limitations.
- The corpus models the requested witness ratio and two near-capacity sender groups. It does not reproduce all production workflow/content/fanout distributions. Existing private per-sender input limits remain unchanged.
- Original proofs remain private and increase ledger storage. No proof, conflict, hash, or replay check was removed to meet throughput targets.
- Whole-sender rule evaluation and full publication proof verification remain substantial CPU work. Publication is slower than A1 because it validates the added LG2 proof material; its measured cost is included above.

## Reproduction

All roots must be new paths beneath `/private/tmp`; scripts refuse overwrite.
Run from the repository using the existing local environment:

```sh
export PYTHONPYCACHEPREFIX=/private/tmp/scout-lg2-review-cache
export FLOP_SCOUT_STATE_DIR=/private/tmp/scout-lg2-review-state
export PYTHONPATH=/private/tmp/scout-test-deps

.venv/bin/python scripts/benchmark_projection_lg2.py --root /private/tmp/review-lg2-timing --records 2000 --repetitions 3
.venv/bin/python scripts/profile_projection_lg2.py --root /private/tmp/review-lg2-profile --mode LG2

.venv/bin/python scripts/benchmark_projection_lg2_optimization.py --root /private/tmp/review-lg2-source --mode LG2 --records 161073 --prepare-only
.venv/bin/python scripts/benchmark_projection_lg2_optimization.py --root /private/tmp/review-lg2-full --mode LG2 --records 161073 --reuse-source /private/tmp/review-lg2-source/source.sqlite

.venv/bin/python scripts/projection_lg2_fixtures.py --root /private/tmp/review-lg2-fixtures
.venv/bin/python scripts/audit_projection_lg2_optimization.py --old /private/tmp/scout-lg2-router-fixtures-final-20260908 --new /private/tmp/review-lg2-fixtures --output /private/tmp/review-lg2-parity.json
.venv/bin/python -m pytest -q --basetemp=/private/tmp/review-lg2-tests
.venv/bin/python flop_scout.py self-test
rg --files -g '*.py' -0 | xargs -0 .venv/bin/python -m py_compile
git diff --check
```

Repeat the scale preparation/run with `--mode A1` and separate roots for its
control. The supplementary harness supports `--batch 50/100/200/500`,
`--shape single/multi/mixed`, and `--mode LG2_NULL` for ordinary non-LG2 inputs.
The pytest dependency directory is local test tooling, not a new production
dependency. The locator microbenchmark takes an explicit temporary source path.
