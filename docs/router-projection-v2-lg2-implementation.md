# Scout A1-LG2 implementation and measured limits

Implemented locally against the revised Router contract. The representation and
synthetic correctness checks are ready for Router development. Production use
remains unqualified. See the explicit performance decision below.

## Preflight and files changed

Repository `/Users/greg/Dev/flop_scout_v02`; branch `feature/tclk-discovery`;
HEAD `e24636b409d26f74d981619e0521973cae68c870`. Required repository instructions,
README, prior LG1 implementation/optimization/authority reports, revised Router
contract, normative SQL, and sizing estimate were reviewed. Producer hashes
matched the prior LG1 review before edits; existing dirty changes were preserved.
No unexpected source changes were found. No production state or network was
accessed, no Router files edited, and no services, deployment, commit, or push run.

Changed in this task:

- `scout_projection.py`
- `scout_projection_contract.py`
- `scout_projection_compact.py`
- `scout_projection_legacy.py`
- `scout_projection_source.py`
- `scout_projection_publish.py`
- `scout_projection_cli.py`
- `scout_runtime.py`
- `test_scout_projection_lg2.py`
- `scripts/benchmark_projection_lg2.py`
- `scripts/projection_lg2_fixtures.py`
- `docs/router-legacy-generation-lg2-schema.sql`
- `README.md`

New review artifacts: this report, `router-projection-v2-lg2-storage.json`,
`router-projection-v2-lg2-benchmark.json`, and `router-projection-v2-lg2-evidence.json`.
Preexisting changes in `flop_scout.py`, `scout_schema.py`, `scout_worker.py`, other
projection modules and prior reports remain preserved. The runtime change here
only extends the existing opt-in diagnostic revision/policy binding to LG2.

## A1-LG2 implementation and normative schema compliance

Exact revision `A1-LG2`; exact encoding
`router-legacy-generation-storage/v2`; unchanged complete
`router-legacy-generation-authority/v1` policy. Pointer/manifest `/v2`, database
schema `scout-router-projection/v2`, user_version=2, and original nine tables are
unchanged. LG2 adds only the two normative tables. Their DDL is copied verbatim
from Router; SHA-256:

`b3e39648e0019f490b19bd15a1e36a0e93a05261d7d0c55fce6bdb8e085356e8`

Both tables use their prescribed WITHOUT ROWID keys, CHECK constraints, virtual
`message_id`, and witness foreign key. There are no new secondary indexes.
Startup and artifact validation check exact sqlite_master and table_xinfo shapes;
publication also checks integrity, foreign keys and logical report bindings.
Manifest row_counts includes exactly both new counts, including zeros.

LG2 annotations contain the original eight A1 keys. No `legacy_generation` key,
including null, is emitted. New CLI initialization defaults to LG2. Frozen Python
API defaults retain LG1 compatibility; configured LG2 runtime paths pass the
revision explicitly. Opening existing state never upgrades it. A1/LG1 validators
reject LG2; mixed fields, policy, encoding or schemas reject.

## Report, witness, enum and locator models

One report per admitted raw message, with 32-byte original raw identity and
integer reported_code 0 or 1. Codes reconstruct the original strings "0"/"1".
Row membership under the exact manifest policy implies LEGACY_REPORTED_ONLY and
UNRESOLVED_LEGACY; no resolved-generation field exists.

Each distinct witness retains raw_ref, cache kind, original 32-byte record hash,
and reversible locator. Kinds are exactly 1=evidence_records, 2=tclk_frames,
3=kibble_events. Unknown types/codes reject at the Python boundary and stored
values must satisfy the normative SQL. Decode requires 1–256 witnesses, at least
one evidence_records witness, unique canonical references, and no conflicting
hashes for the same decoded locator. Full logical annotations, including all
other eight fields, remain bounded to 64 KiB after decoding.

The empty token is used only when the original locator exactly equals the
lowercase cache hash. That explicit hash string is rejected as a noncanonical
alternative encoding. Other UTF-8 locators remain exact and bounded to 256
characters. No locator is shortened or invented. Same-generation multi-link
inputs yield one report and N witnesses, without additional messages, edges,
operator groups, support or independent evidence. Repeated updates are idempotent;
validated witness additions are monotonic, and losses/conflicts fail.

## Captured/reported, watermark, workflow and qualification semantics

All original LG1 admission checks remain in force: immutable raw/event/hash,
room, seq, sender, nonce, signature, timestamp, compatible source/ingestion class,
singleton concrete report, cache original, no alternate raw candidate, and no
unavailable lineage falsely upgraded to verified lineage. Original proof is
required during staging, replay and publication; it remains private.

Captured generation stays UNKNOWN_LEGACY for admitted reports. Watermarks,
coverage witnesses, interactions and workflow identity continue using captured
generation only. Reports cannot bridge a concrete workflow domain, select an
ambiguous root, prove closure, enrich unknown authority, promote qualifications,
or create independence. Invalid signatures and DID mismatches remain negative.
Same-operator Bench qualifications retain their exclusions. Qualification and
invalidation history is preserved byte-for-byte through migration and replay.

The mandatory bulk report/message/provenance anti-join runs before cut completion
and during publication validation. Retained private-input comparison detects
missing reports as well as missing witnesses. Expiry removes witnesses, then
reports, with base membership removal in the same transaction, subject to the
existing permanent/pin/dependency guards.

LG2 report validation fixes an observed SQLite join-plan problem: CROSS JOIN
keeps the report scan outermost, followed by an indexed full provenance-key
lookup. An ordinary inner join selected a provenance-prefix scan plus a repeated
full report scan. This correction adds no schema/index and preserves all checks.
A query-plan regression test covers it.

## Replay and migration

`projection --db <dedicated-path> migrate-lg2` explicitly accepts LG1 state only,
after pending evaluations/pin work completes. It archives the private LG1 working
pair with hashes and read-only files, preserves old input versions/evaluations,
converts current inputs to a compact private representation, and records a
versioned LG2_MIGRATION operation. Attached DDL, current input pointers and config
change in one explicit transaction. Logical old/new audit equality is checked.

Replay starts at the original revision, replays original LG1 history, then applies
the recorded migration. A1→LG1→LG2 histories also replay without rewriting their
qualifications. Direct A1→LG2 and downgrade are not silently accepted. New LG2
private input versions do not retain the old expanded annotation; source originals
remain complete, and archived historical LG1 versions remain LG1.

The first publication after migration copies the accepted LG1 database, manifest
and pointer into a separate `lg1-publication-archive-*` directory. Ordinary
publication retention does not remove that archive. It allocates new content and
publication IDs, database artifact and manifest, with kind CONTENT. Subsequent
unchanged LG2 heartbeats reuse the new artifact. Crash/retry may leave additional
preserved archives; none is overwritten or automatically deleted.

Operational migration must drain old source outbox work first. The producer does
not reinterpret an old LG1 outbox payload as LG2; a revision mismatch rejects.
No production migration was attempted.

## Read-only diagnostics

Status exposes revision, encoding, report/witness totals, reported 0/1 totals,
average/max witnesses per report, decoded UTF-8 locator mean/p50/p95/max bytes,
conflict/unsupported attempt counters and the last redacted LG2 projection error.
The source-admission counters retain their historical LG1 identifiers internally;
they count persisted rejection attempts, not distinct source rows. No raw text is
printed. Private originals are read only by validation/replay, not by diagnostics.
The fixture publication readiness flag describes that synthetic artifact only;
production readiness remains NO.

## LG2 fixtures

Fixture index:
`/private/tmp/scout-lg2-router-fixtures-final-20260908/index.json`

Nine cases: normal concrete generation, report 0, report 1, multiple same-generation
witnesses, true conflict, same-operator Bench qualification, qualification
invalidation, heartbeat reuse, and unrelated unknown capture without a report.
Eight are expected ACCEPT; the true-conflict artifact is expected REJECT even
though its artifact/manifest hashes have been recomputed consistently.

These are temporary development publications, with fixed clock
`2026-09-08T12:00:00.000000Z`. Inject that clock for freshness checks. Public identity
bytes and explicit synthetic authority premises are not real signature claims.
Private source/replay files under the fixture root are not Router inputs.
Producer validation and replay pass; Router acceptance has not been run.

## Storage results: 1k, 10k, 100k and 161,073

Measured exact producer row shapes with identical LG1/LG2 evidence fields and
witness multiplicity `1 + 32890/161073`, rounded at each size. The control has the
same base rows without legacy audit data; it is not a claim that A1 admits the
legacy class. All stored locators in these synthetic shapes are explicit 64-byte
values. 4096-byte pages, bounded batches, no VACUUM and no source/proof trimming.

These scaled files are UNPUBLISHED storage experiments using repeated synthetic
row templates and changed identities. They lack corresponding private originals
and must not be consumed as Router fixtures or called end-to-end producer runs.
The separate 2k timings below use real synthetic source mapping and full producer
publication. No production locator distribution is inferred.

| Reports | A1 bytes | LG1 bytes | LG2 bytes | Added LG2 bytes | LG2 vs A1 | LG2 vs LG1 |
|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 1,417,216 | 2,465,792 | 1,650,688 | 233,472 | +16.47% | -33.06% |
| 10,000 | 13,586,432 | 24,100,864 | 15,798,272 | 2,211,840 | +16.28% | -34.45% |
| 100,000 | 135,417,856 | 240,635,904 | 157,425,664 | 22,007,808 | +16.25% | -34.58% |
| 161,073 | 218,021,888 | 387,502,080 | 253,464,576 | 35,442,688 | +16.26% | -34.59% |

| Reports | LG table bytes/report (both tables) | Report table bytes/report | Witness table bytes/witness | Witnesses | Witnesses/report |
|---:|---:|---:|---:|---:|---:|
| 1,000 | 225.28 | 49.15 | 146.29 | 1,204 | 1.204000 |
| 10,000 | 220.36 | 44.65 | 145.92 | 12,042 | 1.204200 |
| 100,000 | 220.00 | 42.56 | 147.35 | 120,419 | 1.204190 |
| 161,073 | 219.99 | 42.49 | 147.40 | 193,963 | 1.204193 |

The both-table bytes/report excludes the 8,192-byte fixed file/schema increase;
added LG bytes and total DB percentages include it. WITHOUT ROWID primary-key
B-tree allocation is included in the table numbers, not hidden as zero-cost keys.

| Reports | LG1 payload delta vs A1 | LG2 payload delta vs A1 | Shared secondary-index bytes | Added secondary-index bytes |
|---:|---:|---:|---:|---:|
| 1,000 | +75.81% | +14.82% | 348,160 | 0 |
| 10,000 | +75.94% | +14.76% | 3,297,280 | 0 |
| 100,000 | +75.65% | +14.70% | 32,894,976 | 0 |
| 161,073 | +75.58% | +14.69% | 52,912,128 | 0 |

Locator distribution: mean=64, p50=64, p95=64, max=64 bytes, both stored and decoded,
at every measured size; zero empty tokens in these synthetic source shapes.
Unit tests separately cover the reversible empty token, UTF-8 exact preservation,
bounds, and rejection of the explicit hash equivalent. Max witnesses/report=2.

Storage meets the user maximum +25% at all four scales, but misses the preferred
+15%. The Router contract additionally calls ≤10% preferred and ≤15% acceptable;
these results fall within its coordinated-review maximum, not those lower tiers.

## Performance and RSS

Three fresh-process trials per mode, 2,000 source records each, rotating mode order.
About 20.4% have a second cache witness. Every timed artifact was published and
validated by the producer. Peak RSS includes source setup and expiry. Timing
instrumentation for class admission and conversion is included in total runtime.
The final run follows the join-order correction; raw initial results remain under
`/private/tmp/scout-lg2-performance-20260908` for diagnosis.

| Measurement | A1 | LG1 | LG2 | LG2 vs A1 |
|---|---:|---:|---:|---:|
| Update throughput (mapping + staging + seal) (rows/s) | 399.0330 | 309.5330 | 303.2806 | -24.00% |
| Source mapping (s) | 0.3519 | 0.6653 | 0.6533 | +85.63% |
| Staging and complete-cut evaluation (s) | 4.6469 | 5.7961 | 5.9443 | +27.92% |
| Expiry throughput (rows/s) | 791.6395 | 688.7188 | 709.0898 | -10.43% |
| Complete expiry evaluation (s) | 2.5264 | 2.9039 | 2.8205 | +11.64% |
| Publication-database backup (s) | 0.0039 | 0.0086 | 0.0044 | +14.90% |
| Standalone validation (s) | 0.0779 | 0.1686 | 0.1819 | +133.54% |
| Artifact SHA-256 (s) | 0.0011 | 0.0021 | 0.0013 | +18.54% |
| Full publication (s) | 0.0918 | 0.7005 | 0.8473 | +822.68% |
| Peak RSS (MiB) | 53.7656 | 69.5000 | 58.2344 | +8.31% |
| Private ledger before expiry (MiB) | 7.8203 | 16.4336 | 13.7695 | +76.07% |
| Published database (bytes) | 2789376.0000 | 5242880.0000 | 3239936.0000 | +16.15% |

Median original-source LG class admission: LG1 8124.19 rows/s;
LG2 8138.37 rows/s. A1 does not execute this admission class.
LG2 compact encoding takes 0.029000 s per 2k update;
bounded logical decode across validation/update calls takes
0.314423 s. These clocks are included in mapping/update,
not additional work to add to the total. Decode may run multiple times per row
to validate each stage; the clocks are not unique-row throughput metrics.

LG2 update throughput changes -24.00% versus A1 and
-2.02% versus LG1.
Peak RSS changes +8.31% versus A1 and
-16.21% versus LG1.
The +25% storage maximum, −10% throughput maximum and +15% RSS maximum are
considered separately; the combined performance decision is **NO**.

Throughput remains the blocking performance budget. Expiry throughput also changes -10.43% versus A1, narrowly exceeding the 10% regression maximum. LG2 removes public JSON
storage repetition and reduces private storage/memory relative to LG1, but retains
original-source validation and adds normalized witness updates and bounded logical
decoding. It does not remove those proof checks to meet a timing target. Further
work should profile/amortize repeated immutable-proof validation and bounded
projection transaction costs while preserving replay and complete-cut guarantees.

## Full validation

- **545 tests passed**, including all 491 baseline tests and 54 LG2 tests.
- Local `flop_scout.py self-test`: PASS; no network write.
- `py_compile`: 48 repository/script Python files passed.
- `git diff --check`: PASS.
- Full suite covers existing scheduler fairness, checkpoint latency, source
  replay, publication, heartbeat, expiry, qualifications and pin/dependency paths.
- LG2 tests cover exact schema/generated columns, codes, locator reconstruction,
  malformed input, original proof loss, report/witness loss, true conflicts,
  source outbox binding, logical bounds, same-operator and negative evidence,
  captured-domain workflows/interactions, migration/archive/retention/replay,
  witness additions, idempotency, manifest mixing and the storage budget.

Reproduction (all state must be isolated under a new `/private/tmp` root):

```sh
PYTHONPYCACHEPREFIX=/private/tmp/scout-lg2-cache FLOP_SCOUT_STATE_DIR=/private/tmp/scout-lg2-tests PYTHONPATH=/private/tmp/scout-test-deps .venv/bin/python -m pytest -q
PYTHONPYCACHEPREFIX=/private/tmp/scout-lg2-cache FLOP_SCOUT_STATE_DIR=/private/tmp/scout-lg2-tests .venv/bin/python flop_scout.py self-test
PYTHONPYCACHEPREFIX=/private/tmp/scout-lg2-cache FLOP_SCOUT_STATE_DIR=/private/tmp/scout-lg2-tests .venv/bin/python scripts/projection_lg2_fixtures.py --root /private/tmp/scout-lg2-fixtures-new
PYTHONPYCACHEPREFIX=/private/tmp/scout-lg2-cache FLOP_SCOUT_STATE_DIR=/private/tmp/scout-lg2-tests .venv/bin/python scripts/benchmark_projection_lg2.py --root /private/tmp/scout-lg2-storage-new --storage
PYTHONPYCACHEPREFIX=/private/tmp/scout-lg2-cache FLOP_SCOUT_STATE_DIR=/private/tmp/scout-lg2-tests .venv/bin/python scripts/benchmark_projection_lg2.py --root /private/tmp/scout-lg2-performance-new --records 2000 --repetitions 3
```

The temporary pytest dependency path is local test tooling, not a production
runtime dependency. Benchmark and fixture generators require unused temporary
roots and refuse overwrites.

## Known limitations, Router work and production dry-run readiness

No production data, source shape, live polling cadence, production performance,
consumer acceptance or end-to-end stack soak was measured. Scaled storage results
are not full producer timing. Longer actual locators or greater witness fanout may
increase overhead. Private originals are still retained per input version; this
change does not implement a shared-original private-ledger redesign. Baseline
whole-sender evaluation limits and history growth remain unchanged.

Router still needs its separately authorized LG2 revision/encoding dispatch,
exact schema/generated-column and row-count validation, bounded normalized audit
decoding, logical-reference and continuity checks, and explicit accepted-state
migration/cache rebinding. Existing LG1 scoring, source authority, workflow,
independence and freshness rules must remain unchanged. Use the temporary fixtures
for that work; no Router files were changed here.

Production dry-run readiness: **NO**. The throughput budget is not met, and no
production access or qualification was authorized in this mission. LG2 is ready
for isolated Router implementation and contract tests; that does not assert
performance acceptance or authorize rollout.

## Required decisions

SCOUT_A1_LG2_IMPLEMENTED = YES

LG2_PERFORMANCE_ACCEPTABLE = NO

SCOUT_A1_LG2_FIXTURES_READY = YES

SCOUT_A1_LG2_READY_FOR_ROUTER_IMPLEMENTATION = YES

Stopped at local implementation, evidence and review. No production access,
deployment, services, Router edits, commit, or push.
