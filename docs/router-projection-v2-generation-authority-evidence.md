# Scout V2 generation-authority evidence

Recommendation to Router: **B — strict conflict should remain.** Neither `"0"` nor `"1"` can be authoritatively assigned to the affected UNKNOWN_LEGACY raw records from the surviving evidence. The cache labels are consistent and the two populations are disjoint; the original generation-bearing transport capture is missing. This does not authorize enrichment, a contract amendment, or a migration.

`IMPLEMENTATION_READINESS = BLOCKED_PENDING_GENERATION_AUTHORITY`

`GENERATION_RESOLUTION_BLOCKED = YES`

This evidence-only report answers the [Router review](../../flop-router/docs/SCOUT_ROUTER_GENERATION_RESOLUTION_REVIEW.md), using the same frozen production cut as the [prior dry-run](router-projection-v2-production-dry-run.md). [Machine-readable evidence](router-projection-v2-generation-authority-evidence.json) includes complete marginal and joint distributions, query definitions, revision/file hashes, and sanitized diagnostic source. No production contents, raw IDs, DIDs, or signatures are published.

## Source snapshot summary

Snapshot time: **2026-09-08 21:36:00.918629 UTC**. Scout HEAD was `e24636b409d26f74d981619e0521973cae68c870`, branch `feature/tclk-discovery`, with preexisting uncommitted V2 implementation work. Working-file hashes are recorded separately from HEAD; the working tree must not be described as the deployed commit.

The quiescent source DB and WAL were APFS-cloned into a new private temporary directory. Device/inode/size/mtime/ctime, WAL SHA-256, and SQLite `data_version` stayed stable across the clone. Only the clone was checkpointed. The source fingerprint exactly matched the prior snapshot whose full `quick_check` passed; that integrity result was reused rather than repeating the 48-GiB scan. No full-file DB SHA-256 is claimed. Long-running queries used the copy only.

| Source table | Rows |
|---|---:|
| raw_network_records | 4,289,850 |
| observed_events | 4,289,850 |
| messages | 4,289,843 |
| evidence_records | 4,282,049 |
| compatibility_evidence_links | 9,460,539 |
| tclk_frames | 383,824 |
| kibble_events | 323,565 |
| interactions | 11,908 |

DB size: **52,022,870,016 bytes**; WAL: **115,392 bytes**; maximum observed event: **4,289,850**. WAL SHA-256: `e89edce2ee16fd1a86695b754833886054550704ebacfd328b2556bcc573d76a`. Table totals come from the identical prior validated cut; the maximum event and all task-specific aggregates were checked on the new copy.

## Distinct raw records and generation sets

The selection is actual/raw `generation IS NULL OR generation='UNKNOWN_LEGACY'`. It contains **168,882** raw records: **161,081 legacy_evidence** and **7,801 legacy_messages**. All have a compatibility link. **161,073** have at least one concrete-generation link; **7,809** have unknown-only/non-generation links, including eight unknown-generation evidence cache records.

Concrete means a non-NULL value other than empty string, UNKNOWN_LEGACY, or GENERATION_MISSING. Numeric/string zero remains concrete. One linked row means one `(cache_table, cache_rowid)`, not a repeated field occurrence. The raw row's own `reported_generation` is checked for agreement but is not counted as another link.

| Per-raw linked generation set | Distinct raw records |
|---|---:|
| `{0}` only | 127,146 |
| `{1}` only | 33,927 |
| `{0,1}` | 0 |
| Other singleton | 0 |
| Other multiple | 0 |
| **Total affected** | **161,073** |

Maximum distinct linked generations per raw: **1**. The prior 127,146 and 33,927 evidence-pair counts each represent distinct records and do not overlap.

## Link multiplicity and conflict counts

| Concrete cache links | Generation 0 pairs | Generation 1 pairs |
|---|---:|---:|
| evidence_records | 127,146 | 33,927 |
| tclk_frames | 391 | 32,294 |
| kibble_events | 205 | 0 |
| **Total** | **127,742** | **66,221** |

There are **193,963 concrete linked rows**. **128,183** affected raw records have exactly one concrete link; **32,890** have two same-generation links; **0** have competing concrete generations. Counting *all* compatibility rows, including messages and opportunities without generation, those populations have three and four links respectively. There are no affected validation-response links.

The alternate-candidate query searched the entire source table across all generations and sources for another raw ID with the same room, sequence, and exact text hash, without a LIMIT or first-match selection. Result: **0 alternate candidate pairs, 0 affected records with alternatives**. There are also **0 evidence_retrievals rows** attached to any unknown-generation raw record. Thus no alternate capture or later retrieval supplies a generation claim here.

## Provenance agreement matrix

Counts below are **linked pairs**. Each joint predicate was evaluated on the same pair. Missing fields are not equality, and copied metadata is not independent corroboration.

| Joint predicate | Evidence 0 | Evidence 1 | TCLK 0 | TCLK 1 | Kibble 0 |
|---|---:|---:|---:|---:|---:|
| room + seq + exact text hash agree | 127,146 | 33,927 | 391 | 32,294 | 205 |
| Above + sender agree | 127,133 | 33,926 | 391 | 32,293 | 205 |
| Above + original lineage agrees | 0 | 0 | 0 | 0 | 0 |
| room + seq + hash + sender agree; lineage unknown | 127,133 | 33,926 | 391 | 32,293 | 205 |
| room + seq + hash agree; sender differs | 0 | 0 | 0 | 0 | 0 |
| room + seq agree; hash differs | 0 | 0 | 0 | 0 | 0 |
| sender unavailable in linked row | 13 | 1 | 0 | 1 | 0 |
| identity + nonce + signature + network timestamp agree | 127,133 | 33,926 | 0 | 0 | 205 |
| Above + offline signature/raw identity/hash checks pass and no DID-mismatch flag, without lineage | 127,132 | 33,924 | 0 | 0 | 205 |
| **Full provenance/authority passes** | **0** | **0** | **0** | **0** | **0** |

All 193,963 concrete pairs agree on stored link hash and recomputed exact text hash; all available stored message/frame hashes agree with exact text. All agree with raw `reported_generation`. Every affected raw ID recomputes correctly from its source/room/actual/report/envelope identity inputs, and each reconstructed envelope's text hash matches the stored raw text hash.

Both endpoints are absent for every concrete pair. All 161,073 original cache source labels are `service-poll`; all affected raw source labels are `legacy_evidence`. This is a known difference between an original ingestion label and a migration container, **not proof of conflicting transport endpoints**. TCLK/Kibble rows have no comparable ingestion-source field. Exact capture timestamps agree on every concrete pair. Network timestamps agree in evidence/Kibble; TCLK stores no network timestamp, nonce, or signature. Its `observed_at` is capture time and is not substituted for network time.

Of 161,073 distinct affected raw records, fresh offline verification finds **161,058 VERIFIED_OFFLINE**, **14 UNSIGNED**, and **1 INVALID_SIGNATURE**. Generation 0 accounts for 127,132 verified, 13 unsigned, and the invalid signature; generation 1 accounts for 33,926 verified and one unsigned. Cached verification statuses agree with this fresh result. Two generation-1 raws also retain `did_mismatch=1` despite valid signatures; the stronger identity predicate excludes them, leaving 33,924 generation-1 evidence pairs passing that predicate without lineage. A signature can verify while application/transport identity binding fails. The invalid signature and these two identity flags are not misclassified as competing generation claims. No private key was accessed; verification uses public DID material.

TCLK parsing separately reports 27,941 parseable and 4,744 malformed linked frames; all 205 linked Kibble rows are KIBBLE_MALFORMED. Parsing is distinct from signature validity and generation authority. No malformed evidence was removed to improve the counts.

**Ambiguous linkage count:** zero competing-generation assignments and zero alternate exact candidates. **Unresolved generation-origin count:** 161,073 distinct raws. These are different claims. Fourteen raws lack the linked sender/signature binding, one fails signature verification, and two additional generation-1 raws retain an internal DID-mismatch flag. No affected record satisfies complete original transport provenance, even among the verified subset.

## Generation-writer paths and historical evidence

The audit examined reachable local history for four relevant files: 14 distinct committed versions of `flop_scout.py`, six of `scout_evidence.py`, one of `scout_schema.py`, and four of `scout_coverage.py`, plus current working files. JSON records every examined revision/hash and generation assignment expression. This bounds the code investigation; it does not prove that no unrecorded external writer or historical working-tree change existed.

| Path | Generation input and consequence |
|---|---|
| Room parser, historical `8251fda` and current `fetch_room_view` | JSON body generation, otherwise X-Room-Generation header. Both 0 and 1 survive; missing both returns None. The historical parser discarded the original response metadata and did not flag body/header disagreement. Current capture retains both and a conflict flag. |
| Historical `service_poll` / current `service_poll_room` → `ingest_messages` → `evidence_record_from_message` / `store_evidence_record` | Caller passes parsed generation; cache writer stringifies non-None and maps only None to UNKNOWN_LEGACY. Stored envelope is the message, not the entire HTTP response. All affected evidence rows say `service-poll`, but the executing code revision is not recorded. Cursor-state initialization does not fabricate a generation for the cache insertion. |
| `tclk_record_from_message`, `kibble_record_from_message` | Same caller-supplied generation conversion. They do not derive room generation from signed TCLK or Kibble application payloads. Their extra links repeat the same label and provide no independent capture. |
| `scout_evidence.initialize`, schema 1, `2e631db` | Imports cache generation verbatim as **reported_generation**, passes **generation=None**, marks source legacy_evidence and provenance PARTIAL. This preserves a legacy assertion without upgrading it to captured authority. |
| Legacy messages / compatibility fallback | Legacy messages have no generation. A missing compatibility match creates legacy_<table> evidence with the cache value only reported. No affected record uses these other legacy sources. |
| `compatibility_links` | Historical migration selects first room/seq/text match without a sender/generation uniqueness proof. The insert trigger adds a generation predicate, but remains first-match. This mechanism alone cannot grant authority; the independent alternate-candidate query found no alternatives in this cut. |
| Raw `ingest` / `raw_identity` | Actual and reported generation remain distinct and both enter immutable identity. Current body/header conflict handling can retain a report while clearing actual generation. A missing actual generation therefore cannot universally be interpreted as permission to enrich. |
| Defaults, schema 2/3, later reconciliation | No generation 0/1 default was found in the reviewed production writer/DDL paths. Missing values use None or named unknown/missing sentinels. Later schema changes do not reconstruct historical transport authority. Zero is not proven defaulted merely because origin is missing. |
| Historical/current export paths | Old export used X-Room-Generation. Current backfill requires an expected generation and a matching actual export header. Offline export verification can use a manifest or generation-<value> path, but produces a verification report rather than inserting these service-poll cache rows. Path-derived context is not transport proof. |
| Scout Bench helper, `network_result_generation`, introduced `8251fda` | Maps None, empty, **0** to UNKNOWN_LEGACY in normalized Bench result provenance; separately preserves the input report. It does not normalize the affected service-poll evidence cache. |
| Bench package `_coerce_record` | Separate implementation accepts context or a nonempty raw generation and preserves zero. Neither Bench path proves the origin of these Scout cache rows. |

Relevant immutable milestones: cache provenance in `7135618d528c556a5f3650bbe59183c7161cb662`; Bench normalization in `8251fdaaa5b9d0c5413c8a4c5beda769f570d392`; raw migration in `2e631dba758f8426861ae7b986a9e39d87aa2485`; timestamp fix in `614fc8d79066c3aa7728c0c6456b145f80823e14`. Commit dates do not prove production execution dates.

Sanitized reproductions executed the immutable historical parser with an injected in-memory response, and the immutable historical migration in SQLite `:memory:`. They made no network request or production write:

| Synthetic input | Historical parser | Cache generation | Scout Bench normalized generation |
|---|---|---|---|
| body 0 / no header | 0 | 0 | UNKNOWN_LEGACY |
| no body / header 0 | 0 | 0 | UNKNOWN_LEGACY |
| body 1 / no header | 1 | 1 | 1 |
| no body / header 1 | 1 | 1 | 1 |
| neither | None | UNKNOWN_LEGACY | UNKNOWN_LEGACY |
| body 0 / header 1 | 0 | 0 | UNKNOWN_LEGACY |

The last case demonstrates a historical authority limitation; it is **not evidence that this conflict occurred in production**. Historical migration of synthetic cache labels 0, 1, and UNKNOWN_LEGACY leaves actual generation NULL and copies each label unchanged into reported_generation. It also reproduces old `created_at == retrieved_at` behavior. No reproduction claims that a synthetic server response proves an actual historical response.

Historical parser function SHA-256: `78932c42688dd47aef4035bc680cf387f0ab1705a86ba8b298082503ad1a7131`. Historical migration module SHA-256: `ead6db2b8069d28d2ae4a2d48687194e88e6ad56529e7a4a8de1d2b096534b9d`. Additional function/module and working-file hashes are in JSON.

## Generation 0 authority

**CAN WE PROVE THAT 0 MEANS A REAL OBSERVED SERVER GENERATION FOR THE AFFECTED PRODUCTION ROWS? NO.**

All 127,146 affected zero raws carry migrated cache reports, with no original endpoint, response body/header generation, capture snapshot, source epoch, alternate matching raw, or retrieval evidence. Their message envelopes do not establish generation. No affected zero is proven defaulted or inferred; its ultimate origin is unknown.

There is positive evidence that zero occurs in **other** captured transport metadata: **3,807,195 nonlegacy COMPLETE raw records**, comprising 2,262,230 body-generation captures and 1,544,965 header-generation captures. The stored endpoint is present and no generation conflict is flagged. This is a metadata aggregate of existing captures, not a new network observation or full authenticity audit of those other records. None matches an affected legacy record under room/seq/hash. It refutes a blanket claim that every zero is an unknown sentinel, but cannot retroactively bind these legacy rows to zero.

Migration carried zero; it did not invent actual zero. Scout's Bench result helper uses zero as a contextual unknown sentinel and emits UNKNOWN_LEGACY while retaining reported zero. No affected cache row is labeled as a Bench-derived source.

## Generation 1 authority

**CAN WE PROVE THAT 1 MEANS A REAL OBSERVED SERVER GENERATION FOR THE AFFECTED PRODUCTION ROWS? NO.**

The same missing-authority conditions apply to all 33,927 affected one raws. Nonzero is not an authority predicate. Other stored transport captures contain **313,773 nonlegacy COMPLETE generation-1 records**: 193,720 body-generation and 120,053 header-generation captures, with endpoint present and no conflict flag. None is an alternate exact match for an affected record. The Bench helper preserves one, but that does not prove its source.

## Authority-class counts

The primary classification below concerns the **ultimate server-generation origin of concrete linked metadata**, counted once per concrete cache row. Missing origin is classified conservatively. Carriage by migration is a separate, explicitly non-additive dimension.

| Ultimate-origin class | Generation 0 pairs | Generation 1 pairs |
|---|---:|---:|
| AUTHORITATIVE_TRANSPORT_CAPTURE | 0 | 0 |
| SIGNED_MESSAGE_REPORTED | 0 | 0 |
| DERIVED_FROM_PRIOR_CAPTURE | 0 | 0 |
| MIGRATION_CARRIED_FORWARD as proof of original origin | 0 | 0 |
| DEFAULTED | 0 | 0 |
| INFERRED | 0 | 0 |
| UNKNOWN_ORIGIN | 127,742 | 66,221 |
| CONFLICTING concrete generation claims | 0 | 0 |

For the separate **creation of the raw reported field**, MIGRATION_CARRIED_FORWARD is **127,146 zero + 33,927 one = 161,073 distinct raw records**. The same records' original label origin remains UNKNOWN_ORIGIN: 127,146 and 33,927 distinct raws. The additional 32,890 protocol-cache links do not create more independently observed raw reports. Do not add migration-carriage counts to unknown-origin counts or call migrated labels authoritative. There are zero positively established default/inference origins, not proof that every possible historical writer has been excluded.

Generation claims inside signed text were checked separately from signature validity. API generation is absent from the signing preimage, which binds room, nonce, and exact text. Consequently the 161,058 successful signature verifications establish no server-generation binding by themselves.

## Version and time correlation

All affected records have raw source **legacy_evidence**, `legacy_record=1`, `raw_completeness=PARTIAL`, `ingestion_schema=flop-scout-evidence/v1`, and `ingestion_version=1`. That version is a constant, **not an implementation SHA**. A per-row executing Git revision cannot be recovered from it.

| Physical schema version | Recorded migration time, UTC |
|---|---|
| 1 | 2026-09-05 13:31:26.462699 |
| 2 | 2026-09-06 13:24:50.909158 |
| 3 | 2026-09-06 14:52:01.315253 |

| Stored retrieval date, UTC | Generation 0 raws | Generation 1 raws |
|---|---:|---:|
| 2026-09-03 | 56,284 | 9,900 |
| 2026-09-04 | 69,086 | 23,222 |
| 2026-09-05 | 1,776 | 805 |

Generation 0 retrieval range: **2026-09-03 19:35:36.304976 → 2026-09-05 00:21:52.062664 UTC**. Generation 1: **2026-09-03 19:35:37.827955 → 2026-09-05 00:21:48.929395 UTC**. All precede schema 1's recorded migration time. Both populations span all three retrieval dates; no conflicting-set cluster exists.

Every affected `created_at` equals the imported `retrieved_at`. Before `614fc8d`, raw ingest used that supplied time as created_at; later code uses current time for new rows. Therefore these created_at values **must not be interpreted as actual migration execution times**. The database's schema migration record and explicit legacy/report fields provide the migration correlation. Network-message timestamps are separate and are reported independently in JSON; they do not date ingestion or prove generation. The migration boundary identifies a bounded legacy population, not an authorized mapping to actual 0/1.

## Room and source distribution

Counts are distinct affected raws. Mailbox room identity is redacted.

| Room/group | Generation 0 | Generation 1 |
|---|---:|---:|
| lobby | 68,882 | 0 |
| technocore | 58,057 | 0 |
| tclk-offers / TCLK-related room | 0 | 33,927 |
| kibble | 205 | 0 |
| faucet | 0 | 0 |
| mailbox | 2 | 0 |
| other | 0 | 0 |

All original evidence-cache sources are **service-poll** (127,146 zero; 33,927 one); all raw sources are **legacy_evidence**. Bench/verification-derived source labels: **0**. Original endpoint availability: **0** for both generations. Generation 1 is confined to tclk-offers in this affected cut; zero dominates the other affected rooms. TCLK *content* links also occur outside the TCLK room, so the 32,685 TCLK cache rows should not be confused with the 33,927 affected tclk-offers raw records.

## What is proven and what is not proven

Proven: exact population and disjoint sets; no competing generation assignments or alternate room/seq/hash candidates; full content/hash agreement; stated sender/signature availability and fresh verification results; migration carrying reported metadata; missing original transport provenance; both values appearing in other preserved transport captures.

Not proven: original body versus header input for any affected generation label; absence of a historical body/header disagreement; exact historical executing revision; authoritative endpoint/source-epoch binding; that a reported zero or one can become actual generation; that signature validity authenticates generation; or that this evidence resolves Router's other workflow/qualification/coverage obligations.

## Minimal Router decision input

Keep the existing strict stop. Full original-generation authority is **0 / 161,073 affected raws**. Unknown-origin linked metadata is **193,963 pairs**. The evidence rules out overlapping concrete generation sets and alternate exact candidates as the explanation for the prior pair counts, but it does not support an enrichment rule.

**B is the current recommendation.** If coordinated work resumes, **C** means a separately reviewed reconciliation design that preserves captured UNKNOWN_LEGACY, raw identity, original hashes, audit/qualification history, and captured-generation watermarks. This report authorizes no such implementation. Fresh observations or more counts cannot reconstruct missing historical generation authority; any proposed enrichment would need actual historical proof or a separately specified representation that does not claim an observed generation.

## Query and validation record

The machine-readable artifact preserves the diagnostic source, query definitions Q1–Q11, schema column inventory, full joint vectors and marginals, historical code hashes, and sanitized reproduction outcomes. The diagnostic extraction used the complete compatibility table, then indexed cache-row lookups; it did not repeatedly join the full warehouse per record. Alternative matching used the room/sequence index and exact text hash. All new analysis artifacts were temporary.

Validation passed: JSON parsing, aggregate sum/distinct/joint invariants, embedded diagnostic syntax/source hashes, output privacy checks, sanitized historical path assertions, and `git diff --check`. No runtime test suite was run. Recursive inspection of metadata, message envelopes, and parsed JSON/TCLK text found no generation-named field in any affected record; raw transport metadata contains only envelope-serialization and hash-basis annotations.

Final source DB/WAL fingerprint and WAL hash, Scout/Router code and review hashes, worker diagnostics, Router state file metadata, and publication-pointer inventory match baseline. Services `com.flop.scout.poll`, `com.flop-scout.worker`, and `com.greg.flop-router.worker` remain unloaded. No Scout worker/service-poll process or production DB/poll-flock handle was found. No network requests, production writes, private-key access, Router edits, deployments, commits, or pushes occurred.

A combined final-check escalation was rejected over concern about recursive state-file hashing and did not execute. The completed checks used Router state **stat metadata only**, pointer path inventory, and separate read-only service/process inspection; no check remains blocked.

The new APFS copy, skinny analysis DB, diagnostic scripts/logs, and tracker were removed. Production backups and preexisting artifacts were preserved. Sanitized diagnostic source remains embedded in the aggregate JSON for reproducibility.

Only the two generation-authority report files were created by this task. Every other entry below predated this task.

```text
 M README.md
 M flop_scout.py
 M scout_runtime.py
 M scout_schema.py
 M scout_worker.py
?? docs/router-projection-v2-benchmark.json
?? docs/router-projection-v2-generation-authority-evidence.json
?? docs/router-projection-v2-generation-authority-evidence.md
?? docs/router-projection-v2-implementation.md
?? docs/router-projection-v2-production-dry-run.json
?? docs/router-projection-v2-production-dry-run.md
?? docs/router-projection-v2-schema.sql
?? docs/router-projection-v2-source-review.md
?? scout_projection.py
?? scout_projection_cli.py
?? scout_projection_contract.py
?? scout_projection_model.py
?? scout_projection_pins.py
?? scout_projection_publish.py
?? scout_projection_rules.py
?? scout_projection_service.py
?? scout_projection_source.py
?? scripts/benchmark_projection_v2.py
?? scripts/projection_audit_stress.py
?? scripts/projection_fixture_support.py
?? scripts/projection_v2_fixtures.py
?? test_scout_projection.py
```
