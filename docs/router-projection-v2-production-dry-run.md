# Production-data V2 dry-run: source consistency blocks qualification

**Result: BLOCKED_SOURCE_CONSISTENCY. No valid projection or publication was produced.** The unchanged V2/A1 producer stopped at source event 9, after mapping eight records, with `Compatibility generation mismatch`. None of the requested performance classifications can honestly be assigned before a valid source cut is completed. This is not a successful zero-row projection.

## Production source and safe copy

- Source database: **52,022,870,016 bytes (48.450 GiB)**; WAL 115,392 bytes.
- Snapshot time: `2026-09-08T20:58:37.080138+00:00`.
- Temporary snapshot: `/private/tmp/scout-production-v2-axyr_y2_/source.sqlite`; measurement artifacts removed after reporting (see safety evidence).
- Method: APFS clone of quiescent DB + WAL; unchanged inode/size/mtime/ctime, WAL SHA256 and SQLite data_version checked across clone. Cloning took 0.005564 seconds. Available space was smaller than a full warehouse allocation, so APFS copy-on-write cloning avoided a second 48 GiB allocation.
- The frozen clone passed `PRAGMA quick_check` in 860.90 seconds. A second temporary APFS clone received the producer's indexes/outbox; the frozen copy remained unchanged during validation.
- Scout worker, Router worker, and old Scout poller were already unloaded before measurement. No source writer handles were reported. SQLite was opened with `mode=ro` and `query_only` for source consistency checks, then closed; no long live read transaction was held.
- Database/WAL identity, size, nanosecond mtime/ctime, WAL SHA-256 and SQLite data_version were checked across cloning. All construction and diagnostics used temporary copies.

| Source table | Exact rows |
| --- | ---: |
| raw_network_records | 4,289,850 |
| observed_events | 4,289,850 |
| messages | 4,289,843 |
| evidence_records | 4,282,049 |
| interactions | 11,908 |
| compatibility_evidence_links | 9,460,539 |
| tclk_frames | 383,824 |
| kibble_events | 323,565 |

Snapshot maximum committed derived event ID: `4289850`. Equality of raw/event totals alone does not prove all compatibility provenance is valid.

## Exact blocker

- Event: **9**; room `lobby`; sequence **21594285**; source `legacy_evidence`.
- Raw record: `b40d6a6b0f15025eec30a9fb4bd78d07f3436d9d320a71820f10ede125c35c2b`.
- Raw generation: SQL NULL, which maps to `UNKNOWN_LEGACY`.
- Linked `evidence_records` generation: string `"0"`.
- Both link and raw record bind text SHA-256 `b4672806e8224b692b1d38aaf908b181ed16de463c877699db37790263ae8990`; room and sequence match. Those matches do not establish generation identity.
- The messages compatibility table has no generation column; the conflict is in the verification-cache link.
- The [reviewed source mapping](router-projection-v2-source-review.md#source--v2-field-mapping) explicitly requires matching generation and says conflicting matches fail; NULL and zero cannot be aliased. The producer failure therefore cannot be bypassed as a harmless sizing adjustment.
- Temporary index/outbox preparation took 85.87 seconds; the attempt stopped after 110.57 seconds total. These are producer bootstrap timings, not Router preparation timings.

Generation-conflicting linked pairs in the full diagnostic scan: `[{"raw_generation": null, "cache_generation": "0", "n": 127146}, {"raw_generation": null, "cache_generation": "1", "n": 33927}]`.

## Requested projection / Router measurements

| Metric | Result |
| --- | --- |
| Projected messages / relational rows | Not available: no completed cut |
| Projection DB size / index size / bytes per message or row | Not available for a valid projection |
| Provenance / interactions / workflows / durable qualifications / events / pins / dependencies / watermarks | Not available for completed production-shaped output |
| Permanent/pinned, active/unresolved, 30-day context, 90-day capability, closed work/TCLK | Not available without completed classification/workflow/qualification evaluation |
| Records expiring today | Total unknown; ordinary/capability age cutoffs remove zero source records at this snapshot |
| Router copy / hash / integrity / schema-watermarks / qualifications / compact index / routing-ready time | Not run: no valid publication |
| Router peak RSS / changed-content preparation / heartbeat | Not measured: no accepted content or reusable cache |
| Performance readiness / headroom | Unassigned; source consistency blocks evaluation |
| Top projection size / Router latency driver | Unmeasured; do not substitute warehouse or producer timings |

The failed attempt left an **86,016-byte initialized projection** with zero message, interaction, provenance, membership, qualification, event, watermark and coverage-history rows, plus one metadata row. The **237,568-byte private ledger** has one STAGING evaluation, zero staged input rows, workflows, pins, dependencies and publication records. The eight mapped records had not filled the first 200-row staging batch. These empty intermediate counts are not the real production projection composition. Exact partial table/index page allocations are preserved in the JSON evidence, labeled `partial-state`.

No pin export was found in the inspected Scout/agent state trees. No pin was imported and no empty export was used to override a live interchange. There is no existing V2 historical ledger in this dry-run: even a successful fresh bootstrap would not reconstruct unavailable historical qualifications or external pins.

## Source shape and policy reduction models

The source has **4,284,680 signed-DID candidates** out of 4,289,850 raw records. These are candidates, not accepted projection rows or proof of offline authenticity. Maximum per-sender raw count in this snapshot is 38,603.
Trusted first-observed range is `2026-08-27T11:31:43.151383+00:00` through `2026-09-07T16:49:42.802203+00:00`. At `2026-09-08T21:11:25.799549+00:00`, **0 records were at least 14 days old**. Raw text totals 486,513,421 UTF-8 bytes (463.98 MiB), averaging 113.41 bytes/raw record. This is source raw text only, not projection size or a table-page estimate.

| Model, without changing policy | Current message savings | DB savings / resulting count |
| --- | ---: | --- |
| Ordinary context 30 → 21 days | 0 | 0 from this change; valid baseline unavailable |
| Ordinary context 30 → 14 days | 0 | 0 from this change; valid baseline unavailable |
| First-observed capability 90 → 60 days | 0 | 0 from this change; valid baseline unavailable |
| First-observed capability 90 → 45 days | 0 | 0 from this change; valid baseline unavailable |
| Closed work based on trusted proof first-observation, 90 → 60/45 days | 0 | All such proof observations are younger than 14 days |
| Closed TCLK based on validated offer deadline, 90 → 60/45 days | Unknown | Requires authoritative workflow evaluation; cannot infer from record age |

No durable qualification, event, identity/operator fact, required witness, negative evidence, active workflow or pin/dependency was removed. No contract or selection policy was edited. Exact total projected counts/sizes for these models require a valid baseline; reporting a synthetic estimate as a production measurement would be misleading.

Existing source classifications (not V2 retention reasons): `{"IDENTITY_PRESENCE": 44923, "MALFORMED_UNVERIFIABLE_EVENT": 78065, "PROMOTIONAL_CLAIM": 61, "TCLK_TRANSCRIPT_EVENT": 342706, "UNCLASSIFIED": 3824094, "WORK_RESULT": 1}`. The high source cardinality is a capacity concern, but this failed build does not establish which published table or Router stage dominates.

## Recommendation and next gate

**Do not proceed toward deployment (A).** Resolve the legacy raw/verification-cache generation conflict under the existing provenance contract, preserving UNKNOWN_LEGACY and immutable IDs; then rerun this unchanged-limit dry-run. Do not assign generation zero, drop the failing record, omit proof, or publish an empty substitute merely to complete a benchmark.

B (policy tightening), C (Router optimization), and D cannot be selected from a missing valid performance measurement. The tested context/capability horizon reductions offer zero immediate savings on this snapshot. Source-consistency resolution is a prerequisite outside those performance-only alternatives. Keep the 30-second / 512 MiB / 4 GiB guards and the preferred 20-second / ~80k-message target unchanged.

## Safety and cleanup

No Scout/Router implementation, contract, live database, identity, publication, launchd configuration or service was modified. No key contents were opened, no network requests were made, and nothing was committed or pushed. Only this report and its aggregate JSON evidence were added to the repository.

Live Scout was already STOPPED with stale diagnostics at baseline; it cannot be certified as running/healthy. Services were not started to satisfy that requested check. Final source, Router state/code and pointer comparisons and launchctl results are in the JSON evidence.

Cleanup is restricted to the exact newly created temporary measurement root and scripts/logs. Prior synthetic benchmarks, production backups, live databases and publication files are excluded.

[Aggregate evidence and partial table/index allocations](router-projection-v2-production-dry-run.json)

Final verification: `{"source_db_wal_stat_unchanged": true, "source_wal_sha256_unchanged": true, "router_state_file_metadata_unchanged": true, "router_candidate_code_unchanged": true, "inventoried_publication_pointers_unchanged": true, "inventoried_pointer_count": 0, "services": {"com.flop.scout.poll": {"returncode": 113, "unloaded": true, "message": "Bad request.\nCould not find service \"com.flop.scout.poll\" in domain for user gui: 501"}, "com.flop-scout.worker": {"returncode": 113, "unloaded": true, "message": "Bad request.\nCould not find service \"com.flop-scout.worker\" in domain for user gui: 501"}, "com.greg.flop-router.worker": {"returncode": 113, "unloaded": true, "message": "Bad request.\nCould not find service \"com.greg.flop-router.worker\" in domain for user gui: 501"}}, "scout_lifecycle_before": "STOPPED", "scout_lifecycle_after": "STOPPED", "scout_diagnostics_unchanged": true, "production_health": "Preexisting STOPPED/unloaded; not certified running healthy", "temporary_root_removed": true, "redundant_cross_checks_cancelled_after_full_count": true}`.
