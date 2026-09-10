# Scout V2/A1-LG1 implementation review

Scope: local Scout implementation and synthetic qualification, 2026-09-08.
No live production state, Router files, services, deployment, commit, push,
network request, or operator identity was accessed or changed by this task.
The self-test uses its existing ephemeral local cryptographic test.

SCOUT_A1_LG1_IMPLEMENTED = YES
SCOUT_A1_LG1_FIXTURES_READY = YES
PRODUCTION_QUALIFIED = NO
NO_MATERIAL_PERFORMANCE_REGRESSION = NO

The approved audit representation is implemented. Required source checks remain
strict. Synthetic tests and fixtures support correctness review. **The admitted
legacy population has material measured storage and processing overhead; the
requested no-material-overhead condition is not satisfied.** This report does
not authorize a production dry-run or deployment.

## Pre-flight and files changed

Read the repository AGENTS.md and README, complete source review, original V2
implementation review, generation-authority evidence, and the approved Router
`docs/SCOUT_ROUTER_SNAPSHOT_V2.md`, including its LG1 extension. Confirmed
`contract_revision=A1-LG1` and the exact
`router-legacy-generation-authority/v1` policy. Pre-existing dirty files matched
the prior evidence report's source hashes; no unexpected source changes were
found. Branch: `feature/tclk-discovery`; HEAD at pre-flight:
`e24636b409d26f74d981619e0521973cae68c870`.

Changes made for this task:

| File | LG1 change |
|---|---|
| `scout_projection_contract.py` | Exact policy, revision dispatch and closed annotation validation. |
| `scout_projection_legacy.py` (new) | Narrow source proof, original-record reconstruction, immutable audit continuity. |
| `scout_projection_source.py` | Source mapping, policy-bound outbox parts, late raw/retrieval invalidation, bounded linkage checks. |
| `scout_projection.py` | Private originals, replay binding, explicit migration and A1 archive, retained-proof checks, diagnostics. |
| `scout_projection_publish.py` | Closed manifest shapes, revision-aware database/history checks, forced transition CONTENT publication. |
| `scout_projection_cli.py` | Explicit initialization revision and `migrate-lg1` command. |
| `scout_runtime.py` | Configured outbox revision and scoped source-rejection diagnostics. |
| `test_scout_projection.py` | Existing manifest assertion uses the declared default revision. |
| `test_scout_projection_lg1.py` (new) | Source, authority, replay, migration, wire, negative evidence and diagnostic tests. |
| `scripts/projection_lg1_support.py` (new) | Explicit synthetic sources, public-byte identities and optional test-only verification premise. |
| `scripts/projection_lg1_fixtures.py` (new) | Eight temporary Router fixtures. |
| `scripts/benchmark_projection_lg1.py` (new) | Fresh-process paired synthetic overhead benchmark. |
| `README.md` | Links this review and identifies LG1 as unqualified for production. |
| This report and `router-projection-v2-lg1-benchmark.json` | Results, limitations and review evidence. |

Other dirty files in the final status predate this task. Earlier production
evidence reports, schema SQL, policy/classifier/rule modules and Router files
were not edited for LG1. No Technocore transport/protocol behavior was changed.

## A1-LG1 implementation and exact class detection

An eligible source must have actual raw generation NULL or UNKNOWN_LEGACY,
source `legacy_evidence`, legacy flag integer one, completeness PARTIAL, schema
`flop-scout-evidence/v1`, version one, and raw reported generation exactly string
`0` or `1`. It must have an exact evidence_records link whose original source is
`service-poll`. Other sources, versions, reports and unknown origins do not
receive the exception.

All applicable compatibility links are read, with an explicit 256-link bound
and failure beyond the bound. Every linked row must exist. Validate original
room, integer sequence, exact text/hash, required sender, available nonce,
signature and network timestamp. Full original named-column objects, including
schema-native IDs, are preserved without synthetic rowid fields. Evidence
locators use evidence_id; protocol locators use the full canonical record hash.
Every concrete-generation cache reference is represented and canonical-sorted.
Multiple rows in the same cache remain ambiguous and fail.

The raw identity is recomputed from its original source, captured/report values
and envelope. Normalized raw fields and the original derived event must agree.
The approved transport metadata contains only the known reconstruction/hash
markers; original endpoint/body/header/epoch proof must be unavailable. Supplied
transport assertions or retrieval evidence are outside this narrow exception.
No original transport authority is inferred from a service-poll cache label.

Search all raw identities at the same room, sequence and exact text hash,
regardless of source or generation. An alternate raw fails. New raw candidates,
retrievals and link/cache updates put affected inputs back in the opt-in outbox's
pending set. Conflicting late evidence cannot be treated as a harmless heartbeat.
These source indexes/triggers are installed only by explicit source preparation.

## Captured versus reported model and true conflicts

`messages.generation` stays UNKNOWN_LEGACY. The required ninth annotation key is
`legacy_generation`; it is null for interactions, normal concrete captures and
unrelated unknown captures. For an admitted message, its exact contract object
contains captured_generation, reported_generation, LEGACY_REPORTED_ONLY,
UNRESOLVED_LEGACY, migration/schema/source markers, actual raw ID, exact text
hash and all required cache references. There is no resolved_generation field.

UNKNOWN_LEGACY linked to both reports fails. Concrete captured 0 versus reported
1, and the reverse, fail. Missing/mismatched hashes, sender, room, sequence,
lineage, required linkage, alternate raw or unsupported migration also fail.
The exception relaxes only the reviewed captured-versus-reported comparison.
It does not repair unsigned, malformed, invalid-signature or DID-mismatch facts.
Representable adverse facts retain existing negative/audit semantics. Missing
required identity remains a blocker, not grounds to skip a selected source.

Raw warehouse rows, raw/event IDs, original timestamps, envelopes and source
hashes are untouched. Exact raw, event and cache originals are stored in hashed
private replay inputs. Stage/replay checks reconstruct the public audit object;
publication/reopen checks also require the originals for retained LG1 rows.
Neither changing nor removing a retained report/class is allowed. Valid new exact
cache links may add references; removing or changing existing references fails.

## Watermarks and interaction IDs

Coverage counts, min/max sequences and durable coverage witnesses use captured
UNKNOWN_LEGACY only. The report never creates coverage in 0/1 or continuity.
Diagnostic report counts are explicitly non-authoritative and separate from
coverage. Tests check replay and both public coverage tables.

`si1:` endpoint identities retain original raw IDs and captured generations.
Report values are absent from the canonical endpoint identity. Cache multiplicity
cannot create another interaction, and source resolution remains unambiguous.
The tests exercise endpoints with different reports but the same captured domain,
repeat insertion and replay. Interaction annotations always carry null LG1 data.

## Workflow and qualification semantics

Workflow root lookup continues to use actual captured generation, never reported
generation. Root provenance must independently satisfy the existing authority
checks. Tests provide explicit synthetic verified premises to exercise ambiguous
roots across reports; reports cannot choose an issuer, bridge a concrete domain,
or establish closure. No authentication or closure is invented for malformed or
unsigned protocol evidence. Existing unresolved-workflow behavior remains.

Durable qualification records keep their original source references, versions,
input manifests, evaluation IDs and first qualification times. No LG1 field is
added to a qualification. Report-only cache additions do not rewrite existing
qualifications or create another independent message. Retained qualification
dependencies keep their original UNKNOWN_LEGACY message and LG1 audit proof.

Local-family semantics remain `operator_group=local-flop-agent-family`,
`same_operator=true`, `independent_reputation=false` where applicable. The
same-operator Bench fixture uses explicit controlled local artifact premises;
it does not certify an external claim or independent reputation.

## Replay semantics, manifest versioning and explicit migration

The public SQLite user_version, schema and nine-table DDL are unchanged.
Selection/classifier/qualification versions are unchanged. LG1 manifests contain
all original A1 fields plus exactly one `legacy_generation_policy` field with
the full contract object. Manifest hashes bind the policy and database hash.
Mixed, missing, extra and unsupported manifest/annotation fields fail.

Private configuration, LG1 evaluation bodies and outbox message parts bind the
exact revision and policy. Edge-only LG1 cuts also carry a policy-bound empty
message part. A1 payloads are not silently interpreted as LG1. Historical A1
replay stays A1 until an explicitly recorded migration operation. Downgrade is
rejected. New initialization defaults to LG1; existing A1 state stays A1.

For a separately authorized local transition, the CLI provides:

```text
python flop_scout.py projection --db /absolute/temporary/projection.sqlite migrate-lg1
```

The command requires completed source and pin work, validates the old ledger,
and archives the old A1 projection/private-ledger pair in an exclusive sibling
`*.a1-archive-<unique-id>` directory. Files are hashed, fsynced and made read-only;
the command returns the archive path. A crash may leave an archive requiring
review; no old archive is overwritten or automatically deleted.

Migration adds null LG1 annotation slots to existing A1 inputs/derived rows,
retains old canonical input versions and qualification history, and records the
exact policy transition. Existing A1 inputs cannot acquire a new legacy class
through this operation. New eligible raw IDs undergo independent LG1 checks.
The first publication has a new content ID, immutable database artifact,
manifest and publication ID, even if no other data changed. It is CONTENT,
never an A1-artifact heartbeat. Later identical LG1 content can reuse its artifact.
Old immutable publications remain available under the existing retention rules.

## Status and diagnostics

Read-only `projection ... status` reports contract revision, exact policy,
`non_authoritative_report_counts` (0 and 1, including zero counts), total
`legacy_reported_only_rows`, last LG1 error and persisted rejection counts.
Projector/service status also provides the nested legacy_generation summary.

Counts are explicitly scoped: projector counters count bootstrap/consume
rejection attempts, persist across restart, and are not a distinct-population
census. Runtime `router_projection_source` diagnostics count source-capture
rejection attempts within that worker process. They expose the exact policy,
true generation conflicts, unsupported legacy inputs and last code, with no
raw message content. Repeated attempts can increment counts. Invalid sources
leave readiness blocked; a later census belongs in a separately authorized
frozen-copy dry-run.

## LG1 fixtures

Final temporary index:
`/private/tmp/scout-lg1-router-fixtures-final-20260908/index.json`.

| Fixture directory | Expected consumer result |
|---|---|
| `normal-concrete` | Accept; concrete generation, LG1 annotation null. |
| `legacy-reported-0` | Accept; captured UNKNOWN_LEGACY, reported 0. |
| `legacy-reported-1` | Accept; captured UNKNOWN_LEGACY, reported 1. |
| `true-conflict` | Reject; conflicting reports despite valid artifact hashes. |
| `heartbeat-reuse` | Accept; new publication, same immutable LG1 database. |
| `same-operator-bench` | Accept; controlled local Bench history, no independence. |
| `qualification-invalidation` | Accept audit event without rewriting qualification. |
| `unknown-without-lg1` | Accept; unrelated UNKNOWN_LEGACY, LG1 annotation null. |

All positive artifacts passed Scout's exact database validator and manifest
binding. The deliberately invalid artifact failed Scout semantic validation.
Normal/legacy private state reconstructs through replay. Temporary source and
private originals remain under the fixture root for development inspection.
Fixed synthetic clock: 2026-09-08T12:00:00.000000Z. Consumer freshness tests must
inject that clock. Router was not run or modified; its acceptance remains a
separate implementation/test task. No large production-style artifact is claimed.

## Performance overhead

See `router-projection-v2-lg1-benchmark.json` for the final measurements, all
individual trials, medians and percent changes. Each trial is a fresh process:
2,000 synthetic messages, one evidence-cache reference per row, three trials per
mode. Controls use identical payloads with no concrete report so strict A1 can
represent them. LG1_NULL measures revision/null-key overhead; LG1_REPORTED
measures the full admitted class, source proof and private originals. This is a
paired representable control, not an A1 acceptance of the previously blocked class.

Projection throughput includes source mapping, staging and complete-cut rules.
Publication includes producer history/original checks and public validation.
Validation is also measured independently. Peak RSS includes source setup.
Private-ledger size is additional to public artifact size. The final run is
performed after code changes, without concurrent Scout tests.

| Metric (median; 2,000 rows) | A1 control | LG1 null | LG1 admitted | Admitted change |
|---|---:|---:|---:|---:|
| Projection rows/second | 400.396 | 397.646 | 317.557 | -20.7% |
| Public database MiB | 2.660 | 2.766 | 4.406 | +65.6% |
| Private replay ledger MiB | 7.820 | 7.816 | 15.633 | +99.9% |
| Publication seconds | 0.090 | 0.090 | 0.660 | +636.4% |
| Validation seconds | 0.076 | 0.077 | 0.161 | +112.0% |
| Peak RSS MiB | 48.031 | 48.703 | 60.516 | +26.0% |
| Source mapping seconds | 0.366 | 0.348 | 0.636 | +73.6% |

The null-slot control changes throughput by -0.7%, database size by +4.0%, publication time by +0.7%, validation time by +0.9%, and peak RSS by +1.4%. The admitted class adds about 916 public bytes per selected row in this sample. Its private ledger is approximately twice the control size.

Admitted LG1 annotations and originals materially increase public/private storage
and processing. This cannot honestly be called no material regression. No field
was omitted, shortened or moved into generation authority to improve these
numbers. Absolute small-sample times/RSS do not establish the unchanged Router
4-GiB / 30-second / 512-MiB production gates. Multiple protocol references and
production distributions can have different overhead. No linear production
size/latency extrapolation is used as qualification evidence.

## Full validation

- Full Scout suite: **491 passed in 52.80 seconds** (418 prior tests plus 73 LG1 tests).
- Existing projection tests are included unchanged except the default manifest revision assertion.
- `flop_scout.py self-test`: **PASS**, no network write.
- `py_compile`: **PASS**, all 42 root/scripts Python files.
- `git diff --check`: **PASS**; new LG1 files also checked for trailing whitespace.
- Fixture pointer/manifest/database hash verification: **PASS**, all eight fixtures.
- Router changes: **none**. Production access/deploy/services/commit/push: **none**.

Validation used the repository `.venv/bin/python`, existing temporary pytest
package path `/private/tmp/scout-test-deps`, `FLOP_SCOUT_STATE_DIR` under
`/private/tmp/scout-lg1-*`, and a temporary bytecode cache. Logs:
`/private/tmp/scout-lg1-full-final.log`, `/private/tmp/scout-lg1-self-test.log`.
No production observer path was passed to any command.

The full suite covers scheduler fairness, SQLite checkpoint latency, publication,
heartbeat reuse, projection replay, qualifications, expiry and pin/dependency
handling. LG1 tests additionally cover class boundaries, immutable bindings,
negative evidence, captured authority, late conflicting inputs, reference
addition/removal, retained originals, A1 archives and explicit revision changes.
No test assertion was weakened to accept mixed generations or promote authority.

## Known limitations and Router changes required

The no-material-overhead criterion is not met. This is a correctness candidate,
not a production-qualified producer. The historical evidence report's unsigned,
missing-sender and malformed cases were not remeasured. LG1 does not certify that
all previously affected records can publish; any required invalid source must
still block the later dry-run. Diagnostics are scoped attempt counters rather
than a production population audit. Private replay growth is measured and must
be considered separately from the public 4-GiB limit.

Router still needs its own explicit revision/policy dispatch, projected LG1
binding/continuity validation, audit-only visibility and explicit accepted-state
migration. It must retain captured generations throughout profiles, workflows,
qualifications and interaction identities, exclude only the LG1 audit object
from routing-semantic deduplication, and reject conflicts before deduplication.
It must rebuild/rebind relevant private caches and reject A1 downgrade. These
changes were neither implemented nor tested here. Current A1-only consumers
must continue rejecting LG1.

## Production dry-run plan — not executed

After separate authorization and review of the material overhead:

1. Establish a complete, fenced source cut and make a frozen private copy under
   the established production procedure. Preserve original production state.
2. Prepare the optional source indexes/outbox only on the copy. Initialize or
   explicitly migrate a separate private LG1 projection; preserve old A1 state.
3. Run exact source checks and report accepted/rejected totals by authority,
   report and linkage/negative reason, including the known adverse populations.
   Do not drop required rows or enrich unresolved generations.
4. Check original IDs/text/event hashes, required dependencies/pins, historical
   qualification/event bytes and UNKNOWN_LEGACY coverage. Reconstruct by replay.
5. Produce no candidate publication if required source proof fails. If valid,
   measure actual immutable database size, publication/validation time and RSS.
6. Use that valid artifact for Router's separately qualified LG1 consumer under
   unchanged readiness limits. Neither this plan nor synthetic success authorizes
   service startup, rollout, network writes, commit or push.

## Final git status

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
?? docs/router-projection-v2-lg1-benchmark.json
?? docs/router-projection-v2-lg1-implementation.md
?? docs/router-projection-v2-production-dry-run.json
?? docs/router-projection-v2-production-dry-run.md
?? docs/router-projection-v2-schema.sql
?? docs/router-projection-v2-source-review.md
?? scout_projection.py
?? scout_projection_cli.py
?? scout_projection_contract.py
?? scout_projection_legacy.py
?? scout_projection_model.py
?? scout_projection_pins.py
?? scout_projection_publish.py
?? scout_projection_rules.py
?? scout_projection_service.py
?? scout_projection_source.py
?? scripts/benchmark_projection_lg1.py
?? scripts/benchmark_projection_v2.py
?? scripts/projection_audit_stress.py
?? scripts/projection_fixture_support.py
?? scripts/projection_lg1_fixtures.py
?? scripts/projection_lg1_support.py
?? scripts/projection_v2_fixtures.py
?? test_scout_projection.py
?? test_scout_projection_lg1.py
```
