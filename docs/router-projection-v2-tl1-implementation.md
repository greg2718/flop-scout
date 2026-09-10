# Scout A1-LG2-TL1 implementation review

Scout implements the approved structural boundary, immutable historical enrollment, compact TL1 table, domain holds, publication validation, replay, and diagnostics. This is a synthetic development qualification. Router implementation and coordinated operational qualification remain outstanding.

## Files changed

Relative to the fresh pre-task baseline `/private/tmp/scout-tl1-baseline-vznf7cn0`, modified Python files are `scout_projection.py`, `scout_projection_contract.py`, `scout_projection_source.py`, `scout_projection_compact.py`, `scout_projection_legacy.py`, `scout_projection_publish.py`, `scout_projection_cli.py`, and `scout_runtime.py`. Runtime changes only carry the registered cohort into the existing optional projection outbox.

New implementation and validation files: `scout_projection_tclk.py`, `test_scout_projection_tclk.py`, `docs/router-tclk-legacy-tl1-schema.sql`, and five scripts: `projection_tl1_support.py`, `projection_tl1_fixtures.py`, `benchmark_projection_tl1.py`, `stress_projection_tl1_capacity.py`, `verify_projection_tl1_schema.py`. README links this report; this report and `router-projection-v2-tl1-evidence.json` record the results. Existing unrelated dirty files were preserved. No Router changes, production data access, service starts, deployment, commit, or push occurred.

## Pin verification and official TCLK/1 parity

The approved local schema is exactly 6,070 bytes, SHA-256 `17071a2b3b21e8484cac9da7976088f3700e6fb6c1372268d4756b61ddd60c70`, from `flop-labs/tclk`, revision `5cc4ab93efbc8999a3a7e1471b639deca25998ea`, path `schema/tclk1-frames.schema.json`. No replacement or main-branch fetch occurred. Boundary: `tclk1-tl1-structural-schema/v1`; validator: `router-tclk1-structure/1`.

Scout implements the vocabulary used by those immutable schema bytes. An independent Ajv 8.17.1 Draft 2020-12 comparison of 2,120 generated mutations produced zero mismatches. The comparison caught the Python/ECMAScript end-anchor difference; Scout now rejects trailing line terminators where the pinned patterns do. This is structural parity evidence, not a claim of complete upstream decoder/state-machine conformance.

Normative ACCEPT still requires `ref` and `contract`; `offer_id` is unsupported. Authentication does not make a structurally invalid frame valid. Schema-passing records retain existing normative processing. Reference-rule diagnostics never determine cohort membership or add new normative transitions.

## Structural cohort implementation and four-case rule

| Pinned schema | Diagnostic decoder | Structural candidate |
| --- | --- | --- |
| FAIL | FAIL | Yes |
| FAIL | PASS | Yes |
| PASS | FAIL | No |
| PASS | PASS | No |

Admission additionally requires independently verified transport signature/authorship, immutable original raw/event provenance, explicit historical enrollment, and the approved class/reason/capacity rules. Missing or unparseable frame `from` does not falsely assert a transport DID mismatch; an actual conflicting supplied author still prevents authenticated admission.

Enrollment binds source ID, epoch, fixed through-event cut, count, and SHA-256 of sorted concatenated raw 32-byte IDs. Initial registration and explicit LG2 migration are ledger-anchored. Migration enumerates the entire quiescent source snapshot, rejects missing previous source originals, and compares the complete discovered cohort before activation. Enrollment cannot roll forward as new malformed frames arrive. Incomplete or conflicting evidence fails closed.

## TL1 classification, schema compliance, and nonconformance model

Eligible rows receive `TCLK_LEGACY_NONCONFORMING`, separate from authentication status, with no capability support or workflow mapping. The copied Router SQL matches byte for byte. TL1 adds the exact `legacy_tclk_records` table, with raw BLOB primary key, bounded type/mask, and generated `sm1:` message ID. The public artifact has 12 tables; the eight annotation keys and LG2 representation remain unchanged. Logical audit IDs are `lt1:` plus raw hex.

| Bit | Reason |
| --- | --- |
| 1 | MISSING_REQUIRED_REF |
| 2 | MISSING_REQUIRED_CONTRACT |
| 4 | UNSUPPORTED_OFFER_ID |
| 8 | MISSING_LINKAGE |
| 16 | MALFORMED_RECEIPT |
| 32 | CONFLICTING_CLAIMED_OFFER_HINTS |
| 64 | OTHER_SCHEMA_FAILURE |
| 128 | UNPARSEABLE_OR_AMBIGUOUS_JSON |
| 256 | INVALID_FIELD_TYPE_OR_VALUE |
| 512 | UNSUPPORTED_FRAME_TYPE |

Missing, invalid, and conflicting fields remain distinct. Malformed/nonobject/duplicate-key JSON gets only mask 128 and no arbitrarily selected claims. Unsupported bits fail closed. Receipt-like records use claimed type 2 and the receipt bit in addition to applicable field/linkage reasons. ACCEPT-like records use type 1; unavailable/nonstring type uses 0; other strings use 3.

## AUDIT_HINT model

Read-only claim views preserve ABSENT, PRESENT_NULL, PRESENT_TYPED_VALUE, AMBIGUOUS_DUPLICATE_KEY, and UNAVAILABLE_PARSE. Claims never alias an official identifier. Hints search independently authenticated, structurally valid, correctly hashed OFFERs in the same source, epoch, room, and captured generation. Multiple candidates stay ambiguous. Hints neither choose an offer nor create workflow edges, qualify capability, establish reputation, or narrow retention.

Hints are derived and paginated, with zero persisted hint-table bytes. Candidate groups are counted without expanding the full cohort-by-domain Cartesian product. Diagnostics include distinct candidate dependencies and ambiguity. Raw message text is not emitted by status; the explicit record audit view returns typed claims only.

## Retention hold model and dependency accounting

Before expiry, Scout finds complete provenance domains containing enrolled TL1 evidence and holds all TCLK records in those domains, including unmatched and later normative records. It expands both interaction directions and qualification/event references to a fixed point. Shared dependencies are unioned by stable identity. Every required dependency must exist; held messages and interactions have null expiry and `TCLK_LEGACY_AUDIT` unless an existing higher-priority permanent reason applies. There is no automatic release.

Byte accounting serializes each selected dependency row once as canonical JSON `[table,row-object]` plus newline, with BLOBs represented as hex. It includes messages, interaction rows, provenance, selection memberships, LG2 reports/witnesses, TL1 rows, and qualification/event dependencies. Snapshot metadata, coverage, and aggregate watermarks are not dependency rows in this metric. Disk allocation and canonical dependency bytes are different measurements.

## Capacity enforcement

Inclusive limits are exactly 4,096 enrolled records, 100,000 held messages, and 268,435,456 serialized dependency bytes. No truncation, sampling, oldest-row removal, or limit raising is implemented. Failed validation prevents advancing publication. The tests cover each exact bound and one above it.

Physical public-row stress results:

| Case | Result | Validation seconds |
| --- | --- | ---: |
| 99,999 held messages | PASS, 197,490,810 bytes | 31.094 |
| 100,000 held messages | PASS, 197,492,761 bytes | 31.009 |
| 100,001 held messages | TL1_HOLD_MESSAGE_CAPACITY | 0.682 |
| 268,435,455 bytes | PASS | 31.788 |
| 268,435,456 bytes | PASS | 31.714 |
| 268,435,457 bytes | TL1_HOLD_BYTE_CAPACITY | 10.468 |

These stress cases exercise actual public dependency accounting using synthetic replicated rows and padding. They are not full source-pipeline qualification artifacts. Maximum-size validation exceeds 30 seconds on this machine; the bounded model is correct, but operational deadline suitability is not established.

## Workflow, closure, qualification, scoring, and generation semantics

TL1 claims produce no accepted/closed transition, closure timestamp, settlement proof, execution proof, contract identity, or generation authority. A held domain stays unresolved for expiry purposes. Tests cover normative ACCEPT, alias-only ACCEPT, missing-link receipt, and authenticated malformed JSON; unsupported linkage never accelerates expiry.

TL1 and evidence retained solely by its hold are excluded from positive qualification observations and template peer counts. Negative evidence remains available. Independently eligible evidence can still qualify. Same-operator rules are unchanged. Existing historical qualifications and events remain byte-identical across migration; new evaluations use selection `router-evidence-horizons/3` and classifier `router-evidence-classes/3`, while qualification policy remains version 1.

A1-LG2 captured generation and normalized reports/witnesses are preserved. UNKNOWN_LEGACY is not promoted from claims or reported metadata, and hints do not cross generation domains.

## Replay, decoder drift, migration, and manifest versioning

Replay reconstructs explicit initial enrollment or migration, complete enumeration, holds, IDs, masks, dependency sets, qualifications, and public rows. Tests reopen an interrupted activation, resume the same cohort, archive the old accepted LG2 artifact, and replay the result. A decoder-drift test substitutes true/false/unavailable diagnostic results and verifies identical mapped evidence and cohort identity; structural vectors also remain unchanged.

Manifests emit only `A1-LG2-TL1` for TL1 semantics and bind all six schema/validator fields, exact policy, and immutable cohort. Heartbeats preserve those bindings and reuse the accepted database. Wrong pins, mixed representations, missing enrollment, or cohort overflow reject. Old accepted publications are archived during explicit migration. No implicit production migration was introduced.

Read-only `tl1-status`, `tl1-record`, and `tl1-hints` expose revision/pin, enrolled schema failures, diagnostic decoder counts, type/reason counts, hint ambiguity, holds, bytes/utilization, overflow, and last error. Decoder counts are explicitly labeled `PINNED_REFERENCE_RULES_DIAGNOSTIC_NOT_A_COHORT_INPUT` and scoped to enrolled evidence; they do not represent a full room scan.

## TL1 fixtures

17 temporary fixtures are available at `/private/tmp/scout-tl1-router-fixtures-final/index.json`. They include all four schema/decoder combinations, normative ACCEPT, alias-only ACCEPT, ambiguous and single-candidate hints, missing-link receipt, invalid signature, cross-generation candidate, same-operator evidence, heartbeat reuse, capacity-near-limit, capacity-overflow rejection, wrong pin, and mixed representation rejection. The near-limit artifact contains all 4,096 enrolled records; the separate physical stress exercise covers message/byte maxima. Manifest rejection fixtures have correctly recomputed outer hashes so their semantic rejection is observable. Router has not consumed these fixtures in this task.

## 2,505-record and 4,096-record results

These runs use actual synthetic signed source ingestion, mapping, enrollment, hold construction, and publication, with ACCEPT/receipt mixtures and ten additional expired normative OFFERs. Unmatched hints deliberately do not narrow the domain hold.

| Measurement | 2,505 records | 4,096 records |
| --- | ---: | ---: |
| ACCEPT-like / receipt-like | 2,373 / 132 | 3,880 / 216 |
| TL1 table allocation | 118,784 B | 188,416 B |
| TL1 bytes/record | 47.419 | 46.000 |
| Persisted AUDIT_HINT storage | 0 B | 0 B |
| Held messages | 2,515 | 4,106 |
| Serialized dependency bytes | 7,277,482 | 11,883,718 |
| Dependency rows | 17,595 | 28,732 |
| Held-message / enrollment amplification | 1.003992 | 1.002441 |
| Structural classification records/s | 79,239.6 | 77,866.5 |
| Enrollment records/s | 305.1 | 294.4 |
| Enrollment seconds | 8.210 | 13.913 |
| Hold computation seconds | 0.937 | 1.558 |
| Peak RSS | 113,328,128 B | 134,725,632 B |

Results and final artifact filenames are retained in `router-projection-v2-tl1-evidence.json`. Benchmark roots are `/private/tmp/scout-tl1-final-2505` and `/private/tmp/scout-tl1-final-4096`. The low amplification is a property of these synthetic domains, not a production estimate or upper bound. Candidate-rich ambiguity is covered by separate fixtures. No real production shape was measured.

## Existing LG2 regression and validation

A paired isolated 2,000-record LG2 benchmark against the pre-task snapshot measured update 3.753→3.821 seconds (+1.81%), expiry 0.994→1.008 (+1.41%), publication 0.900→0.856 (−4.93%), and validation 0.194→0.190 (−2.11%). Public size remained 3,239,936 bytes and private ledger size 14,413,824 bytes. Peak RSS decreased from 63,586,304 to 59,637,760 bytes. This single paired run is compatible with ordinary measurement noise; it is not a statistical performance guarantee. Existing scheduler/checkpoint tests remain part of the full suite.

Full pytest suite: **643 passed in 61.58 seconds**, including all 584 baseline tests and 59 TL1 tests. Local signature self-test: PASS. Python compilation of all root and scripts Python files: PASS. `git diff --check`: PASS. Exact DDL and approved pin checks: PASS. Ajv structural comparison: 2,120 cases, zero mismatches. Both benchmark databases were revalidated with the final producer validator.

## Known limitations, Router changes required, and production dry-run readiness

The schema interpreter intentionally supports the pinned schema vocabulary, not arbitrary future JSON Schema. Decoder diagnostics port selected pinned reference rules and are not execution of the upstream TypeScript decoder. Future reconciliation and release of historical holds remain unimplemented by design.

Router still needs its independent TL1 manifest/schema validator, cohort verification, identical hold/dependency accounting, read-only audit views, and closure/qualification exclusion, followed by consuming the supplied fixtures. Maximum-bound validation took approximately 32 seconds, so a coordinated deadline/performance decision is required before treating the capacity ceiling as operationally qualified. No automatic deadline or capacity increase was made. Neither synthetic amplification nor these timing runs establishes production load readiness.

The Scout producer is ready for Router implementation. Coordinated production dry-run readiness is NO until Router implementation, fixture parity, and operational deadline qualification are complete.

```
SCOUT_A1_LG2_TL1_IMPLEMENTED = YES
SCOUT_TL1_FIXTURES_READY = YES
TL1_CAPACITY_MODEL_ACCEPTABLE = YES
SCOUT_A1_LG2_TL1_READY_FOR_ROUTER_IMPLEMENTATION = YES
SCOUT_A1_LG2_TL1_READY_FOR_PRODUCTION_DRY_RUN = NO
```

Capacity-model acceptance here means exact, bounded, fail-closed accounting; it does not certify maximum-size processing within Router's operational deadline.
