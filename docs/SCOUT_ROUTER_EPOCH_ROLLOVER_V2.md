# Scout/Router bounded epoch rollover V2 — Phase 0 contract

**Status:** proposed design contract only.  This document neither enables V2 nor
authorizes a publication, database migration, service change, or deletion of an
existing artifact.  All examples use synthetic identifiers.

## 1. Purpose and non-goals

V2 permits an active Scout epoch to remain bounded while preserving auditable,
immutable history across epoch transitions.  It addresses the current A1
property that an append-only `current_inputs` set eventually reaches
`MAX_ENROLLED=50000` and cannot be compacted safely.

It does **not** change the meaning of a signed source record, make remote text
trusted, change same-operator rules, infer qualification from a signature, or
add any wallet, settlement, or network-write behavior.  A V2 implementation
MUST retain every A1 verification that applies to data present in an active
epoch.  It MUST reject a candidate when any required archive or commitment
cannot be verified.

The schema name proposed here is `flop-scout-router-epoch-rollover/v2`.  It is
an extension contract, not a replacement interpretation of existing
`flop-scout-router-snapshot/v2` artifacts.  Active A1 publications remain V1
continuations for acceptance purposes until a deliberately authorized first V2
transition.

## 2. Existing contracts: reuse and limits

| Existing concept | Reuse in V2 | Insufficient by itself |
| --- | --- | --- |
| Canonical JSON and SHA-256-bound pointer/manifest/database artifacts | Every descriptor and commitment is canonicalized and hash-bound. | A pointer/hash alone does not prove omitted historical evidence remains available. |
| A1 `source_checkpoint` (`source_id`, `epoch`, `committed_event_id`) | Bind each active epoch to its source identity and non-regressing cut. | A1 requires the same epoch forever; V2 needs an authorized epoch transition. |
| A1 `_extension` row/history/provenance checks | Remain mandatory within an epoch and for the predecessor evidence retained in the active set. | A1 permits omission only after ordinary expiry and cannot represent archived mandatory evidence. |
| `source_coverage_state.retained_floor` | Evidence-grounded per-domain floor input; nullable additive column remains a coverage observation. | It is not itself an archive commitment, an authorization to omit data, or a proof that mandatory closure is preserved. |
| Immutable coverage/provenance tables and triggers | Supply inputs to durable-history and coverage-witness commitments. | They do not bound the Router validation chain. |
| Router cached accepted projection / revision-history archive handling | Provides the single verified predecessor against which a candidate is checked. | Existing revision history is small and revision-oriented, not a general epoch archive protocol. |

V2 MUST NOT reuse a retained floor as a deletion instruction, treat archive
paths as authority, accept a changed source identity without an exact
predecessor binding, or relax A1 checks for V1 publications.

## 3. V2 manifest extension and field contract

All fields are required for a `CONTENT` V2 epoch-transition artifact unless
marked conditional.  Integers are JSON integers, never floats; identifiers are
bounded ASCII lower-case hex or documented prefixed strings; timestamps are UTC
RFC3339 `Z` strings with microseconds permitted.

| Field | Type / bound | Meaning and validation |
| --- | --- | --- |
| `epoch_rollover` | object, canonical JSON <= 64 KiB | Versioned V2 envelope; no unknown fields until a later explicit revision. |
| `epoch_rollover.schema` | exact string | `flop-scout-router-epoch-rollover/v2`. |
| `epoch_number` | integer `>= 1` | Strictly greater than the Router-accepted predecessor epoch number. |
| `epoch_id` | `se2:` + 64 lower-case hex | `SHA256(domain("epoch-id"), scout_source_binding, epoch_number, creation_cut, predecessor_commitment)`. Unique; never reused. |
| `created_at` | UTC timestamp | Creation time, `>=` predecessor published time; not a substitute for source freshness. |
| `source_binding` | object | Exact Scout/source identity: `source_id`, source `epoch`, and an immutable source descriptor/hash. |
| `source_cut` | object | `source_id`, source epoch, `committed_event_id`, and cut evidence hash.  Event id never regresses for the same source binding. |
| `predecessor` | object | Exact accepted predecessor commitment detailed in section 4. |
| `archive` | object | Immutable predecessor archive descriptor detailed in section 5. |
| `retained_floor_commitment` | object | Deterministic coverage/history/closure commitment detailed in section 6. |
| `active_epoch` | object | Bounded active set policy and actual counts detailed in section 7. |
| `rollover_state` | object | Final immutable state record.  Only `PUBLISHED` is admitted in a public manifest. |
| `contract_revision` | exact string | `A1-EPOCH-V2`; V1 values remain accepted only through the old A1 path. |

The ordinary manifest remains responsible for `snapshot_id`,
`database_content_id`, `publication_kind`, `database`, artifact `sha256`,
`size_bytes`, `row_counts`, `watermarks`, `coverage_history`, selection policy,
and source checkpoint.  A V2 candidate MUST pass all normal manifest/database
hash, size, schema, SQLite integrity, provenance, qualification, membership,
fanout, workflow, freshness, and pointer checks before these new fields are
considered.

## 4. Exact predecessor binding

`predecessor` is an exact commitment, not a lookup hint:

| Field | Required value |
| --- | --- |
| `publication_id` | Router's last accepted `snapshot_id`. |
| `content_id` | Router's last accepted `database_content_id`. |
| `manifest_sha256` | SHA-256 of the canonical predecessor manifest bytes. |
| `artifact_sha256` / `artifact_size_bytes` | Hash and exact byte size of the predecessor database artifact. |
| `epoch_id` / `epoch_number` | Prior active epoch identity and number; a first V2 transition uses synthetic V1-origin identity computed from the already accepted V1 manifest commitment. |
| `source_cut` | Exact predecessor `source_checkpoint`. |
| `accepted_state_hash` | Domain-separated hash of the Router's durable accepted-predecessor record. |

Router MUST compare all fields to its already accepted state, not merely to a
publication currently available on disk.  Any mismatch, missing state,
publication/content regression, unexpected heartbeat, or arbitrary epoch jump
is rejected.  The first V2 transition is a separately gated migration from the
accepted V1 commitment; it does not retroactively relabel the V1 artifact.

## 5. Immutable archive binding

The predecessor evidence omitted from the active epoch MUST remain retrievable
as an immutable archive.  `archive` contains:

| Field | Rule |
| --- | --- |
| `schema` | Exact `flop-scout-epoch-archive/v1`. |
| `archive_id` | Domain-separated SHA-256 identifier over descriptor commitment. |
| `artifact_sha256`, `size_bytes`, `database_schema_version` | Exact immutable artifact contract; size bounded by configured maximum. |
| `locator` | Opaque relative retrieval identifier, not an absolute path or authority.  It may contain no `..`, NUL, symlink traversal, URI scheme, or unbounded text. |
| `previous_epoch_id`, `previous_manifest_sha256` | Bind archive to exactly the predecessor being retired. |
| `preservation` | `IMMUTABLE_RETAINED`; records the minimum retention policy/version and audit availability. |
| `archive_commitment_sha256` | Hash of canonical descriptor excluding this self-field. |

Scout writes/renames an archive only into a containment-checked immutable
archive root.  Router validates descriptor canonical bytes, locator syntax,
hash/size/schema and predecessor binding before acceptance.  It MAY cache a
verified archive locally under hash-derived ownership-safe paths.  If required
archive bytes are unavailable, unreadable, changing, oversized, corrupt, or
mismatched, Router rejects the V2 candidate fail-closed; it does not accept a
new active epoch on an archive promise.  Audit retrieval later rechecks the
same descriptor/hash and may perform full history inspection.

## 6. Retained-floor and omitted-history commitment

`retained_floor_commitment` is a canonical object with sorted entries keyed by
`(room, generation, domain)`.  Each entry contains the evidence-derived
`retained_floor` (or explicit `null` only where no floor has been established),
the omitted sequence intervals, coverage status/witness digest, and the
selection-policy version that produced it.  It additionally commits to:

- `mandatory_proof_closure_sha256`: canonical set/hash of every required
  identity, provenance, interaction/workflow, pin, terminal, and fanout proof
  carried forward or located in the archive;
- `durable_qualification_history_sha256`: canonical durable qualification
  identity/payload history, never an aggregate count alone;
- `coverage_witness_sha256`: canonical evidence coverage and retention-loss
  witness set;
- `permanent_pinned_evidence_sha256`: canonical permanent and pin-rooted
  evidence set; and
- `omitted_history_sha256`: canonical list of omitted projection identities,
  their archive location, and reason class.

Floors cannot claim coverage across unresolved gaps, confirmed retention loss,
or missing evidence.  A row may be omitted only if its exact historical identity
and required proof/qualification relationship appears in the archive commitment
and its omission is permitted by the deterministic policy.  Permanent, pinned,
unexpired, mandatory lifecycle, or proof-closure evidence is never silently
dropped.  A forged, lowered, reordered, missing, or non-evidence-grounded floor
is a rejection, not an opportunity to recompute a convenient value.

## 7. Active-epoch capacity and selection policy

V2 does not choose an arbitrary smaller number.  Let:

```
M = mandatory closure count after deterministic proof expansion
R = pinned/permanent/unexpired mandatory count
H = measured 12-hour ingestion headroom at configured high-rate percentile
S = fixed safety reserve for deterministic source-batch overshoot
T = configured target active enrollment
X = hard active maximum
```

Required invariant: `M >= R`, `T + H + S <= X`, and an active build succeeds
only if `M <= T <= X`.  The policy records all measured inputs and its version.
The exact `T`, `X`, source batch cap, high-rate percentile/window, and disk
budget are operator-approved constants, not inferred from this design document.

Selection is stable and total: policy version, required closure first, then
explicit class priority, source event order, and raw-record-id tie-breaker.
It includes source provenance, complete membership and qualification rules, and
the same bounded fanout safeguards as A1.  If closure alone exceeds `T` or `X`, a
rollover aborts before mutable staging/pointer publication.  It never evicts a
required record merely to meet capacity.

Rollover triggers at the earlier of: (a) projected time to `X` is 12 hours at
the measured high-rate ingestion estimate, (b) a scheduled cadence reaches its
cut, or (c) an operator-approved disk-growth threshold.  An acceleration that
reduces headroom below 12 hours triggers an immediate scheduled attempt and an
alert; repeated failure keeps the last accepted publication and requires human
intervention.  Epochs are repeated indefinitely; each retains an immutable
archive and a bounded active set.  Storage monitoring separately tracks active,
archive, staging, cache, and free-space bytes.

## 8. Router acceptance and bounded chain validation

Router recognizes V1/A1 exactly as today.  V2 is accepted only after a
Router-first, inactive feature gate is explicitly enabled for the first
transition.  For V2, Router:

1. completes ordinary artifact, database, trust, provenance, durable-history,
   coverage, membership, qualification, fanout, freshness, and A1-in-epoch
   validation;
2. validates canonical V2 field types, bounds, domains, and all hashes;
3. exact-matches `predecessor` to its durable already accepted commitment;
4. verifies archive descriptor and bytes, or rejects if unavailable;
5. requires `epoch_number == prior + 1`, a new derived `epoch_id`, and
   non-regressing source identity/cut according to the documented binding rule;
6. validates floor/omission/mandatory proof/durable history commitments and
   rejects loss or substitution; and
7. atomically stores only the accepted new predecessor commitment plus the
   verified archive descriptor/hash.

Normal polling validates one predecessor and one newly referenced archive, not
an unbounded chain.  It does not revalidate every older archive on every poll.
Audit mode can retrieve any archive by immutable descriptor and verify a chain
from a trusted checkpoint.  Checkpoints contain the prior commitment hash and
archive descriptor hashes, are append-only/hash-linked, and never permit a
rewritten history to replace a previously accepted commitment.

## 9. Atomic state machine and recovery

The private rollover journal is canonical, bounded, hash-linked to the
predecessor, and stored outside publication roots.  It has these states:

| State | Durable condition / retry rule |
| --- | --- |
| `PREPARE` | Exact expected predecessor locked and validated; retry only if it still matches. |
| `CUT_CAPTURED` | Immutable source cut and deterministic selected identities recorded.  Retry reuses them exactly. |
| `ACTIVE_BUILT` | Candidate active DB and archive staged, hashes/sizes recorded; no pointer changes. |
| `SCOUT_VERIFIED` | Both independent Scout verification passes and all commitment checks succeeded. |
| `ROUTER_VERIFIED` | Offline/isolated Router validator accepted exact staged bytes; production Router never writes Scout state. |
| `PUBLISHED` | Archive and candidate are durable, manifest/pointer atomically installed, acceptance receipt recorded. |
| `ABORTED` | Reason and immutable diagnostics recorded; last accepted publication is retained. |

Every transition is compare-and-swap on journal state plus predecessor hash.  A
crash can resume only the same selected records/cut/artifact hashes; otherwise
it aborts.  A partial archive, pointer, or state disagreement is fail-closed.
No recovery edits timestamps, changes a captured cut, deletes the predecessor,
or publishes an unverified candidate.

## 10. Canonicalization, bounds, and security rules

- Canonical UTF-8 JSON uses the existing repository canonical serializer;
  object keys are sorted, arrays are policy-sorted, no duplicate keys, NaN,
  floats, or non-finite values are permitted.
- Every digest is SHA-256 over canonical bytes prefixed with a fixed domain
  string and NUL separator, e.g. `flop-scout/epoch-v2/predecessor\0`.
- Self-hashes exclude only their own field.  All other nested commitment hashes
  are mandatory and independently recomputed.
- JSON descriptors, arrays, string lengths, archive/database sizes, row counts,
  path lengths, and archive count per transition have explicit bounded limits.
- Paths are relative opaque locators resolved under a designated root after
  containment checks; symlinks, special files, mutable files, ownership/mode
  violations, and TOCTOU changes are rejected.
- Signatures authenticate evidence but do not by themselves establish truth,
  authority, qualification, provenance completeness, or identity reputation.
  Same-operator and remote-content handling remain unchanged.

## 11. Compatibility and deployment order

1. Deploy Router V2 parsing/validator support first, still accepting V1 and
   with V2 acceptance inactive.  Validate only offline fixtures and isolated
   copies.
2. Deploy Scout V2 builder disabled; ordinary V1 refresh remains byte/behavior
   compatible and A1 checks unchanged.
3. Rehearse first transition on production-shaped isolated roots, including
   crash recovery and archive retrieval.
4. Obtain explicit approval for one first V2 transition.  Router feature gate
   is enabled before Scout publishes the candidate.
5. After a V2 publication, rollback is forward-only: retain the last accepted
   V2 artifact/archive and repair with a later V2 publication.  Downgrading a
   Router that cannot validate the accepted V2 chain is not a safe rollback.

## 12. Implementation slices and gates

| Slice | Scope / likely files | Tests and stop condition | Rollback |
| --- | --- | --- | --- |
| 1 | Pure canonical V2 model/validator, new Scout/Router shared fixture docs only. | Unit vectors, malformed/bounds/hash tests. Stop on any ambiguity in canonical model. | Drop unreferenced code; no state exists. |
| 2 | Router `scout_projection.py` V2 parser/validator behind inactive gate. | V1 regression suite plus V2 fixtures; reject unavailable archive/any predecessor mismatch. | Keep gate off; V1 reader unchanged. |
| 3 | Scout deterministic active-set/closure planner, likely new module plus coverage readers. | Fixture/copy DB only; prove policy determinism and no required loss. | No runtime wiring. |
| 4 | Staged builder/journal/archive/recovery, current-publication integration. | Isolated roots: crash at every state, double-run idempotency, both verifier passes. | Retain predecessor; remove only unreferenced staging after audit. |
| 5 | Cross-repository production-shaped rehearsal. | Backup-copy only; Router full validation, archive audit, performance/disk gates. | Delete disposable roots only after reporting. |
| 6 | Controlled Router-first deployment with inactive V2 gate. | V1 live health unchanged; gate/readiness telemetry. | Gate remains off or forward repair before V2 acceptance. |
| 7 | Controlled first Scout transition. | Explicit approval, exact expected predecessor, final Router receipt. | Forward-only V2 repair; accepted predecessor retained. |

## 13. Decisions still requiring operator approval

1. Target/hard active capacity and measured ingestion percentile/window.
2. Exact mandatory closure categories and whether any currently finite evidence
   becomes mandatory across an epoch boundary.
3. Archive storage backend, retention duration, independent backup, access
   controls, and audit service-level objective.
4. Whether source identity can change across epochs; if yes, the exact
   cross-source provenance/replay rule.
5. First-transition operational authority, feature-gate default, checkpoint
   retention, and the measurable performance/disk acceptance thresholds.
