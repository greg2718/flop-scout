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
marked conditional.  Integers are JSON integers, never floats. **Every V2
string, including keys, identifiers, timestamps, locators, and policy names, is
ASCII-only**; this deliberately leaves no Unicode-normalization ambiguity.
Identifiers are bounded lower-case hex or documented prefixed strings;
timestamps are UTC RFC3339 `Z` strings with microseconds permitted.

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

### 4A. Accepted anchor and A1 bridge

The first V2 transition may encounter a Router whose accepted A1 content is
older than Scout's currently published A1 content.  The wire contract therefore
uses `accepted_anchor`, `bridge_predecessor`, and `bridge_binding_sha256`, not
a singular predecessor.  Each descriptor has exactly
`publication_sequence`, `content_id`, `manifest_sha256`, `artifact_sha256`,
`artifact_size`, `source_kind`, `source_id`, and `source_cut`.  The binding is
`SHA256(domain("a1-bridge-binding"), canonical({accepted_anchor,
bridge_predecessor}))`; it binds identities only and is never evidence that a
Router validated the bridge.  Directness is derived solely from complete
descriptor equality.  Router must locally validate a differing A1 bridge.

The candidate source identity must equal the bridge identity, and cuts must be
non-regressing `accepted_anchor <= bridge_predecessor <= candidate`.  Archive
retirement binds the bridge manifest, not the accepted anchor.  No receipt,
mode, validation-success indicator, or Router-private state hash is permitted
in a Scout-produced manifest.

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

## 5. Immutable archive binding — Phase 3B-B format contract

The predecessor evidence omitted from an active epoch MUST remain retrievable
as a canonical `flop-scout-epoch-archive/v1` manifest plus immutable members.
This section specifies bytes and validation only.  It does not authorize archive
creation, publication, or Router acceptance.

### 5.1 Existing transition descriptor remains the outer binding

No V2 transition-wire field is added.  The existing `archive` object remains
the transition commitment and has its current exact fields.  For this format:

| Existing descriptor field | Required archive-manifest interpretation |
| --- | --- |
| `schema` | Exact `flop-scout-epoch-archive/v1`. |
| `locator` | Safe relative locator of the canonical archive-manifest JSON, not a member path. |
| `artifact_sha256` / `size_bytes` | SHA-256 and exact size of the complete canonical manifest bytes. |
| `database_schema_version` | Exact `flop-scout-epoch-archive-manifest/v1`. |
| `previous_epoch_id`, `previous_manifest_sha256`, `previous_bridge_binding_sha256` | Exact bridge predecessor identity, repeated byte-for-byte in the archive manifest. |
| `preservation` | Exact `IMMUTABLE_RETAINED`. |
| `archive_commitment_sha256` | Existing descriptor commitment; it therefore binds the manifest locator, hash, size, and bridge binding without changing the wire schema. |

`archive_id` is repeated in the manifest.  A descriptor hash alone is not a
promise that members exist: all member validation below remains mandatory.

### 5.2 Canonical archive manifest

The manifest is one canonical JSON object with exactly these fields:

```text
schema                         "flop-scout-epoch-archive/v1"
archive_id                     descriptor archive_id
manifest_commitment_sha256     self commitment defined below
accepted_anchor                complete A1 descriptor
bridge_predecessor             complete A1 descriptor
previous_bridge_binding_sha256 exact bridge binding
source_checkpoint              {source_id, source_epoch, source_cut}
legacy_recovery                {schema, commitment_sha256, validated_records, closure_count}
retention                      "IMMUTABLE_INDEFINITE_FIRST_TRANSITION"
members                        sorted member array
```

`accepted_anchor` and `bridge_predecessor` use the complete descriptor shape
from section 4A; neither is inferred from IDs or cuts.  `legacy_recovery.schema`
is exact `scout-legacy-a1-provenance-recovery/v1`; its commitment is the
domain-separated, local recovery result for this descriptor-bound bridge.  It
is evidence, never a Router receipt or a Scout wire assertion.

The required `members` roles are exactly and uniquely:

| Role | Required schema | Meaning |
| --- | --- | --- |
| `bridge_projection_sqlite` | `scout-router-projection/v2` | Exact bridge-predecessor projection artifact. |
| `source_evidence_sqlite` | `flop-scout-epoch-source-evidence/v1` | Exact immutable source-evidence SQLite subset used by recovery. |
| `legacy_recovery_json` | `scout-legacy-a1-provenance-recovery/v1` | Canonical, redacted local recovery result; never raw source text. |

Every member has exactly `role`, `locator`, `sha256`, `size_bytes`, and
`schema`.  Members sort strictly by `(role, locator)`; duplicate roles,
locators, hashes, or unsorted members reject.  The bridge member hash/size
must equal `bridge_predecessor.artifact_sha256`/`artifact_size`; the recovery
member hash must be the exact canonical recovery-result bytes whose commitment
equals `legacy_recovery.commitment_sha256`.

Canonical JSON is UTF-8, sorted keys, compact separators, no duplicate keys,
no floats/non-finite values, and ASCII-only strings.  The manifest commitment
is:

```text
SHA256("flop-scout/epoch-archive-manifest/v1\0" ||
       canonical(manifest with manifest_commitment_sha256 omitted))
```

The descriptor `artifact_sha256` is separately SHA-256 over the complete
canonical manifest bytes including that field.  This distinction prevents a
self-hash ambiguity while retaining the existing descriptor binding.

### 5.3 `flop-scout-epoch-source-evidence/v1`

The `source_evidence_sqlite` member is a normalized SQLite subset, not a copy
of a live observer database and not a broad current-source window.  For the
content-242 bridge it contains **exactly 49,808** `raw_record_id` values: the
complete `source_provenance.raw_record_id` set of the bridge projection, and
none of the 92 unrelated source rows.  For any later authorized bridge, its
raw-record count must exactly equal that bridge's provenance count and remain
`<= 50,000`.

Its schema identifier is exact `flop-scout-epoch-source-evidence/v1`; it has
only these normalized tables and no application-defined extras:

| Table | Required immutable content and constraints |
| --- | --- |
| `source_evidence_metadata` | Exactly one row (`singleton=1` PK with `CHECK(singleton=1)`), `schema='flop-scout-epoch-source-evidence/v1'`, `revision='legacy-a1-recovery/1'`, canonical DDL hash, accepted anchor, bridge predecessor, source checkpoint, previous bridge binding, recovery commitment, and raw/event/cache counts. |
| `raw_records` | Exact raw identity inputs: `raw_record_id`, source/room/generation/reported generation, sequence, sender, signature, nonce, raw text, recovered raw-text hash, and raw envelope.  PK `raw_record_id`; `UNIQUE(raw_record_id,raw_text_sha256)`; checks on bounded lower-case hashes and non-negative sequence. |
| `observed_event_witnesses` | Exact `event_id`, raw ID, and raw-text hash.  PK `event_id`; `UNIQUE(raw_record_id)`; composite FK to `raw_records`; each raw row has exactly one witness. |
| `compatibility_links` | `cache_table`, explicit stable source `cache_rowid`, raw ID, raw-text hash.  PK `(cache_table,cache_rowid)` and composite FK to `raw_records`; `cache_table` check permits only `messages`, `evidence_records`, `tclk_frames`, or `kibble_events`. |
| `messages`, `evidence_records`, `tclk_frames`, `kibble_events` | Only cache columns required by `exact_cache()` plus an explicit `cache_rowid INTEGER PRIMARY KEY` holding the original source SQLite rowid. Extraction must select `rowid AS cache_rowid` and preserve it verbatim; SQLite-generated replacement rowids are prohibited. Each cache row has exactly one matching compatibility link; no unlinked cache row is allowed. |

The following is the normative object set whose normalized DDL is hashed.  An
implementation may not add tables, triggers, views, or indexes to this member.

```sql
CREATE TABLE source_evidence_metadata(
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  schema TEXT NOT NULL CHECK(schema='flop-scout-epoch-source-evidence/v1'),
  revision TEXT NOT NULL CHECK(revision='legacy-a1-recovery/1'),
  canonical_ddl_sha256 TEXT NOT NULL CHECK(length(canonical_ddl_sha256)=64 AND canonical_ddl_sha256 NOT GLOB '*[^0-9a-f]*'),
  accepted_anchor_json TEXT NOT NULL, bridge_predecessor_json TEXT NOT NULL,
  source_checkpoint_json TEXT NOT NULL,
  previous_bridge_binding_sha256 TEXT NOT NULL CHECK(length(previous_bridge_binding_sha256)=64 AND previous_bridge_binding_sha256 NOT GLOB '*[^0-9a-f]*'),
  recovery_commitment_sha256 TEXT NOT NULL CHECK(length(recovery_commitment_sha256)=64 AND recovery_commitment_sha256 NOT GLOB '*[^0-9a-f]*'),
  raw_record_count INTEGER NOT NULL CHECK(raw_record_count BETWEEN 1 AND 50000),
  observed_event_count INTEGER NOT NULL CHECK(observed_event_count=raw_record_count),
  cache_link_count INTEGER NOT NULL CHECK(cache_link_count>=0 AND cache_link_count<=200000)
);
CREATE TABLE raw_records(
  raw_record_id TEXT PRIMARY KEY CHECK(length(raw_record_id)=64 AND raw_record_id NOT GLOB '*[^0-9a-f]*'),
  source TEXT NOT NULL, room TEXT NOT NULL, generation TEXT, reported_generation TEXT,
  seq INTEGER NOT NULL CHECK(seq>=0), sender_did TEXT, signature TEXT, nonce TEXT,
  raw_text TEXT NOT NULL CHECK(length(raw_text)<=65536),
  raw_text_sha256 TEXT NOT NULL CHECK(length(raw_text_sha256)=64 AND raw_text_sha256 NOT GLOB '*[^0-9a-f]*'),
  raw_record_json TEXT NOT NULL CHECK(length(raw_record_json)<=65536),
  UNIQUE(raw_record_id,raw_text_sha256)
);
CREATE TABLE observed_event_witnesses(
  event_id INTEGER PRIMARY KEY CHECK(event_id>=0), raw_record_id TEXT NOT NULL UNIQUE,
  raw_text_sha256 TEXT NOT NULL CHECK(length(raw_text_sha256)=64 AND raw_text_sha256 NOT GLOB '*[^0-9a-f]*'),
  FOREIGN KEY(raw_record_id,raw_text_sha256) REFERENCES raw_records(raw_record_id,raw_text_sha256)
);
CREATE TABLE compatibility_links(
  cache_table TEXT NOT NULL CHECK(cache_table IN ('messages','evidence_records','tclk_frames','kibble_events')),
  cache_rowid INTEGER NOT NULL CHECK(cache_rowid>0), raw_record_id TEXT NOT NULL,
  raw_text_sha256 TEXT NOT NULL CHECK(length(raw_text_sha256)=64 AND raw_text_sha256 NOT GLOB '*[^0-9a-f]*'),
  PRIMARY KEY(cache_table,cache_rowid),
  FOREIGN KEY(raw_record_id,raw_text_sha256) REFERENCES raw_records(raw_record_id,raw_text_sha256)
);
CREATE INDEX compatibility_links_by_raw ON compatibility_links(raw_record_id,cache_table);
CREATE TABLE messages(cache_rowid INTEGER PRIMARY KEY, room TEXT NOT NULL, seq INTEGER NOT NULL CHECK(seq>=0), text TEXT NOT NULL CHECK(length(text)<=65536), sender TEXT);
CREATE TABLE evidence_records(cache_rowid INTEGER PRIMARY KEY, room TEXT NOT NULL, generation TEXT, seq INTEGER NOT NULL CHECK(seq>=0), text TEXT NOT NULL CHECK(length(text)<=65536), did TEXT, sig TEXT, nonce INTEGER);
CREATE TABLE tclk_frames(cache_rowid INTEGER PRIMARY KEY, room TEXT NOT NULL, generation TEXT, seq INTEGER NOT NULL CHECK(seq>=0), raw_text TEXT NOT NULL CHECK(length(raw_text)<=65536), transport_did TEXT);
CREATE TABLE kibble_events(cache_rowid INTEGER PRIMARY KEY, room TEXT NOT NULL, generation TEXT, seq INTEGER NOT NULL CHECK(seq>=0), exact_text TEXT NOT NULL CHECK(length(exact_text)<=65536), sender_did TEXT);
```

The metadata row stores canonical JSON for the complete accepted-anchor,
bridge-predecessor, and source-checkpoint descriptors, rather than loose IDs.
Those JSON values must byte-canonically equal the archive manifest fields.
`previous_bridge_binding_sha256`, `recovery_commitment_sha256`, and all count
fields are separate scalar columns.  For content 242 the count invariants are
`raw_record_count=49808`, `observed_event_count=49808`, and cache/link counts
matching the rows actually retained; no aggregate alone substitutes for the
set-equality checks below.

The canonical DDL hash is defined without depending on SQLite's pretty-print
whitespace.  In fixed order by `(object_type, object_name)`, tokenize every
required `sqlite_master.sql` statement using SQLite's lexical grammar; reject
comments, unrecognized tokens, quoted identifiers, and objects outside the
named table/index set.  Serialize each token as canonical JSON
`[token_kind, token_text]`, with keywords upper-cased and unquoted identifiers
lower-cased.  Hash:

```text
SHA256("flop-scout/epoch-source-evidence-ddl/v1\0" ||
       canonical({schema:"flop-scout-epoch-source-evidence/v1",
                  objects:[[object_type, object_name, normalized_tokens], ...]}))
```

This hash binds tables, PK/unique/FK/check constraints, and required indexes;
it is not a promise of byte-identical SQLite pages.  The member's file hash
binds the produced bytes, while validation independently proves schema and
semantic equivalence.

Validation order is exact:

1. Securely open and hash/size-verify the archive manifest and members as in
   section 5.4; verify the source-evidence member role/schema first.
2. Open the held SQLite descriptor read-only with `query_only`; reject files
   above 1 GiB, a raw count above 50,000, metadata count != 1, or any bounded
   JSON/text/locator violation before materializing rows.
3. Run `PRAGMA integrity_check` and `foreign_key_check`; inspect required
   tables, indexes, and normalized DDL hash; reject missing/extra objects or
   any absent PK/unique/FK/check contract.
4. Require metadata's complete descriptors, bridge binding, source checkpoint,
   recovery commitment, and counts to exactly equal the archive manifest.
5. Compare raw IDs bidirectionally with bridge `source_provenance`: both
   `EXCEPT` directions empty and exact counts equal.  Then require exactly one
   event witness per raw, valid identity/text/hash recomputation, cut bound,
   and no orphan/extra raw, event, link, or cache row.
6. Re-run `exact_cache()` semantics for every present supported link and rerun
   the local legacy recovery; its count and commitment must equal metadata and
   manifest.  Any failure rejects the candidate/audit result fail-closed.

### 5.4 Bounds and safe retrieval

- Manifest bytes: <= 64 KiB; depth <= 16; objects <= 64 fields; arrays <= 256
  items; member count is exactly three.
- Every locator is ASCII, <= 256 bytes, relative, non-empty, has no empty,
  `.`, `..`, backslash, NUL, URI scheme, or absolute component.
- Each member is a regular file <= 1 GiB; total members <= 2 GiB.  Hash and
  size are lower-case SHA-256 and positive bounded integer values.
- The archive root is opened as a directory descriptor.  Implementations walk
  validated locator components with `openat`/`O_NOFOLLOW`, require regular
  files by `fstat`, hash through the held descriptor, and compare pre/post
  descriptor metadata plus exact size.  Path-based checks, symlink following,
  and check-then-open reads are forbidden.
- Descriptor, manifest, every nested descriptor, every member hash/size/schema,
  bridge binding, source checkpoint, and recovery commitment are independently
  checked.  Any unavailable, changing, oversized, malformed, ambiguous, or
  mismatched input rejects fail-closed.

### 5.5 Retention, Router verification, and crash handling

First-transition archives are immutable and retained indefinitely.  Scout
stages all members and the manifest beneath a containment-checked private
staging directory on the target filesystem; it hashes/fsyncs each member,
writes/fsyncs the manifest last, fsyncs directories, then atomically renames
the complete directory into the immutable archive root before publishing any
candidate pointer.  A crash leaves either no final archive or a fully
descriptor-verifiable one; partial staging is never published.

For the first legacy bridge only, Router independently performs the local
legacy-A1 recovery verification from the exact descriptor-bound bridge and
source-evidence members, records a Router-local result, and never accepts a
Scout-supplied receipt.  Ordinary later polling validates the manifest and
member hashes, not an ever-growing chain or a claimed receipt.  Audit retrieval
repeats descriptor/manifest/member verification and may repeat recovery; any
failure rejects the audit result and the candidate that requires it while
retaining the last accepted publication.

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
For the first deployment, `X` remains **50,000**; any later increase requires
an independently approved production-shaped rehearsal.  `T` is calculated, not
fixed.  `H` is at least 12 hours and uses the greater of a conservative measured
high-percentile ingestion rate and twice the recent mean.  `S` remains a
separate deterministic safety reserve.

Selection is stable and total: policy version, required closure first, then
explicit class priority, source event order, and raw-record-id tie-breaker.
It includes source provenance, complete membership and qualification rules, and
the same bounded fanout safeguards as A1.  If closure alone exceeds `T` or `X`, a
rollover aborts before mutable staging/pointer publication.  It never evicts a
required record merely to meet capacity.

Scheduling begins before capacity is exhausted: its trigger is `X - H - S`.
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

### Legacy-A1 local provenance recovery

Legacy A1 artifacts that omitted `source_provenance.raw_record_sha256` may be
examined only by a local, read-only recovery resolver.  This is recovery
evidence for Scout's own migration planning: it is **never** a Router receipt,
Router-private state, a producer-wire assertion, or an assertion that Router
accepted the recovered artifact.  The resolver requires an exact
caller-authorized descriptor and rejects any difference from the descriptor
verified by acquisition.  It recomputes immutable raw identity, verifies exact
source/event/cache witnesses and the declared source cut, and emits only
identifiers, hashes, event IDs, reasons, counts, and a domain-separated local
commitment.  It never changes the content bytes, manifest, pointer, or source
database.

Recovery is bounded before materialization: at most 50,000 source/projection
records, 1 GiB per supplied SQLite artifact, 64 KiB per raw JSON/text or
embedded JSON value, 64 coverage rows, and a 16 MiB canonical commitment
payload.  Missing, duplicate, oversized, malformed, mismatched, or ambiguous
evidence fails closed without echoing raw text.  The rule is limited to an
explicitly authorized legacy descriptor; it is not a generic provenance
substitution mechanism.  All future projections MUST carry a non-null,
validated `raw_record_sha256` for every source-provenance message.
- Every digest is SHA-256 over canonical bytes prefixed with a fixed domain
  string and NUL separator, e.g. `flop-scout/epoch-v2/predecessor\0`.
- Commitment views are precise: `archive_commitment_sha256` excludes only
  `archive_commitment_sha256`; `retained_floor_commitment_sha256` excludes only
  `retained_floor_commitment_sha256`; and `transition_sha256` excludes only
  `commitments.transition_sha256`.  Every other field, including all nested
  commitments, remains in its corresponding canonical view.
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
4. Obtain explicit approval for one first V2 transition.  Its authority is a
   local operator action bound to exact predecessor values; network content
   cannot trigger it.  The first transition keeps source identity unchanged.
   Router feature gate is enabled before Scout publishes the candidate.
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

1. Target capacity and measured ingestion percentile/window; the first hard
   maximum is fixed at 50,000.
2. Exact mandatory closure categories and whether any currently finite evidence
   becomes mandatory across an epoch boundary.
3. Archive storage backend, retention duration, independent backup, access
   controls, and audit service-level objective.
4. Later-epoch source-identity changes, if ever allowed, and their exact
   cross-source provenance/replay rule.  The first transition cannot change it.
5. Checkpoint retention and measurable performance/disk acceptance thresholds.
