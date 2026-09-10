# Scout → Router V2 coordinated source decisions

## DECISION STATUS

Scope: documentation and temporary fixture validation only. No projector,
classifier, schema migration, runtime, CLI, service, or Router change is implemented.
This replaces the earlier list of open mapping questions with explicit Scout-side
decisions and one coordinated selection-policy amendment. Proposed amendment text
is not an assertion that Router has accepted it.

Baseline: `feature/tclk-discovery`, `e24636b409d26f74d981619e0521973cae68c870`.
The only pre-existing worktree change was this document. Read AGENTS.md, this
review, the complete Router `SCOUT_ROUTER_SNAPSHOT_V2.md` and its benchmark.
Source inspection covered raw/events, compatibility messages/evidence/edges,
Kibble/TCLK transcripts, Bench request/result normalizers and Router's evidence,
interaction and same-operator handling. No production data or identities were read.

| Gate | Status | Decision |
| --- | --- | --- |
| Interaction ID | RESOLVED | SHA-256 over immutable, role-ordered source identities; no database edge IDs |
| Classifier order | BLOCKED | Explicit ordering resolved below; permanent support vs subsequent duplicate downgrades needs amendment A1 |
| Workflow closure | RESOLVED | Protocol-specific authority and linkage; otherwise unresolved; immutable local observation clock |
| Pin format | RESOLVED | Explicit cumulative local interchange, immutable additive pins, PERMANENT only |
| Transitive dependencies | RESOLVED | Typed minimal evidence graph, deterministic closure, fail closed on missing local dependencies |
| Source mapping | RESOLVED | Exact seven-table mapping below; unrepresentable selected evidence blocks publication |
| Negative evidence | RESOLVED | Provenance-backed failures/contradictions, not criticism or reputation by allegation |
| Raw text policy | RESOLVED | Full selected text once in messages; no reconstructed raw envelope hash masquerading as original bytes |
| Operator semantics | RESOLVED | Canonical local family; explicit legacy alias; consumer validates, never upgrades independence |

`IMPLEMENTATION_READINESS = BLOCKED` pending A1. Missing production mappings or
pin exporters are deployment inputs, not excuses to invent source facts. No live
census is attempted. The current Router consumer is V1; future V2 consumer work
and foreground qualification remain separate requirements.

## INTERACTION ID CONTRACT

Canonical encoding `C(x)` for all **new** IDs in this document:
UTF-8 JSON, object keys sorted lexicographically, compact `,`/`:` separators,
`ensure_ascii=false`, `allow_nan=false`, no BOM or trailing newline. Reject
invalid UTF-8/lone surrogates, duplicate keys, unsupported values and nonfinite
numbers. Do not Unicode-normalize, case-fold, trim or coerce identity strings.
Required identifiers are nonblank; SQL integers must be integers, not booleans,
floats or decimal-looking text. Arrays retain declared semantic order; sets are
sorted and deduplicated by canonical bytes before encoding. Existing Scout IDs
keep their original algorithms; never recompute them with this new encoder.

```
interaction_id = "si1:" + lowercase_hex(SHA256(C(identity)))
```

Exact `identity` fields:

```json
{
  "schema": "flop-scout-interaction-identity/v1",
  "source_namespace": "scout-observer",
  "relationship_type": "subsequent_signed_post_within_5_signed_messages",
  "endpoints": [
    {"role":"source","raw_record_id":"<raw id>","room":"<room>","generation":"<generation>","seq":1,"sender_did":"<sender>"},
    {"role":"target","raw_record_id":"<raw id>","room":"<room>","generation":"<generation>","seq":2,"sender_did":"<sender>"}
  ]
}
```

The endpoints array has exactly those two roles in that order. Each endpoint
resolves to one immutable raw source record. A changed direction, source position,
generation, endpoint identity or actual relationship type creates a different ID.
Exclude scores/confidence, primary/retention classifications, operator group,
first-observed/reparse/publication times, SQLite rowids and event autoincrement
IDs. Event IDs are provenance aliases, not the interaction identity. Late arrival
of a task link changes provenance/dependencies, not this ID. Classification
changes must not relabel an edge's factual `relationship_type` in place.

For existing heuristic edges retain their exact `relationship_type`, including
window size; changing the inference window defines a different relation. Never
rename such an edge `explicit_reply` or `protocol_reply`. Router's direct edge
allowlist is `explicit_reply`, `reply_to`, `did_mention`, `protocol_reply`,
`direct_response`; Scout's current subsequent-post heuristic is not on it.
This review does not authorize manufacturing new direct edges from job proximity.

Resolve legacy `interactions` endpoints by room, source/response seq, sender and
available exact provenance links to messages/raw evidence. Require one generation-
consistent pair; the generationless `(room, seq)` cache alone is insufficient.
Deduplicate aliases only when they identify the same immutable raw record. If
multiple raw records/generations remain plausible, fail `INTERACTION_SOURCE_AMBIGUOUS`;
never pick newest/oldest/lowest rowid. A future corrected ingestion path should
record endpoint raw IDs at edge creation. This is an input qualification failure,
not an unresolved identity algorithm. Real distinct endpoint pairs remain distinct.

`interactions.id` is unusable: `rebuild_interactions()` deletes all rows and assigns
fresh IDs and `created_at`. For resolved historical edges, the first-observed
clock is `max(endpoint raw created_at)`; this denotes first availability of the
source pair, not the last rebuild. Persist it once in the source identity ledger.
An unknown endpoint first-observed time blocks finite-horizon qualification.
Heuristic edge confidence is copied verbatim if finite; it is not identity.

Message projection identity is `sm1:<raw_record_id>`. Distinct existing raw IDs
remain distinct even if they represent identical text or different retrieval
source namespaces. Do not change Scout's raw identity/deduplication algorithm.

## CLASSIFIER PRECEDENCE

There are two separate decisions, not an overloaded enum:

1. `source_provenance.annotations_json.classification`: one primary **event type**.
2. `selection_membership.retention_class`: one primary **retention reason**.

Existing raw/observed events are not rewritten. Recognition is bounded parsing of
hostile data, not execution or acceptance of its assertions. A protocol discriminator
must occur in its defined structural position, not somewhere in quoted prose.
Reject duplicate JSON keys; nested conflicting discriminator fields do not win
by merge order. Unknown/conflicting envelopes use `MALFORMED_UNVERIFIABLE_EVENT`
or `UNCLASSIFIED` as applicable, not a guessed positive protocol class.

Primary precedence is numeric and explicit (smaller wins):

| Rank / candidate event pattern | Primary classification | Secondary facts using existing fields only | Reason |
| --- | --- | --- | --- |
| 10: text starts `tclk1 ` and recognizable frame attempt | TCLK_TRANSCRIPT_EVENT | Signature status; full attempted frame; task/job links when unambiguous | Outranks prose work/request and rail claims inside the transcript |
| 20: exact Bench request/result/delivery schema | VERIFICATION_REQUEST or VERIFICATION_RESULT | Separate authenticity, correctness, reproducibility, verification/task links | Outranks generic WORK_RESULT; a failure is still a verification attempt |
| 30: valid recognized Kibble version/type | KIBBLE_JOB / KIBBLE_CLAIM / KIBBLE_RESULT / KIBBLE_ATTESTATION / WORK_ACCEPTANCE / VERIFICATION_RESULT / WORK_REQUEST | Exact type preserved in full text; task links | JOB outranks generic WORK_REQUEST; RESULT/DELIVER outrank WORK_RESULT; ACCEPT means a claimed acceptance, not automatic closure |
| 40: provenance-backed, configured official registry/network announcement | OFFICIAL_NETWORK_ANNOUNCEMENT | Identity binding evidence links, if actually present | Outranks generic promotion; a URL, room name or claimed official label is insufficient |
| 50: authenticated identity/operator binding or disclosure; otherwise ordinary identity announcement | IDENTITY_PRESENCE | Authoritative operator fields only if established; unknown stays NULL | Outranks promotion but does not by itself imply permanent IDENTITY_OPERATOR retention |
| 60: explicit versioned generic work/request/acceptance/result/verification envelope | Corresponding existing WORK_* / VERIFICATION_* class | Available explicit linkage | Unknown versions are not normalized into a supported protocol |
| 70: anchored generic verification/work/rail prose | Existing anchored VERIFICATION_RESULT / WORK_RESULT / WORK_ACCEPTANCE / WORK_REQUEST / EXTERNAL_RAIL_CLAIM | Claim remains claim | Follow the listed rank, then the existing anchored pattern specificity; no substring scanning for a winner |
| 80: explicit capability advertisement | CAPABILITY_CLAIM or PROMOTIONAL_CLAIM | No fabricated concrete support | Capability signal only unless separate concrete rules establish more |
| 90: malformed/unrepresentable content without recognized structural family | MALFORMED_UNVERIFIABLE_EVENT | Signature/parse evidence remains distinct | A known failure cannot disappear as ordinary noise |
| 100: other parseable text | UNCLASSIFIED | No extra tags | CONTEXT fallback |

For Kibble the existing accepted types map explicitly: JOB→KIBBLE_JOB,
CLAIM→KIBBLE_CLAIM, RESULT/DELIVER→KIBBLE_RESULT, ATTEST→KIBBLE_ATTESTATION,
ACCEPT→WORK_ACCEPTANCE, WITNESS→VERIFICATION_RESULT, BRIEF→WORK_REQUEST.
The primary describes the attempted event family even when its signature fails.
For example, an identifiable tampered Bench delivery remains VERIFICATION_RESULT,
with invalid authenticity and NEGATIVE_EVIDENCE retention. This differs from the
current generic classifier's early MALFORMED_UNVERIFIABLE_EVENT return; no current
source row is mutated. Malformed JSON that only vaguely resembles a result is not
a verified or linked result. A recognized prefix alone cannot open an indefinite
workflow without a resolvable workflow root/link.

V2 permits no arbitrary secondary-tag array. Preserve facts in existing
`verification_status`, `verification_links`, `task_routing_links`, `evidence_links`
and the single full message body. Recognition diagnostics/candidate labels stay
in producer-private state. Do not add `flags`, `workflow_state`, or a second
classification column to the strict published schema.

Retention precedence: NEGATIVE_EVIDENCE, PINNED, IDENTITY_OPERATOR,
BENCH_VERIFICATION, CAPABILITY_CONTRADICTION, CAPABILITY_SUPPORT, TCLK_LIFECYCLE,
WORK_LIFECYCLE, CAPABILITY_SIGNAL, CONTEXT. Concrete contradictions also satisfy
the first rule, so NEGATIVE_EVIDENCE wins. Membership is a union: a lower-priority
permanent rule still makes `retain_until` NULL. Pin roots are populated even for
a row whose primary reason is NEGATIVE_EVIDENCE. Successful workflows shared by
several roots expire only after all required roots close and the latest applicable
90-day boundary; any unresolved root makes expiry NULL. Generic allegations are
not a permanent rule. Unknown or ambiguous classification is CONTEXT unless an
independently supported retention rule applies.

### Deterministic ordering and the remaining permanence conflict

Order affected message groups by `(room, generation, seq, raw_record_id)` using
lexicographic string comparison and integer seq; group per sender for the current
Router capability algorithm. Do not order by sender timestamps, arrival of a
Python container, SQL physical row order or edge IDs. Missing required order fields
block selected-row qualification. Template keys retain Router's existing
`room:generation:template_hash` semantics. Use all selected-scope rows for template
sender counts before filtering invalid DIDs, as V2 requires. Use actual per-group
multiplicity for duplicate counts. Re-evaluate an affected group as a unit, not
one new row with fabricated `duplicate_count=1`.

Sorting resolves which duplicate receives credit. It does **not** resolve
permanence. The temporary fixture check below demonstrated STRONG→SIGNAL after a
second same-template record. V2 requires both exact Router evidence rules and
permanent retention of support rows. It does not define a durable ever-qualified
witness or how bootstrap and subsequent reclassification preserve that permanence.
Amendment A1 makes this explicit. Do not implement either silently expiring old
support or treating every self-advertising duplicate as permanently qualified.

## WORKFLOW IDENTITY

A workflow is an explicitly scoped protocol root and its validated links, not a
similarity cluster. New identity is:

```
workflow_id = "sw1:" + lowercase_hex(SHA256(C(identity)))
```

Exact object:

```json
{
  "schema":"flop-scout-workflow-identity/v1",
  "protocol":"kibble/v1",
  "scope":{"source_namespace":"scout-observer","issuer":"<root-author DID>","room":"kibble","generation":"g1"},
  "key":{"type":"job_id","value":"job-1"}
}
```

| Root | Protocol/key | Scope and linking rule |
| --- | --- | --- |
| Kibble JOB | kibble/v1; job_id | Source namespace, root poster DID, room and generation. CLAIM/RESULT alone cannot invent the poster. Resolve to a unique matching root; same key with conflicting roots/payloads means CONFLICT, not last-row-wins. |
| TCLK offer | tclk/1; offer_id | Source namespace, verified offer maker DID, room/generation. A job link is a dependency, not an alias merging the TCLK and work workflows. Contract/ref links must uniquely reach the offer root. |
| Bench verification request | flop-verification-request/v1; request_id | `scout-verification`, requester DID; room/generation NULL for explicitly imported local request artifacts. Request hash must match every linked result; reuse of the ID with a conflicting request is CONFLICT. |
| Router task/decision | router-task/v1; task_hash, or router-decision/v1; routing_decision_id | Explicit imported source namespace and producer DID; room/generation NULL. Distinct keys are linked, not coalesced. This does not authorize reading Router's private DB. |
| Generic mailbox/prose with no authoritative protocol key | scout-unresolved/v1; raw_record_id | Raw source namespace, sender, room/generation. Singleton UNKNOWN workflow only for a recognized work event. Later explicit links add graph edges/aliases without rewriting existing IDs. |

Only authenticated, structurally valid roots establish active workflows. An
unverified attempted root without a trusted local link stays context/audit, not
an invented indefinite workflow; established negative facts still take precedence.
Every object has exactly the displayed fields. Protocol/key type combinations are
closed as listed; hashes remain lowercase 64-hex when the key is a hash. Local
room and generation are both NULL, never fabricated room/seq. Message-bearing
roots require real room/generation. Missing issuer/key creates a pending unresolved
link, not a global UNKNOWN issuer bucket. Missing required local root blocks fresh
publication of dependent selected evidence. Unknown external IDs stay opaque.
Different generations, issuers or protocols cannot merge by coincident job text.

Workflow membership/state is producer-private; publish the actual message rows
and existing verification/task/evidence links. No workflow table or extra annotation
field is added. Router reconstructs a finite closure proof from retained root,
terminal and authority evidence plus their membership clocks. If proof cannot be
represented in those existing fields, do not apply a finite closure; remain
unresolved (or fail if required selected source fields are unrepresentable).

## WORKFLOW CLOSURE RULES

State is a fold over a complete committed cut, in immutable first-observed time
order, then raw ID; facts with the same logical time are considered together.
Conflicting authoritative facts produce CONFLICT rather than tie-breaking a winner.
These are observation states, not permission to act:

| Evidence | State / closure decision |
| --- | --- |
| Authenticated unique Kibble JOB | OPEN |
| Bound CLAIM from a worker | CLAIMED; competing unresolved claims remain unresolved |
| Bound RESULT/DELIVER | RESULT_POSTED, not successful completion |
| Kibble ACCEPT from the root poster, authenticated, explicitly referencing a unique RESULT/DELIVER by immutable result ID/hash, all roles and job links consistent | CLOSED; reason KIBBLE_POSTER_ACCEPTED_RESULT |
| ACCEPT without result linkage, third-party ACCEPT, or negative ATTEST alone | Still unresolved; preserve the claim. Current job-board summary status is not authority. |
| Root poster's authenticated explicit rejection of that linked result | REJECTED; retain the rejection/outcome as scoped durable negative evidence, not a blanket accusation about the worker |
| Kibble expiry/cancel without a supported authoritative record and exact linkage | UNKNOWN/unresolved. Existing cache/board disappearance, text deadline or parser status cannot close it. |
| Authenticated TCLK offer with matching transport/frame DID | OPEN; offer alone proves no work or settlement |
| TCLK accept/lock/reveal/refund/receipt/cancel transcript | Preserve the observed frame; does not by itself prove settlement or close an active contract. Missing, conflicting, unauthenticated or ambiguous transitions remain unresolved. |
| Unaccepted/unlocked TCLK offer; verified maker, valid integer expiresMs, no conflicting deadline/extension or active linked obligation at the complete cut | EXPIRED at validated offer deadline; reason TCLK_OFFER_DEADLINE. claimByMs/refundAfterMs are not aliases for offer expiry. |
| TCLK transcript with accepted/locked/unresolved linked work | Stay unresolved even after offer expiry. A future authoritative terminal adapter is separate review; this profile does not infer rail settlement. |
| Bench request | OPEN; all request/result records remain BENCH_VERIFICATION permanently regardless of lifecycle |
| Valid linked Bench result with PASS and independently preserved correctness/reproducibility/authenticity assertions | CLOSED; reason BENCH_LINKED_RESULT. This closes the verification request, not the underlying work or settlement. |
| Valid linked objective Bench FAIL | REJECTED; reason BENCH_OBJECTIVE_FAIL; permanent negative/audit evidence |
| Bench invalid signature, bad request hash, role mismatch, conflicting outcome or missing result authority | Unresolved; preserve audit and established negative facts; never accept a claim of PASS as closure |
| Generic work without a supported authoritative terminal schema | UNKNOWN/unresolved; prose “done”, message silence or missing source file cannot close it |

Bench authority means either an explicitly configured local controlled-result
import with exact request/result hash linkage, or offline-verified network
transport bound to the known Bench DID and the full request linkage fields checked
by `request_linkage_matches()`. Do not coerce booleans/strings, accept the normalizer's
`artifact_hashes_valid=True` when no request was supplied as actual verification,
or confuse signature presence with VERIFIED_OFFLINE. Malformed/unsupported results
stay audits without authoritative closure. Standalone local verification artifacts
remain configured external inputs; do not fabricate a network message to represent
them. Where their proof is unavailable in selected transcript/links, no finite
message expiry is justified; permanent Bench membership is unaffected.

For a terminal event, `closed_at` is the immutable trusted local **first observed**
time of the first valid authoritative terminal record, after checking all required
root/result/authority links. It is not its claimed completed_at, the current parser
clock, a replay time or a newly imported copy's mtime. If authority/link proof only
became available later, use the maximum first-observed time of the required proof
records (first complete authoritative proof). For expiry-only TCLK closure use
validated `expiresMs * 1000` integer microseconds. This refines V2's “first valid
observed terminal event”; it does not trust sender timestamps. Retain-until is
`closed_at + 7,776,000 seconds`; eligible exactly while evaluation is strictly
before that instant. A terminal claim followed by conflicting evidence reopens
qualification to CONFLICT/unresolved; do not delete the conflicting transcript.

Producer-private closure ledger has exactly `workflow_id`, `state`, nullable
`closed_at`, nullable `closure_evidence_id`, nullable `closure_reason`, and a sorted
set of required proof references. `closure_evidence_id` is `sm1:<raw id>` for a
message or a separately named local artifact reference; never an invented Scout
event ID. Expiry closure points to the original offer, not a synthetic event.
Root/proof changes are incremental material changes. Finite closure is published
only when Router can reconstruct it from selected root/terminal/proof rows and
explicit links. Multiple required workflows use the latest valid closure boundary;
any permanent, pinned or unresolved dependency overrides that boundary.

## PIN IMPORT SCHEMA

This is the narrow local interchange definition permitted by V2's explicit pin
input boundary. It is not a new Router DB reader, network protocol or published
V2 table. Router exports to its own state; Scout imports an explicitly configured
regular local artifact. Paths and identities are supplied configuration, not
hard-coded operator home paths or key lookups. Consumer/export implementation is a
future integration prerequisite, not claimed complete here.

Only PERMANENT pins are supported. UNTIL_TIMESTAMP, expires_at and
UNTIL_DECISION_EXPIRES are rejected: they contradict V2's no-implicit-unpin rule.
A pin is a same-operator retention instruction, never independent reputation or
proof its evidence is true.

The cumulative interchange object has exactly:

```json
{
  "schema":"flop-router-projection-pins/v1",
  "source_id":"<configured Router export source>",
  "epoch":"<configured stable export epoch>",
  "revision":"0",
  "produced_at":"2026-09-08T12:00:00Z",
  "previous_sha256":null,
  "pins":[],
  "content_sha256":"<hash of this object excluding content_sha256>"
}
```

Revision is a canonical unsigned decimal string, at most 20 digits. An explicit
revision-0 empty artifact is valid bootstrap; absence is not empty. Initial previous
hash is NULL. Each new revision increments by one and binds the previous accepted
content hash; the complete immutable pin set must be a superset. Same revision
requires identical hash; gap, epoch change, removal or conflict blocks fresh
publication and retains the previously accepted pins. Recovery of skipped revisions
requires the missing interchange sequence, not resetting state. Bound one document
at 4 MiB and 10,000 pin objects; exceeding capacity fails, never truncates. Stage
imports locally and advance acceptance atomically only after every pin validates.

Each `pins` element has exactly:

```json
{
  "schema":"flop-router-projection-pin/v1",
  "pin_id":"rp1:<identity hash>",
  "created_at":"2026-09-08T12:00:00Z",
  "producer":"FLOP_ROUTER",
  "router_did":"<configured public DID>",
  "reason":"RETAIN_EVIDENCE",
  "root":{"kind":"ROUTING_DECISION","id":"<decision id>"},
  "decision_id":"<same decision id>",
  "task_hash":null,
  "retention_mode":"PERMANENT",
  "operator_group":"local-flop-agent-family",
  "evidence_refs":[{"kind":"RAW_RECORD","source_id":"scout-observer","source_epoch":"<configured source epoch>","id":"<raw id>","sha256":null}],
  "dependency_refs":[],
  "content_sha256":"<hash of this object excluding content_sha256>"
}
```

`root` is exactly V2's kind/id object. Kind is ROUTING_DECISION, TASK, VALIDATION or
VERIFICATION. decision_id is nonblank and equals root.id for ROUTING_DECISION;
otherwise nullable and must match any supplied decision reference. For TASK,
root.id is its full task_hash and task_hash must equal it. VALIDATION/VERIFICATION
root IDs are stable validation/request identifiers; never publication IDs or paths.
Other strings are nonblank, bounded at 256 characters; hashes are lowercase 64-hex.
The producer/reason/retention/group values above are exact constants.

`pin_id = "rp1:" + SHA256(C({schema,producer,router_did,root,evidence_refs,
dependency_refs}))`. The braces denote that exact subset of the pin object.
Created-at and other mutable-context fields are excluded from identity but bound
by content_sha256. Existing pin bytes can never change. Additional references for
an existing root require an additional immutable pin (new ID), not editing or
removing its earlier pin. A repeated identical semantic pin with different timestamp
is a same-ID conflict. Pins are sorted by pin_id. Arrays of references are sorted
by canonical bytes, duplicate-free, at most 256 each; evidence_refs is nonempty.
Hashing always uses C, excluding only the object's own content_sha256 field.
Duplicate/unknown JSON keys, wrong types, nonfinite values, unrecognized enums,
invalid timestamps or oversized objects reject the entire update. Use contract
RFC3339 UTC timestamps and the 60-second future-skew bound; enforce nonregression
of accepted export produced_at. Creation time is not permission to expire a pin.

Every reference has exactly kind/source_id/source_epoch/id/sha256. Local kind is
RAW_RECORD, SCOUT_EVENT, MESSAGE, EVIDENCE_RECORD, INTERACTION or WORKFLOW; match
configured source ID/epoch. SCOUT_EVENT id is a canonical decimal event ID and must
resolve to the expected immutable raw record; other kinds use their named source
identity, sm1/si1/sw1 prefixes as appropriate. sha256 is nullable; if present it
must be the exact byte hash defined by that kind. RAW_RECORD hashes refer only to
original raw-record bytes when available, not raw_text_sha256. Do not use the
optional hash until its basis is available; a supplied unsupported/unverifiable
hash fails, not ignored. For MESSAGE use SHA-256 of exact UTF-8 raw text; for
EVIDENCE_RECORD use its preserved message_hash; for INTERACTION/WORKFLOW use C of
the identity object. SCOUT_EVENT uses C of all named immutable source event fields
only when retained as an immutable import; otherwise require sha256=NULL.

An EXTERNAL reference is allowed only in dependency_refs with an explicit external
source namespace and stable opaque ID/epoch; optional hash binds configured local
artifact bytes if supplied. It does not authorize fetching, reading a Router DB
or traversing the filesystem from the ID. Known local source identities cannot be
relabelled EXTERNAL to bypass missing-dependency failure. Router owns retention of
its external task/decision/audit originals; Scout pins only resolved local evidence.

Resolve roots transitively before publication. A malformed input never creates an
indefinite pin. A valid input with a missing local target stays pending and blocks
fresh publication; it never clears accepted pins or silently drops a reference.
Published `pin_roots_json` is the sorted union of root kind/id pairs, not pin IDs.
Apply V2's 256-root/64-KiB per-row limits; overflow blocks qualification. Importer
checks configured producer DID and local operator binding without loading a key.
SHA-256 binds bytes against mistakes; same-user compromise is not excluded.

## TRANSITIVE DEPENDENCY RULES

Typed graph: pin root → referenced message/edge/workflow → minimal source proof.
Required edges are directed and explicitly derived from structural links, never
text similarity or merely equal DID/template/job fragments.

- Message → its one source_provenance and selection_membership row, exact raw/event
  aliases, and explicit locally required authority/verification/negative-proof
  messages. The original warehouse envelope is a terminal lookup witness, not
  another projected copy of text.
- Interaction → both uniquely resolved endpoint message identities and source
  proof used to create the edge. Pinning an edge pins those full selected messages;
  it does not pin all posts in the room or every neighbor of either DID.
- Workflow → its root and the linked request/claim/result/terminal/conflict/authority
  records necessary to interpret that workflow. Include adverse and rejected
  members, not just the accepted result. A coincident external job ID is not an
  edge without scoped linkage. New required members inherit an existing pin.
- Capability decision → the actual positive/adverse evidence references supplied
  by the valid pin artifact. No automatic pin of every matching template or the
  whole profile/warehouse. Publication-only IDs and activity scores are not roots.
- Provenance hashes and opaque external references are leaves. A hash alone never
  authorizes discovery/fetching or guessing a missing body.

Traverse in sorted `(kind, source_id, source_epoch, id)` order with a visited set.
Cycles reach a fixed visited closure, not recursive duplication. Persist frontier
and accepted roots outside the published schema; evaluate at one committed source
cut. Work in at most 200 nodes per turn. An operational limit of 100,000 resolved
nodes per root fails NOT_READY rather than truncating a necessary closure; a later
capacity change does not unpin accepted data. Missing required local nodes and
ambiguous aliases block publication. Explicit external leaves do not claim local
completeness. Union roots on shared nodes. No reverse reachability over unrelated
messages, followers, sender activity or merely similar text.

Ordinary unpinned heuristic edges may reference endpoint provenance without
forcing all endpoint bodies into selected context. If an edge is used as retained
Router support, its explicit pin activates the endpoint dependency rule above.
Active workflow dependencies inherit WORK_LIFECYCLE/TCLK_LIFECYCLE retention;
workflow completion does not revoke explicit pins. Dependency cycles alone are
not new indefinite roots; they need a valid pin, permanent fact or active workflow.

## SOURCE → V2 FIELD MAPPING

Abbreviations: R = raw_network_records; E = observed_events; C = compatibility
messages; V = evidence_records; I = interactions. R↔E joins by raw_record_id.
C/V/TCLK/Kibble links use compatibility_evidence_links **and** exact location,
generation, text/hash and relevant provenance checks. Its older migration may
choose a first matching row, so a link alone is not proof of unambiguous generation.
Conflicting matches fail. Do not convert R.reported_generation into a known actual
generation after a conflict. NULL actual generation is UNKNOWN_LEGACY; zero is "0".
Empty or malformed non-NULL generation is invalid, not silently UNKNOWN_LEGACY.

Required fields must have their declared SQLite types; unknown nullable values
remain SQL NULL. No fabricated network position, sender, offline verification,
raw-record hash or independent reputation. The source-row ID is stable across
reparse; missing E is an incomplete source batch, not an event to omit.

### messages (one row per selected R; sm1 identity; union retention policy)

| Column | Source / exact transformation | Nullable |
| --- | --- | --- |
| projection_row_id | `sm1:` + R.raw_record_id, validated 64-hex raw identity | No |
| room | R.room, nonblank text ≤256 | No |
| generation | R.generation; NULL→UNKNOWN_LEGACY, numeric zero→"0"; no aliasing zero with unknown | No |
| seq | R.seq, nonnegative SQLite integer | No |
| timestamp | R.network_timestamp verbatim; not an expiry clock | Yes |
| sender | R.sender_did verbatim; missing required sender blocks selected evidence | No |
| signed | Exact linked C.signed if available and consistent with source; otherwise apply the existing `is_signed_sender(R.sender_did)` prefix convention (`did:key:z6Mk`), 1/0. This is not full DID validation. This is sender-form metadata, not offline authenticity. Invalid-signature rows remain non-support regardless of this bit. | No |
| text | R.raw_text, exact valid UTF-8, no trimming or normalization | No |
| normalized_text | Exact linked C.normalized_text when present; otherwise NULL. Do not call the signed-post normalization/length-limiting function to truncate evidence. | Yes |
| template_normalized_hash | Exact linked C.template_normalized_hash; otherwise NULL. E.normalized_template_hash uses different promotional normalization and is not a substitute. | Yes |
| nonce | R.nonce verbatim text; preserve leading digits/zero representation and integer precision. Never float. | Yes |
| sig | R.signature verbatim | Yes |
| message_hash | Exact linked V.message_hash (SHA-256 of exact raw text), validated against text. If no V, compute that same explicitly named text hash; not R.raw_record_id or an envelope/Router composite hash. | Yes in schema; populated for representable text |
| verification_status | Exact linked V.verification_status when present. Otherwise NULL; never copy E/R `FAILED` into Router's `INVALID_SIGNATURE` enum without explicit conversion. Classifier separately evaluates R/E authenticity and preserves established negative outcome in membership. Consumer must still enforce invalid/mismatched provenance. | Yes |
| source_export_hash | Exact immutable export snapshot hash only if source metadata records a specific supplying export. No guess from latest room export or substituted raw/text hash. | Yes |
| source_export_path | Associated logical preserved source export path when available, opaque/inert; never a staging/publication path | Yes |
| evidence_id | Exact linked V.evidence_id. If unavailable NULL; do not manufacture a Router `tc:` ID or conflate it with sm1/raw identity. | Yes |

Selected malformed required values cause NOT_READY, including NULL/non-UTF8 text,
invalid sender/seq/location. The source still retains them. An unresolved required
negative fact cannot turn into a healthy empty projection by dropping it. Missing
optional compatibility data stays NULL; later linkage is a material provenance
update without changing identity or first-observed time.

### interactions (resolved I edge; si1 identity)

| Column | Source / transformation | Nullable |
| --- | --- | --- |
| projection_row_id | Interaction contract above; never I.id | No |
| source_did | I.source_did, must equal resolved source endpoint | No |
| target_did | I.target_did, must equal resolved target endpoint | No |
| relationship_type | I.relationship_type verbatim; heuristic not upgraded to direct | No |
| confidence | I.confidence verbatim finite SQLite numeric value; reject NaN/Infinity and fabricated defaults | No |

Ordinary edges use 30 days from stable first-available-source-pair time. Explicit
pins/permanent operator facts override expiry. Distinct real logical edges remain
multiple rows. Replay of a rebuilt alias is idempotent. Any selected ambiguous
historical edge blocks qualification rather than reassigning its generation.

### source_provenance (one-to-one with either entity; same retention)

| Column | Source / transformation | Nullable |
| --- | --- | --- |
| entity_type | Literal message or interaction | No |
| projection_row_id | Corresponding sm1/si1 key | No |
| source_namespace | R.source for message; `scout-interaction-inference` for current heuristic edge | No |
| source_record_locator | `scout-raw:<raw_record_id>` or `scout-interaction:<si1 identity>`; stable logical reference, not a URL | No |
| scout_event_id | Decimal E.event_id string for message. Interaction NULL because two endpoints; endpoint event aliases remain in producer ledger and evidence links resolve their messages. | Yes |
| raw_record_id | R.raw_record_id for message; NULL for multi-source interaction | Yes |
| raw_record_sha256 | Exact original source-record bytes digest only where explicitly available; usually NULL. R.raw_text_sha256 hashes text (or reconstructed JSON fallback), not universally original wire bytes. Never substitute it. | Yes |
| annotations_json | Canonical C of exact annotation object below; bounded/validated | No |

Annotations keep V2's exact eight keys, with no new fields:

| Key | Mapping |
| --- | --- |
| classification | Single primary event class from the explicit precedence table; not a source truth claim |
| same_operator / independent_reputation / operator_group | Validated operator policy below; nullable unknown, never truthy-string coercion |
| capability_support | Sorted unique `{capability_id,classification,evidence_id}` objects from actual versioned capability decisions. Evidence_id must resolve the associated source identity. Missing linked evidence ID means no invented entry; readiness for required support proof fails if unresolved. Never populate from mere keywords/unauthenticated claims. A1 governs permanent membership separately. |
| verification_links | Preserve exact nullable request_id/result_hash/bench_did/validation_id/correctness/reproducibility/authenticity/evidence_classification from validated local normalized artifacts or exact linked network delivery. At least one identity field required. Do not invent correctness from transport verification. |
| task_routing_links | Exact nullable job_proto/job_id/task_hash/routing_decision_id/routing_decision_hash from validated Kibble/TCLK payload or request-linked Bench fields. At least one non-NULL; job numbers are protocol-scoped strings, not guessed by regex. |
| evidence_links | Sorted exact `{room,generation,seq,evidence_id}` objects for explicit proof/endpoint links. A location is complete; otherwise nonblank evidence_id required. Resolve aliases uniquely; no fabricated source seq for a local artifact. |

Arrays sorted by canonical bytes, duplicate-free, ≤256 entries each; object ≤64
KiB; nullable fields remain NULL. Every supplied hash is validated according to
its named basis. For a local normalized result, its `message_hash` is a file-byte
hash and must not become a network text hash or arbitrary result_hash. Preserve an
explicit result_hash only after checking its documented result representation;
otherwise leave nullable result_hash NULL and retain the other verified linkage.
Existing normalizers can default or coerce fields; the projection validator must
validate original types and cross-field equality rather than trust those defaults.
Full Bench correctness/provenance audit and normalized TCLK JSONL remain separate
explicit Router inputs as V2 states. No synthetic room message is created for them.

### snapshot_meta (exactly one row)

| Column | Source / transformation | Nullable |
| --- | --- | --- |
| singleton | Integer 1 | No |
| schema | Literal scout-router-projection/v2 | No |
| database_content_id | Durable producer content counter, canonical decimal; allocate only for material change | No |
| content_created_at | UTC monotonic-clamped content creation instant for the completed committed view; not sender time | No |
| selection_policy_sha256 | SHA-256 of exact C(policy), matching manifest and approved classifier version | No |

Heartbeat leaves all meta fields unchanged. Counters, source epoch/checkpoint,
expiry/pin queues and logs live outside the published minimal schema. Source cut
is a whole committed outbox batch, not simply max(E.event_id): raw, derived and
compatibility work commit separately today. Never advance checkpoint ahead of the
committed projection; lagging checkpoints replay idempotently after crash. No
whole-warehouse rebuild during publication. This is an implementation requirement,
not an outbox claimed to exist today.

### watermarks (one row per currently included message domain)

| Column | Source / transformation | Nullable |
| --- | --- | --- |
| room / generation | Completed snapshot messages group keys | No |
| record_count | COUNT(*) of all selected rows in group, including selected unsigned evidence | No |
| min_seq / max_seq | MIN(seq) / MAX(seq) over that group | No |

Use the contract's GROUP BY room,generation ORDER BY room,generation query only
on completed snapshot contents. Empty projection gives no rows. Duplicate sequence
values count separately when actual source rows differ; conflicting message bodies
at one domain/seq block publication. No claim of complete warehouse coverage or
contiguous numeric sequence. Generation zero and UNKNOWN_LEGACY remain separate.

### selection_membership (one-to-one; no additional columns)

| Column | Source / transformation | Nullable |
| --- | --- | --- |
| entity_type / projection_row_id | Exact corresponding entity type/key | No |
| retention_class | Primary union-retention reason above; A1 approval required for support permanence | No |
| first_observed_at | Message R.created_at, UTC-normalized preserving instant; edge stable source-pair first-observed ledger | No |
| retain_until | NULL for any permanent rule, pin or unresolved workflow; otherwise integer-microsecond-derived UTC horizon/closure boundary | Yes |
| pin_roots_json | Canonical sorted duplicate-free `{kind,id}` roots; empty array is not NULL | No |

Ordinary context is 2,592,000 seconds; capability signals and closed work/TCLK
are 7,776,000 seconds. Never refresh on replay. No silent policy-dependent
shortening. Predicate is evaluation < retain_until, not ≤. Required shared
workflow dependencies use the maximum finite boundary, with unresolved/permanent
rules dominant. Selection-policy version/hash changes require reviewed migration.

### coverage_history (one durable witness per ever-projected domain)

| Column | Source / transformation | Nullable |
| --- | --- | --- |
| room / generation | Domain of a selected message; domain set never shrinks | No |
| max_ever_projected_seq | Monotonic maximum of successfully committed projected rows | No |
| witness_source_locator | Exact source_provenance locator of the supplying message | No |
| witness_record_sha256 | SHA-256(C(object containing every named messages column of that witness)) | No |

When a higher sequence first enters, choose the lexicographically smallest sm1
among equal new maxima and record its witness atomically. An unchanged maximum
retains its existing witness even if that body later expires or another duplicate
arrives. Do not substitute raw_text_sha256. Manifest history exactly matches the
table; current watermarks may shrink on legitimate expiry, history may not.

## NEGATIVE EVIDENCE POLICY

Permanent negative membership records a provenance-backed adverse **fact**, with
its exact subject and limitations; it does not assign independent peer blame.

| Candidate | Permanent? / required proof |
| --- | --- |
| Invalid cryptographic signature | Yes: exact attempted envelope/text, verifier result/version and source position. It proves that envelope failed authentication, not that the claimed DID authored misconduct. |
| Transport/payload DID mismatch | Yes: preserve both conflicting identities and source bytes; do not pick one or silently repair binding. |
| Conflicting evidence identities at same position | Yes in source retention; conflicting projected body/location fails publication. Permanent retention does not license choosing a winner. |
| Objective Bench/controlled validation FAIL | Yes: valid request/result link, trusted controlled artifact or verified Bench sender, exact outcome/hash and separate correctness/reproducibility/authenticity assertions. |
| Concrete capability/security contradiction | Yes: a versioned rule with reproducible source/proof linkage or trusted verification record, not a keyword classifier's suspicion. |
| Authoritative poster rejection of an explicitly linked work result | Yes as a scoped rejection fact. Does not establish global inability, correctness of the poster, or independent reputation. |
| Generic criticism, anonymous negative prose, unverified accusation, low-confidence classifier output | No negative permanence. Signed ordinary context uses its horizon; unsigned irrelevant chatter is excluded unless a different valid linkage/retention rule requires it. |
| Missing signature or unsupported/malformed encoding alone | Not automatically a cryptographic failure or misconduct. Preserve context/linkage/audit as required; do not convert UNKNOWN into FAILED. |
| Invalid/unverified Bench request/result | Permanent BENCH_VERIFICATION audit when its structured family/link is actually recognized, even absent proof of objective failure. Not positive support and not automatically objective NEGATIVE_EVIDENCE. |

A malformed required location/body cannot be dropped to make this policy appear
successful. Pinning is separate: valid Router pins may preserve criticism used in
a decision without relabelling it as established negative evidence. Evidence that
would otherwise be non-permanent does not become proven misconduct through a pin.

## OPERATOR / INDEPENDENCE POLICY

Known configured Scout, Router, Bench and Sentinel identities project:
`operator_group="local-flop-agent-family"`, `same_operator=true`,
`independent_reputation=false`. Identity bindings come from explicit nonsecret
operator configuration/provenance, not signing-key access, DID spelling, room
names, claims of official affiliation or remote self-declared independence.

Source inspection found `LOCAL_OPERATOR_GROUP="flop-labs-local"` in both current
Scout and Router, plus Router's `ROUTER_OPERATOR_GROUP="local-flop-agent-family"`.
For explicitly configured local-family identities, the first is a documented
legacy alias of the canonical group in projection annotations. Preserve the
original assertion in full source text/audit; do not rewrite input artifacts or
apply the alias to unrelated unknown agents. Untrusted remote family claims do
not establish an authoritative binding. Unknown external independence remains
NULL; it never defaults to true.

Router revalidates these disclosures and its local-group exclusions as the V2
contract requires. It must not reinterpret a known local member as independent
because another field, absent group, snapshot hash or source claims otherwise.
Conflicting positive independence for a known family member fails qualification;
canonicalization cannot hide that conflict. Controlled Bench audits remain
CONTROLLED_SAME_OPERATOR_VALIDATION where supplied/validated, not independent
juror/peer credit. This review adds no audit-to-score conversion. No producer
assertion replaces Router's capability/risk or authenticity validation.

## RAW TEXT POLICY

Every selected **message** carries full exact R.raw_text once, in messages.text.
This includes semantic support, contradictions/negative proof, verification and
workflow context, selected promotion/noise and pinned message dependencies. Do
not replace selected text with previews, hashes, summaries or normalized text.
Preserve valid whitespace and Unicode distinctions. Its optional normalized text
is the existing consumer input, not a second claimed original body.

Interactions, membership and provenance contain references, not duplicate bodies.
Local external audit originals stay explicitly configured separate Router inputs;
they do not receive fabricated room/generation/seq. Unreferenced attachments,
whole reconstructed envelopes and duplicate retrieval histories stay in Scout's
warehouse. Expired unpinned bodies are absent; coverage_history may retain only
its compact canonical witness hash/locator, explicitly not full body coverage.
A pinned dependency requiring a message body must restore/select that real source
row before publication or fail; a hash alone cannot satisfy the dependency.

This is scope selection, not lossy compression of selected rows. Long text,
permanent evidence and pins may exceed limits; never trim to fit. Supplied Router
synthetic sizes at 100k/350k/1M/2.5M evidence bundles were 119,668,736 /
419,147,776 / 1,197,826,048 / 2,994,819,072 bytes; source integrity times about
0.18 / 0.67 / 11.64 / 52.89 seconds. Those are supplied measurements, not a new
Scout benchmark or a prediction from current production. Preferred <512 MiB,
normal qualification <1 GiB, 4 GiB hard default remain unchanged; 8 GiB requires
explicit later capacity approval. “Below ceiling” never means automatically qualified.

## FIXTURE VALIDATION

Identity checks used only pure fixture text builders from `test_flop_scout.Tests`
(kibble_event_text, tclk_offer_text with an explicit synthetic DID, verification_request,
bench_delivery_text), canonical JSON and the existing pure raw_identity function.
No signature/key generation, identity material, DBs, network or services were used by
these documentation checks. `did:example:*` labels are synthetic identity inputs,
not assertions of valid Ed25519 authentication. Authentication states in the V2
outcomes below are stated premises. Existing baseline tests separately exercise
cryptography with their normal temporary fixtures.

The exact computed identity vectors and hash-invariant results follow below.
V2 outcomes are reviewed specification expectations, not a V2 runtime claimed
implemented or tested.

### Reproducible identity vectors

The Kibble JOB/CLAIM text is from `Tests.kibble_event_text`, with fixed synthetic
senders and the envelope `{seq, ts: "2026-09-03T12:00:00Z", from, text}`. Raw IDs
use the existing `raw_identity("fixture", "kibble", generation, None, envelope)`.
Canonical interaction input:

```json
{
  "schema": "flop-scout-interaction-identity/v1",
  "source_namespace": "scout-observer",
  "relationship_type": "subsequent_signed_post_within_5_signed_messages",
  "endpoints": [
    {
      "role": "source",
      "raw_record_id": "2d21af0a94d870939e6cf45c51a7b9a24a3a0dbc5c3b576a0eed8847f7b5880f",
      "room": "kibble",
      "generation": "g1",
      "seq": 1,
      "sender_did": "did:example:alice"
    },
    {
      "role": "target",
      "raw_record_id": "32c13a2fd41a194930efce693c1d0bf6cc4482b99f4d6d86bda7b195d392a13a",
      "room": "kibble",
      "generation": "g1",
      "seq": 2,
      "sender_did": "did:example:bob"
    }
  ]
}
```

| Vector | Computed ID |
| --- | --- |
| I1: original | `si1:456af41a19e664702a47b67fdfde455b81f0d9c9b4185ba61777e77f1f0c61be` |
| I2: same claim text at seq 3 | `si1:1662cdb1d1c4edd4fc5918fb35c8f8700caf4e9a0b7dd056c55362a33006831e` |
| I3: reverse endpoints | `si1:aac273013d2b15e82f1fb69d34d6fd87d39af16eb355e9fc24d0d0b8fdaa4c11` |
| I4: target in generation g2 (identity differs; source-pair validation rejects cross-generation heuristic) | `si1:1f1f90b9ec7b3dd22227dc4d5fbd2f5684dd3b068c45a7a2ce3283a3b1e00113` |
| K1: Kibble workflow | `sw1:d578c440fdb0480e59964bfb8acd55c057f68fae63983bead0eccfc2f4466026` |
| K0: zero generation | `sw1:f9edfadc8336ee1209274b87be493ee20639ce7c71ba865044939aea5676825e` |
| KU: unknown generation | `sw1:a3bd78824d7867dae3eb8f21abff0d13cd6dd29f3e367d433caca6af0ebb03df` |
| B1: FVR-local-1 request | `sw1:b137990b117a6ef5d63084f32e4b50bd2aac8520db690731c75234a7a5dc4f4d` |
| T1: offer-1 / synthetic maker | `sw1:83c3302b757904be288f217020428dc04b7b07a4502253351d5352329730de78` |

K1 hashes the exact workflow object displayed in WORKFLOW IDENTITY, substituting
`did:example:alice` for issuer. B1 uses `Tests.verification_request()` requester
DID/request_id with the Bench scope defined above. T1 uses protocol tclk/1,
scout-observer, issuer did:example:alice, room tclk-offers, g1, offer_id offer-1.
Key reordering, JSON serialization/reparse and unchanged source reconstruction
produce I1 again. Edge IDs, scores, classification/operator changes and rebuild
timestamps are not identity inputs. I2/I3/I4 differ; K0 and KU differ. No other
fixture in the table invents an interaction: its interaction ID is N/A unless an
actual source edge and both endpoints are supplied. Invalid source/authentication
premises are not made valid by successfully hashing a candidate identity.


| Fixture / source | Primary and retention expectation | Workflow/state | Pin eligibility / table mapping |
| --- | --- | --- | --- |
| `test_kibble_job_correlation_by_job_id`, JOB→CLAIM→RESULT; manual fixed public endpoint variant | KIBBLE_JOB/KIBBLE_CLAIM/KIBBLE_RESULT; WORK_LIFECYCLE | Kibble sw1 root; OPEN→CLAIMED→RESULT_POSTED, no closure | Explicit pins allowed; each raw maps messages+provenance+membership, actual heuristic edge maps interactions+provenance+membership |
| Same fixture plus documentation-only ACCEPT with no immutable result reference | WORK_ACCEPTANCE; unresolved WORK_LIFECYCLE | No authoritative closure | Retain unresolved; never infer CLOSED from cache status ACCEPTED |
| Same fixture plus documentation-only verified poster ACCEPT with exact result ID/hash, observed at 2026-09-03T12:10:00Z | WORK_ACCEPTANCE; WORK_LIFECYCLE | CLOSED; finite boundary 2026-12-02T12:10:00Z absent pins/other unresolved roots | Pin overrides expiry; terminal/root/result remain closure proof |
| `test_valid_tclk_offer_parses_job_and_rails`, explicit synthetic maker variant | TCLK_TRANSCRIPT_EVENT; TCLK_LIFECYCLE | tclk sw1 root OPEN; job-123 is a linked a2a key, not the Kibble workflow | Offer in messages; protocol rails/full body remain data, task link available; no new interaction inferred |
| `test_expired_tclk_offer_is_not_actionable`, expiresMs=1000, evaluation=2000ms, no active obligation | TCLK_TRANSCRIPT_EVENT; expired lifecycle | EXPIRED at 1970-01-01T00:00:01Z; finite retention already elapsed at a 2026 evaluation | Not selected unless pinned/negative/required; raw warehouse record stays |
| `test_tclk_frame_from_mismatch_fails_closed` | TCLK_TRANSCRIPT_EVENT; NEGATIVE_EVIDENCE | Unknown/unresolved unless unique trusted root links it; never settlement | Full text/provenance retained when representable; pin eligible; invalid identity never support |
| `test_network_bench_result_ingest_verifies_offline_and_preserves_provenance` | VERIFICATION_RESULT; BENCH_VERIFICATION | Bench sw1 root CLOSED only with validated full request linkage | Preserve task/routing/result/authenticity fields; no inferred message for local request |
| `test_network_bench_result_altered_text_is_invalid_signature` | Recognizable VERIFICATION_RESULT attempt; NEGATIVE_EVIDENCE | Unresolved, no PASS closure | Keep attempted raw text and failing authenticity; no capability conversion |
| `test_verification_result_normalization_is_unsigned_local_not_signature_present` | Local verification audit, not a synthetic network row | Bench root can close an imported controlled audit; no finite transcript expiry without represented proof | Separate configured local artifact; verification_links only where actually attached to selected source |
| `test_signature_failures_missing_and_did_mismatch_retained` | Primary content family retained; failed/mismatched envelope negative, missing signature not automatically negative | No workflow absent explicit link | Full message mapping if representable; otherwise NOT_READY, not silent omission |
| `test_kibble_same_room_seq_different_generations_stay_distinct` | Same event family; distinct messages/workflows/domains | g1 and g2 never merged | Different sm1/si1/sw1 where source generation differs; exact watermark groups |
| `test_malformed_records_and_unknown_retained` | Malformed/unclassified according to actual content | No guessed workflow | NULL/surrogate required selected text blocks; ordinary parseable text maps CONTEXT |
| `test_endpoint_switch_fix_is_contextual_debugging_not_testing` in Router | Candidate concrete support; A1 affects permanence | No workflow by inferred similarity | Pin eligible, full message text needed; no top-K trimming |
| `test_can_debug_http_400s_is_self_assertion_only` in Router | PROMOTIONAL_CLAIM; CAPABILITY_SIGNAL | No workflow | 90-day signal; no permanent support merely from “I can” |

Router pure-function check (no SQLite/network calls) used the exact endpoint-fix
text, then a documentation-only same-template duplicate. One row yields STRONG.
Two rows ordered [seq1,seq2] yield SIGNAL/NONE; reversed yield SIGNAL for seq2 and
NONE for seq1. Sorting restores seq1 SIGNAL/seq2 NONE, but does not restore STRONG.
The initial review assertion expecting duplicate STRONG failed; corrected recorded
outputs above establish the actual behavior rather than concealing the failed
hypothesis. This is the concrete evidence for A1, not a failing Scout runtime test.

## OPEN ISSUES

Only one coordinated semantic decision remains: A1, retention of previously concrete
capability evidence after a current-rule downgrade. The proposed rule below is
complete enough to accept or reject; implementation must not choose implicitly.
All other source failures described above have explicit fail-closed behavior;
production census, exact local operator bindings, valid empty pin export,
bootstrap scheduling and exporter/consumer implementation are later deployment
inputs, not permission to fill missing provenance with guessed values.

## PROPOSED ROUTER CONTRACT AMENDMENTS

### A1 — bind permanent support to an immutable qualification witness

Proposed exact additions/replacements to Router's deterministic-selection section:

> Retention membership and current capability scoring are distinct. Every source
> row that first receives LIMITED or STRONG from the supported capability evidence
> rules at a complete committed source cut acquires a permanent retention witness.
> Later template-count changes, duplicate suppression, horizon changes in other
> rows, or score downgrades do not erase that witness or make the row expirable.
> The witness is not an independent reputation assertion or a claim of current
> capability support. Current Router scoring continues to use the current selected
> scope and may return SIGNAL or NONE for that permanently retained source row.
>
> The producer records, outside the minimal published database, the immutable source
> epoch/cut, raw-record identity, capability ID, classifier/policy version and rule
> input/group hash that first established qualification. It evaluates groups in
> canonical (room,generation,seq,raw_record_id) order with actual group multiplicity
> and selected-scope template-sender counts. It never substitutes duplicate_count=1
> to manufacture qualification. A complete-batch change is evaluated atomically;
> a partial batch cannot create a qualification witness.
>
> Bootstrap evaluates its declared committed source cut once. It must not fabricate
> earlier successful qualification from invented one-record historical cuts. Later
> complete outbox batches extend the witness ledger monotonically. Replay of the
> same bootstrap epoch and ordered complete-batch history produces the same witness
> set. A source/policy migration preserves existing permanent memberships and
> witnesses or fails for review; it never silently resets them. Deterministic
> selection therefore includes this durable witness ledger, derivable from that
> fixed bootstrap and committed feed history, in addition to source cut, policy,
> pins and evaluation time.
>
> Published retention_class CAPABILITY_SUPPORT denotes the permanent retention
> reason once such a witness exists, unless a higher-priority retention reason
> applies. annotations.classification remains the current primary event type;
> capability_support entries describe current supported rule outputs, not a
> reconstructed historical score. All other permanent/negative/pin rules continue
> to dominate expiry. Router does not discard or re-score a retained row solely
> because its retention reason is historical support.

To avoid redefining an already reviewed version string, proposed policy replacements
are `version="router-evidence-horizons/2"` and
`classifier_version="router-evidence-classes/2"`; horizons and all other policy
parameters stay unchanged. This changes the bound policy hash. V2 remains the
artifact schema version. Router must explicitly accept this parameter/version set
and the permanent-reason interpretation. No silent acceptance of both versions,
no runtime migration or Router document edit is made here.

If Router instead intends to allow old support to expire on downgrade, it must
explicitly revise the permanent-category and continuity requirements and supply
new acceptance tests; that alternative contradicts the currently approved
“permanent/pinned categories never expire” objective and is not this proposal.

The pin interchange and source mappings above elaborate V2's delegated local
producer interface without adding published tables/columns/annotation keys.
They must be used by the future Router pin exporter; there is no claim an exporter
exists. No other Router wire-schema amendment is proposed. The statement
`V2 CONTRACT SUFFICIENT AS WRITTEN` is **not** made because A1 is required.

## IMPLEMENTATION READINESS

INTERACTION_ID = RESOLVED
CLASSIFIER_ORDER = BLOCKED (ordering resolved; A1 permanence/version decision pending)
WORKFLOW_CLOSURE = RESOLVED
PIN_FORMAT = RESOLVED
TRANSITIVE_DEPENDENCIES = RESOLVED
SOURCE_MAPPING = RESOLVED
NEGATIVE_EVIDENCE = RESOLVED
RAW_TEXT_POLICY = RESOLVED

IMPLEMENTATION_READINESS = BLOCKED

Coordinated Router decision needed: accept A1's immutable qualification-witness
semantics and explicit policy/classifier /2 versions, or supply an alternative
that preserves permanent membership and deterministic complete-batch replay.
After that decision, runtime implementation can follow this exact profile. This
review is not deployment approval. No V2 producer, performance acceptance,
consumer compatibility or service readiness is claimed.

### Validation completed for this coordination review

- Full unchanged Scout baseline: **364 passed in 49.31 seconds**.
- Self-test: **PASS**, using temporary state; no network write.
- Top-level Python `py_compile`: **PASS**, cache under temporary storage.
- Documentation identity/reparse/reorder/repost/generation checks: **PASS**.
- Pure Router duplicate-order fixture: observed results recorded above; no SQLite
  or network calls. This is not a Router V2 consumer test.
- Required section/table-column coverage and Markdown fence checks: **PASS**.
- `git diff --check` and explicit untracked-document whitespace check: **PASS**.

Only `docs/router-projection-v2-source-review.md` changed (still untracked from the
previous task). Existing Python/runtime/test files and Router files remain unchanged.
Temporary scripts/results under `/private/tmp/scout-v2-*` are diagnostic helpers,
not production code. Standard regression/self-test fixtures use their existing
temporary cryptographic test material; no operator identity files were accessed.
No production databases, live publication directories, service commands, network
writes, commit, push, or deployment were performed.

Read-source fingerprints (SHA-256, to identify the reviewed contract inputs):

- Router V2 contract: `4c43e0ab4cdba4764659aeea6ee3a24acafa1dd31146f88ea3a1dbae94c6736c`.
- Router sizing JSON: `4ad1645f77b0341c8c35208d733754fbbecee175e1aa6db259af23079a3e2a95`.
