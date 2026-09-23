# Epoch V2 fresh-cut and continuation contract

This document supersedes neither A1 nor the existing historical first-bridge
rule.  It specifies the next contract revision, `A1-EPOCH-V2-FRESH/1`, for an
explicitly descriptor-bound fresh first cut and indefinitely repeatable V2
content successors.  V2 is disabled until Scout and Router independently
implement this document.

The root schemas are disjoint: `flop-scout-epoch-fresh-first-transition/v1`
contains accepted anchor, bridge predecessor/binding, fresh authority, embedded
fresh transition, and `fresh-first-transition` commitment.  Historical
`flop-scout-router-epoch-rollover/v2` remains historical-only.  Same-epoch
successors use `flop-scout-epoch-content-successor/v1`, an exact predecessor,
embedded successor transition, and `content-successor-transition` commitment.
Dispatch is schema-based; neither root is accepted by the other's validator.

## Fresh-cut authority

The first fresh transition carries `fresh_cut_authority` with the closed fields
`schema`, `source_id`, `epoch`, `committed_event_id`, `snapshot`,
`snapshot_checkpoint_sha256`, `bridge_binding_sha256`, and
`authority_sha256`.

`snapshot` is a closed descriptor: `schema`, `locator`, `sha256`,
`size_bytes`, `sqlite_schema_sha256`, and `semantic_checkpoint_sha256`.
It describes a SQLite Backup API snapshot made before planning.  The authority
commitment is domain-separated over the complete object without its self hash.
The source identity must equal the bridge identity; the cut must be strictly
greater than the bridge cut for a fresh first transition.  Router retrieves the
descriptor-bound snapshot/source-evidence material, checks bytes, schema,
checkpoint, selected and mandatory provenance, and recomputes the authority.
Producer metadata is never sufficient.

The bridge archive remains immutable.  The active plan must cover selected and
omitted prior and new rows, all required provenance/event/cache witnesses, and
all protected closure.  Closure over 50,000 rejects before publication.

## Time and freshness

`content_created_at` is the artifact snapshot time, `transition.created_at`
equals it, and `produced_at`/pointer `published_at` are normal current wall
clock publication times.  Router retains its ordinary max-age check.  A fresh
cut does not authorize stale timestamps, clock substitution, or a larger
generic max age.

## Continuation

A successor has the same epoch ID and an explicit `predecessor` descriptor
equal to Router's accepted V2 descriptor.  It has a strictly greater
publication/content sequence; source cut is monotonic and may advance only
with a new fresh-cut authority.  It binds the prior transition hash, prior
active artifact hash, prior plan commitment, retained-floor declaration, and
archive descriptor.  No gap, rollback, alternate predecessor, policy drift,
or competing successor is accepted.

Only `CONTENT` successors are specified initially.  Heartbeats remain rejected
until a separate immutable no-state-change heartbeat descriptor binds the exact
accepted V2 content/transition/plan/artifact and a current pointer timestamp.
It must not advance source cut, history, policy, floor, archive, or epoch.

Router independently reconstructs selected/omitted sets, compact commitments,
provenance, qualification, coverage, lifecycle, and workflow closure before an
atomic accepted-state/cache update.  Failure leaves accepted state bytewise
unchanged.  Archive/bridge material is never ordinary-cleanup material.

## Implementation order

1. Scout Backup-API snapshot and fresh-cut-authority producer/validator.
2. Router independent snapshot/evidence reconstruction validator.
3. Scout fresh planner/artifact/plan/transition builder and package inputs.
4. Router first-fresh-transition acceptance.
5. Scout V2 content-successor publisher and Router continuation validator.
6. Reuse the existing installer only after package verification accepts the new
   revision; rehearse 232 -> 242 -> fresh V2 -> V2 successor in disposable
   roots, including restart and failure boundaries.
