# A1-LG2-TL1 validator preflight — implementation incomplete

No Scout runtime changes were made. This packet proposes a concrete validator
artifact for coordinated review; it is not a TL1 implementation or a Router
handoff. No production data, including frozen production copies, was accessed.
Router files were read only. No services, deployment, commit or push occurred.

## Preflight

Branch `feature/tclk-discovery`, HEAD `e24636b`. Existing dirty changes belong to
the preceding Scout work. Runtime/script hashes matched the preceding dry-run
baseline; no unexpected changes were found. The requested Scout documentation,
Router contract, TL1 design and additive DDL were read. Previously read unchanged
documents were verified against their recorded hashes.

The exact target remains `A1-LG2-TL1`, with selection
`router-evidence-horizons/3`, classifier `router-evidence-classes/3`, qualification
`router-durable-qualification/v1`, and validator `router-tclk1-structure/1`.
The twelve-table public representation adds only `legacy_tclk_records`; no DDL
deviation is proposed.

## Unresolved validator binding

The [approved design](/Users/greg/Dev/flop-router/docs/ROUTER_TCLK_LEGACY_RECONCILIATION_DESIGN.md:56)
requires the exact schema bytes to be “bundled with implementation and allowlisted
by both owners,” and calls for shared independent golden failure vectors. The
provided authoritative inputs contain a validator version, but no concrete schema
hash, immutable upstream commit, or approved vector artifact.

This missing binding is consequential: the official JSON Schema and the upstream
function named `validateFrame` have different acceptance sets. A pin of schema
bytes alone does not describe whether the function's additional checks belong in
the TL1 structural classification boundary. The design says state/role/deadline
checks remain separate and full schema validity excludes TL1; those provisions
favor a schema-only structural boundary, but this should be explicit in the shared
vectors before either owner claims parity.

Concrete candidate fetched using read-only public GETs:

- Repository: `flop-labs/tclk`.
- Immutable commit: `5cc4ab93efbc8999a3a7e1471b639deca25998ea`.
- Schema path: `schema/tclk1-frames.schema.json`.
- Exact bytes: 6,070.
- SHA-256: `17071a2b3b21e8484cac9da7976088f3700e6fb6c1372268d4756b61ddd60c70`.
- Local [candidate schema](tclk-tl1-validator-review/tclk1-frames.schema.candidate.json)
  and [candidate vectors](tclk-tl1-validator-review/candidate-vectors.json).

The candidate is not registered as an approved runtime allowlist. Both-owner
agreement is not inferred from the fact that it is the current upstream commit.

## Concrete parity cases

The following results come from inspection of the immutable source, not execution
of the upstream TypeScript validator. The vector file contains unsigned synthetic
objects and makes no authentication, workflow, or publication claim.

| Input | JSON Schema | Upstream `validateFrame` | Proposed schema-only TL1 mask |
| --- | --- | --- | --- |
| Complete ACCEPT with ref and contract | Valid | Structurally accepted | 0 |
| Same ACCEPT with ref/contract removed and offer_id supplied | Invalid | Rejected | 15 |
| Complete ACCEPT plus paymentKey consisting of 33 zero bytes in hex | Valid hex33 | Rejected as an invalid curve point | 0 |
| RECEIPT with outcome `["claimed"]` | Invalid enum/type | Accepted through `String(frame.outcome)` | 272 |

The [immutable schema](https://github.com/flop-labs/tclk/blob/5cc4ab93efbc8999a3a7e1471b639deca25998ea/schema/tclk1-frames.schema.json)
requires ACCEPT ref and contract and disallows offer_id. The
[matching reference source](https://github.com/flop-labs/tclk/blob/5cc4ab93efbc8999a3a7e1471b639deca25998ea/src/frames.ts)
adds point validation and uses the receipt outcome coercion described above.

Recommended decision: freeze the candidate schema for the TL1 structural
boundary, with strict duplicate-key/unparseable handling as specified by TL1;
keep protocol identity, cryptographic point validity, transition, role and deadline
checks separate. Never copy the receipt coercion. Review the candidate vectors as
part of a complete shared vector set. This recommendation is not implemented.

## Requested implementation and validation status

Classification, all reason masks, exact table emission, typed claims, AUDIT_HINT,
complete domain holds, dependency accounting, inclusive capacity enforcement,
receipt handling, workflow/closure exclusions, positive-scoring exclusions,
generation authority, deterministic replay, explicit migration, manifest bindings
and diagnostics remain unimplemented for TL1. Existing LG2 behavior was not edited.

The required twelve complete Router fixtures were not generated. The four review
vectors above are not substitutes. The 2,505-record, 4,096-record, 100,000-held-row
and 256-MiB boundary workloads were not run. Hold amplification, TL1 table allocation,
throughput and peak RSS are unmeasured; capacity acceptability is not established.

No runtime tests, self-test or py_compile were run for this documentation-only
packet. The preceding 584-test result is historical, not a new validation result.
Candidate JSON parsing, byte hash and `git diff --check` were checked locally.

Router still needs the independent implementation described in the approved TL1
design, including explicit activation, schema and reason validation, full holds,
closure safety, evidence filtering, continuity, capacities and its new shadow policy.
No production dry run or Router acquisition is ready.

## Files added

- `docs/router-projection-v2-tl1-preflight.md` — this report.
- `docs/tclk-tl1-validator-review/tclk1-frames.schema.candidate.json` — exact upstream candidate bytes.
- `docs/tclk-tl1-validator-review/candidate-vectors.json` — four structural review vectors.

## Readiness

```text
SCOUT_A1_LG2_TL1_IMPLEMENTED = NO
SCOUT_TL1_FIXTURES_READY = NO
TL1_CAPACITY_MODEL_ACCEPTABLE = NO
SCOUT_A1_LG2_TL1_READY_FOR_ROUTER_IMPLEMENTATION = NO
SCOUT_A1_LG2_TL1_READY_FOR_PRODUCTION_DRY_RUN = NO
```

`NO` for capacity means unvalidated, not a measured failure of the limits.
The pending decision is the exact coordinated validator pin and structural boundary;
the rest of the authorized implementation remains outstanding.
