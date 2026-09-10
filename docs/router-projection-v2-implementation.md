# Scout Router V2/A1 producer implementation review

Status: development candidate; **not deployed or operationally qualified**. This
work did not open a live Scout database or publication root, use signing identity,
perform network operations, change Router, change services/launchd, commit, or push.
All measurements and publications below use explicitly named temporary state.

## Contract and preflight

The authoritative input is `flop-router/docs/SCOUT_ROUTER_SNAPSHOT_V2.md`, with
`A1_RESOLVED=YES` and `SCOUT_V2_PRODUCER_CONTRACT_READY=YES`. The reviewed source
mapping is [router-projection-v2-source-review.md](router-projection-v2-source-review.md).
Its SHA-256 is
`bce31fa7dce1f133c317a09539d3eaa8745f15f45316b3250b65bdc36a6297a0`;
that preexisting untracked document was not edited. AGENTS.md, README, the entire
contract/source review, and Router's PRE-A1 benchmark were read before implementation.
Starting branch: `feature/tclk-discovery`; starting HEAD:
`e24636b409d26f74d981619e0521973cae68c870`.

| Field | Implemented value |
| --- | --- |
| Outer projection schema | `scout-router-projection/v2` |
| Manifest revision | `A1` |
| SQLite user_version | `2` |
| Selection policy | `router-evidence-horizons/2` |
| Classifier | `router-evidence-classes/2` |
| Qualification policy | `router-durable-qualification/v1` |
| Pin rule | `transitive-local-evidence-dependencies-no-implicit-unpin/v1` |
| Expiry clock | `trusted-first-observed-strict-before-expiry/v1` |

## Files changed

| Files | Purpose |
| --- | --- |
| `scout_projection.py` | Incremental projector, private replay ledger, qualification history, workflow state, reconstruction |
| `scout_projection_contract.py`, `scout_projection_model.py` | Strict canonical objects, IDs, policy, ranked classification, A1 validation |
| `scout_projection_rules.py` | Frozen pure Router capability rules and their dependency closure; no runtime Router import |
| `scout_projection_source.py` | Exact immutable raw/event/cache mapping and committed source outbox |
| `scout_projection_pins.py` | Validated cumulative local pin interchange and dependency resolution |
| `scout_projection_publish.py` | Online backup, validation, immutable publication, heartbeat and safe retention |
| `scout_projection_service.py`, `scout_projection_cli.py` | Optional background owner and explicit local CLI |
| `scout_runtime.py`, `scout_worker.py` | Optional committed-cut capture through Scout's existing source writer and service lifecycle |
| `scout_schema.py` | Exact optional outbox schema validation; unrelated schema drift still fails |
| `flop_scout.py` | CLI wiring; projection status does not implicitly create default Scout state |
| `docs/router-projection-v2-schema.sql` | Exact nine-table published A1 schema |
| `test_scout_projection.py` | A1, selection, source integration, replay, safety and publication tests |
| `scripts/benchmark_projection_v2.py` | Reproducible post-A1 capacity and actual producer probes |
| `scripts/projection_fixture_support.py`, `scripts/projection_v2_fixtures.py` | Standalone synthetic Router development fixtures, without a pytest dependency |
| `scripts/projection_audit_stress.py` | Actual producer duplicate/supersession and replay stress |
| `README.md`, this report, `docs/router-projection-v2-benchmark.json` | Usage, limitations and measured results |

## CLI additions

All commands require an explicit absolute dedicated projection path. No default
production database is opened. Example **development** initialization:

```sh
.venv/bin/python flop_scout.py projection \
  --db /private/tmp/scout-v2-demo/projection.sqlite init \
  --epoch development-source-epoch \
  --router-source-id development-router \
  --router-epoch development-router-epoch \
  --router-did did:key:z6MkDevelopmentRouter
```

The DIDs here are illustrative public identifiers, not generated identities. Use
the intended public bindings when preparing a separately reviewed environment.

With prefix `flop_scout.py projection --db /absolute/dev/projection.sqlite`:

| Subcommand | Required/optional arguments |
| --- | --- |
| `init` | `--epoch`, `--router-source-id`, `--router-epoch`, `--router-did`; repeatable `--local-did` |
| `status`, `pin-status`, `expiry-status`, `publication-status` | Read-only status; no initialization or lock-file creation |
| `source-init` | `--source-db /absolute/dev/source.sqlite`; explicitly installs outbox/indexes under the source poll lock |
| `update` | `--source-db`; one-time `--bootstrap --complete-cut N --evaluated-at UTC` on a prepared, complete, quiescent source |
| `replay` | Resume sealed pending work, or `--destination /absolute/new/projection.sqlite` for verified reconstruction |
| `pin-import` | `/absolute/cumulative-pins.json` |
| `expiry-run` | Optional `--evaluated-at UTC`; evaluates the last complete source cut |
| `publish` | `--root /absolute/dev/public --source-db /absolute/dev/source.sqlite --pins /absolute/pins.json` |
| `artifact-import` | `/absolute/artifact.json --id ID --source-id ID --epoch ID --authority AUDIT_DIRECTIVE\|CONTROLLED_BENCH\|OBJECTIVE_VALIDATION` |
| `qualify-local` | `--request-id ID --result-id ID --kind CONTROLLED_BENCH\|OBJECTIVE_VALIDATION\|CAPABILITY_CONTRADICTION` |
| `qualification-event` | `/absolute/event.json`; requires already imported, validated local audit authority/proof |
| `retention-run` | `--root /absolute/dev/public`; optional `--keep 4` |

Worker integration is opt-in through `worker run --projection-config
/absolute/config.json`. The JSON contains absolute `path`, `root`, and `pins`
paths plus optional `cadence` (seconds, default 900, minimum 60). Initialize and
bootstrap first. The worker does not implicitly build the source indexes or
initialize projection state. Without this flag it starts no projection owner.

## Projection schema and persistence

[The SQL](router-projection-v2-schema.sql) contains exactly `snapshot_meta`,
`messages`, `interactions`, `source_provenance`, `selection_membership`,
`watermarks`, `coverage_history`, `durable_qualifications`, and
`qualification_events`. Validation compares exact SQLite schema definitions,
including indexes, with this contract. No private tables enter the publication.

The dedicated projection is paired with `projection.sqlite.ledger`. One flock
owner writes both: the ledger is the SQLite main database and the projection is
attached, using rollback journals and FULL synchronization in the same directory.
This permits SQLite super-journal atomic commits across the pair. Keep the pair
together; loss or incompatible ledger schema fails closed instead of initializing
empty history. New candidates use incremental auto-vacuum.

The optional source outbox is written only by the existing Scout source owner.
It captures immutable raw IDs, derived-event/cache updates and interaction
notifications in bounded batches. A manifest seals a complete logical cut only
after active tail/export operations and queued source changes finish. Part hashes,
epoch, committed event cut and acknowledged position are checked on consumption.
Publication never backs up `observer.sqlite` and does not rebuild from it each cycle.

## A1 durable qualifications and event model

Capability qualification evaluates the complete selected sender group in canonical
order with global template sender counts and final duplicate suppression. A
bootstrap cannot manufacture an earlier successful prefix of a duplicate-heavy
group. The vendored pure rules bind Router source SHA-256
`30ac18aa715ea7a905f8c4a76e9a35def2fe432a3e96cba863536d5f7d10d71d`.

Each first qualification is immutable and content-addressed. It records source
and proof references, subject/claim, outcome, first qualifying evaluation/time,
source cut, bootstrap, rule input/group hashes, all policy versions, authenticity,
correctness/reproducibility and operator semantics. Current support annotations
can change while the historical qualification and its required witnesses remain.
First-qualification keys prevent duplicate processing from creating new history.

`SUPERSEDED` and `INVALIDATED` append hash-linked sequence events. There is no
`DOWNGRADE` event: duplicate-driven score changes are current interpretation.
Supersession does not itself label a qualification invalid or create negative
evidence. Invalidation requires an allowlisted reason, exact target/proof binding
and explicitly imported local audit directive. Forks, invalid ordering, broken
hashes, missing authority and supersession cycles fail closed. Original records
and invalidation proof remain permanent. Remote room allegations cannot authorize
these transitions.

Configured original local Bench request/result artifacts can establish controlled
verification qualifications with exact request hash, task/routing linkage,
requester/Bench role and PASS/FAIL checks. Objective contradiction additionally
requires a named supported capability, deterministic FAIL and concrete failed
boolean checks. It adds a scoped contradiction; it does not erase or invalidate an
earlier positive qualification.

## Replay ledger

The private ledger retains canonical source input versions, aliases, evaluation
input/edge manifests, complete-group rule manifests, qualifications, events,
ordered operations, pins, local originals, dependency frontier and checkpoints.
Evaluation/operation heads detect truncated tails. Qualifications are checked
against their original evaluation's time, bootstrap and source cut.

Restart resumes pending sealed evaluations. Full `replay --destination` reconstructs
a new pair using original operation order and evaluation times, compares every
published fact table, restores content/publication allocator state and validates
history. Local Bench closure is reconstructed too. The destination must be new;
divergence leaves a diagnostic candidate and never silently repairs the source.
Unsupported future policy/classifier versions fail closed; historical meaning is
not rewritten under the current version.

## Selection policy, classifier and negative evidence

Explicit classifier ranks implement TCLK, exact Bench, recognized Kibble,
configured official announcement, identity, versioned generic work, anchored
work/verification/rail prose, capability/promotion, malformed attempt and ordinary
fallback precedence. Exact protocol recognition can outrank malformed content;
classification does not establish authenticity. Current support and linkage use
only the contract's approved annotation fields. The source adapter does not turn
a claimed official label or URL into authority.

Permanent membership includes established identity/operator facts, Bench audit,
durable concrete support/contradiction, established negative facts, qualifications
and their proofs. Ordinary selected context gets 30 days; capability signals get
90 days. Closed work/TCLK context gets 90 days from authoritative closure.
Active/unresolved workflows, pins and required dependency chains override expiry.
Expiry uses trusted first observation and a strict-before boundary, never sender
timestamps or a replay clock as a fresh lifetime.

Negative evidence is limited to established signature/provenance or DID mismatch,
supported scoped rejection/failure, proved audit invalidation and linked objective
contradiction. Arbitrary criticism remains a claim. Supersession is not negative.

## Workflow identity and closure

Stable `sw1` IDs bind protocol, namespace, issuer, room/generation where applicable
and immutable workflow key. Private state retains identity, state, `closed_at`,
closure evidence/reason and required proofs. Stable `si1` interaction IDs bind
source/target immutable endpoints and factual relationship; confidence updates
do not change identity. Neither identity uses insertion order or timestamp-only IDs.

Kibble closure requires an authenticated root poster and exact linked result;
an unlinked ACCEPT or board status cannot close work. Conflicting terminal proofs
remain unresolved. TCLK offer expiry requires an authenticated maker, valid
integer `expiresMs`, unambiguous root and no linked active transition. Any active
TCLK obligation remains unresolved; no settlement or claim action is inferred.
Local controlled Bench PASS closes the verification request; objective FAIL is a
retained rejected audit. Conflicting Bench outcomes reopen it to CONFLICT. Generic
work without supported terminal proof stays unresolved.

## Pins, dependencies, expiry and raw text

Pins come only from a local cumulative export; Scout never opens Router's private
state database. Imports validate source/router epochs, canonical hash, revision,
previous hash, roots, reference kinds, immutable superset and retention modes.
An identical import is idempotent; missing dependencies or malformed inputs block
publication. There is no implicit unpin or network fetch of proof.
Pin application commits at most 200 members per transaction. A durable pending
export hash fences source evaluation/publication after interruption; re-import
the same export to resume it before accepting another revision.

Typed local references resolve through exact raw/event/evidence IDs, immutable
interaction endpoints, workflows and explicitly imported original artifacts.
Persisted sorted frontiers and visited sets handle cycles. Expansion is bounded
to 200 nodes per transaction and fails NOT_READY above 100,000 nodes per root;
it does not truncate the required graph or pin unrelated warehouse history.
Pinned edges retain their endpoints, and later required members inherit pin roots.

Expiry uses indexed due work in bounded batches, rechecks policy/pins/qualification
dependencies, and persists progress. Incremental vacuum reclaims up to 200 pages
per completed cut without a full database rewrite. Status exposes pending cuts,
expiry backlog, pin readiness and publication health.

`messages.text` is the canonical published original full text. Existing normalized
text is preserved as the separately specified derived field; provenance and
qualification manifests use hashes/references instead of another raw-text copy.
The private replay archive deliberately retains source versions and local originals.

Configured family evidence preserves `operator_group=local-flop-agent-family`,
`same_operator=true`, `independent_reputation=false`. Unknown identity/operator
relationships remain null. Hashing, publication and Bench qualification never
convert controlled evidence into independent reputation.

## Publication, heartbeat, retention and watermarks

Changed content uses SQLite online backup of the dedicated projection. The candidate
is closed, checked against exact schema/content/history, integrity checked,
fsynced and SHA-256 addressed. Immutable database and manifest names are published
before atomic replacement of `current.json`. A shared publication-root lock also
fences retention. Failures retain the accepted pointer. Validation compares the
candidate with the last accepted database to prevent loss of audit history,
permanent bodies, pins or historical coverage even if both working copies lost data.

Publication ID and database content ID are separate persistent decimal allocators
(up to the contract's 20-digit values). Heartbeats revalidate the referenced file's
hash, update freshness/publication ID, and reuse the database bytes/content ID.
The default 15-minute cadence prevents evidence arrivals from triggering continuous
backup. Due expiry is evaluated before refreshing freshness.

Reference-aware retention preserves databases used by the current/retained
manifests; the root lock protects in-flight work. It deletes only matching owned
filenames, rejects symlinks/non-regular files and never traverses outside the root.
Shared heartbeat databases are handled once.

Watermarks are derived from completed projected rows, grouped and ordered by room
and generation, including `UNKNOWN_LEGACY`. They assert no warehouse-wide coverage.
`coverage_history` retains maximum-ever projected positions and exact witnesses
after ordinary membership expires.

## Size/readiness and post-A1 benchmark

Preferred is below 512 MiB. Below 1 GiB is `QUALIFIED`; 1 GiB through 4 GiB is
`WARNING_LARGE`; over 4 GiB is `OVERSIZE`. Incomplete/invalid state is `NOT_READY`.
Over-cap publication fails while preserving the accepted pointer. There is no
silent truncation or unreviewed 8 GiB override. Byte readiness alone is not
operational qualification.

Final measured results and assumptions are in
[router-projection-v2-benchmark.json](router-projection-v2-benchmark.json).
The capacity model materializes 100k, 350k and 1M message rows in exact A1 tables:
90% ordinary context, 10% concrete support, all five qualifying capability
witnesses for each positive specimen, and invalidation for 1% of messages (all five
witnesses). Normalized text is populated. Audit authority references are synthetic
and cannot be used as production attestations. A1 table pages and encoded JSON
bytes are measured separately from all indexes.

The materializer directly builds exact published tables; its rows/second is not
warehouse ingest throughput. Update/expiry probes separately call the actual
Projector with 200 rows, assert all 200 really expire, and report that timing.
They do **not** establish million-row steady-state update throughput or production
scheduler/checkpoint latency. This needs a later explicitly authorized qualification.

The actual producer duplicate stress preserves five first qualifications after
201 identical messages. The supersession stress retains 250 qualifications and 49
events for 50 distinct source messages, verifies reconstruction and confirms that
supersession does not create negative membership. Both public and private ledger
sizes are included in the machine-readable benchmark report.

## Validation and Router compatibility artifacts

The full regression suite, self-test, compilation and whitespace checks are run
from this repository with temporary state. Final counts and artifact locations
are recorded below after completion. The suite includes scheduler fairness,
checkpoint/coverage, diagnostics, evidence integrity and existing safety counters;
the optional runtime test verifies the source writer and complete-cut integration.
New tests cover A1 history/current support, audit proof, replay/version mismatch,
stable interactions, workflow closure/conflicts, pins/cycles, expiry, UNKNOWN_LEGACY,
atomic pointer failure, retention, size thresholds, cancellation and no key/network
access through projection.

Consumer fixtures include normal, heartbeat reuse, controlled Bench, duplicate
downgrade, invalidation, UNKNOWN_LEGACY, large warning and oversize rejection.
They use the fixed synthetic clock `2026-09-08T12:00:00.000000Z`; consumers must
inject that clock when testing freshness. The oversize artifact deliberately uses
sparse padding beyond 4 GiB and must be rejected before SQLite access. Large-size
fixtures use synthetic measured content, not real authority. Router was not edited
or executed during this task.

## Known limitations and future production plan

- This is an opt-in development candidate. A long source export can delay a
  complete cut and publication; observation continues, but freshness/load needs
  qualification. No live scheduler performance claim is made.
- Complete sender groups are limited to 100,000 records, dependency roots to
  100,000 nodes, and TCLK source-reference lookups/fanout to 200. Capacity failures
  are explicit NOT_READY conditions. These are not silent evidence limits.
- Source cache linkage must be exact. Unsupported or ambiguous workflow terminals
  stay unresolved; the Kibble source adapter currently requires an explicit
  immutable result raw-ID link for acceptance. It does not invent a rejection
  wire format or infer settlement. Official registry authority is not guessed.
- Local Bench/objective and audit inputs require explicit configured imports.
  No external authority fetcher or automatic network Bench closure adapter is
  introduced. Permanent transcript retention is unaffected by missing closure.
- Private input/outbox/audit history is retained for deterministic replay. No
  unreviewed pruning policy exists; budget that disk separately from published DBs.
- Future policy/classifier migrations and an 8 GiB override require separate
  review. Schema/history mismatches fail closed.

Future deployment, **not executed here**: review this diff and Router compatibility
results; agree capacity/cadence and disk budgets; authorize a maintenance window;
fence the source writer and preserve backups; prepare exact outbox indexes;
initialize a distinct V2 projection/ledger with reviewed source/router epochs and
public DID bindings; bootstrap an explicit complete cut; import cumulative pins
and required local originals; inspect a candidate publication; then explicitly
enable worker integration and run a separately authorized scheduler/publication
qualification. Verify heartbeat reuse, Router acceptance, pin failures and rollback
to the accepted pointer before treating it as operational. Do not replace working
history or reset epochs as a recovery shortcut.

## Reproduction commands

Use new temporary roots; the scripts refuse to overwrite existing artifacts:

```sh
.venv/bin/python scripts/benchmark_projection_v2.py \
  --root /private/tmp/my-v2-100k --rows 100000
.venv/bin/python scripts/benchmark_projection_v2.py \
  --root /private/tmp/my-v2-350k --rows 350000
.venv/bin/python scripts/benchmark_projection_v2.py \
  --root /private/tmp/my-v2-1m --rows 1000000
.venv/bin/python scripts/projection_audit_stress.py /private/tmp/my-v2-audit
.venv/bin/python scripts/projection_v2_fixtures.py \
  --root /private/tmp/my-v2-fixtures \
  --large-source /private/tmp/my-v2-350k/projection-350000.sqlite
```

Tests use an external temporary pytest installation because the repository venv
does not contain pytest. No dependencies were added to the repository:

```sh
PYTHONPATH=/private/tmp/scout-test-deps \
PYTHONPYCACHEPREFIX=/private/tmp/scout-v2-impl-cache \
FLOP_SCOUT_STATE_DIR=/private/tmp/scout-v2-reviewed-test-state \
  .venv/bin/python -m pytest -q
FLOP_SCOUT_STATE_DIR=/private/tmp/scout-v2-review-self-test \
  .venv/bin/python flop_scout.py self-test
git diff --check
```

## Final measured results

| Messages | Qualifications / events | DB MiB | Index MiB | Bytes/message | A1 tables + indexes MiB | Readiness |
| --- | --- | --- | --- | --- | --- | --- |
| 100,000 | 50,000 / 5,000 | 367.76 | 18.64 | 3,856.26 | 109.47 | QUALIFIED |
| 350,000 | 175,000 / 17,500 | 1,288.05 | 65.97 | 3,858.90 | 383.18 | WARNING_LARGE |
| 1,000,000 | 500,000 / 50,000 | 3,679.77 | 187.99 | 3,858.52 | 1,094.88 | WARNING_LARGE |

Index bytes include all published indexes; the A1 column includes audit table
pages and their indexes, so these columns overlap. This isolates the added
audit objects, not a claim that the remaining schema exactly matches V1.

| Messages | Materialize s | Backup s | Integrity s | SHA-256 s | Full validation s | Peak RSS MiB |
| --- | --- | --- | --- | --- | --- | --- |
| 100,000 | 74.97 | 0.62 | 0.33 | 0.14 | 9.22 | 109.50 |
| 350,000 | 270.13 | 1.74 | 1.44 | 0.51 | 33.27 | 113.83 |
| 1,000,000 | 775.06 | 4.41 | 5.80 | 1.38 | 99.43 | 120.42 |

| Associated capacity run | Actual update rows/s (200 rows) | Actual expiry rows/s (200 rows) |
| --- | --- | --- |
| 100,000 | 416.57 | 900.86 |
| 350,000 | 408.99 | 802.43 |
| 1,000,000 | 420.12 | 867.68 |

At 1M messages this synthetic profile consumes 3.594 GiB, with 416.23 MiB below the hard ceiling. It remains a warning-sized candidate, not normal operational qualification.

Final full suite: **418 passed in 54.22s** (364 baseline + 54 added cases). Self-test: **PASS**. `py_compile`: **34 files passed**. `git diff --check` and checks of new files: **PASS**.

Actual duplicate stress: 201 messages, five qualifications before and after duplication, 483,328 projection bytes and 897,024 private ledger bytes.

Actual supersession stress: 50 messages, 250 retained qualifications, 49 events, 778,240 projection bytes and 2,170,880 private ledger bytes; deterministic reconstruction passed.

Fixtures: [/private/tmp/scout-v2-a1-review-fixtures/index.json](/private/tmp/scout-v2-a1-review-fixtures/index.json). All eight manifest/database hash pairs, size states and heartbeat identity reuse verified. Fixed synthetic clock only.

Raw evidence:

- `/private/tmp/scout-v2-a1-capacity-{100k,350k,1m}/results.json`
- `/private/tmp/scout-v2-a1-final-audit-stress/results.json`
- `/private/tmp/scout-v2-a1-review-fixtures/verification.json`
- `/private/tmp/scout-v2-a1-reviewed-tests.log`

Final `git status --short`:

```text
 M README.md
 M flop_scout.py
 M scout_runtime.py
 M scout_schema.py
 M scout_worker.py
?? docs/router-projection-v2-benchmark.json
?? docs/router-projection-v2-implementation.md
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

Stopped for review. No deployment, commit, push, Router edits, service changes or production-state access.
