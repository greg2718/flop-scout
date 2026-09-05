# Evidence hardening implementation report

Implemented on `feature/scout-evidence-hardening` in the isolated worktree
`/private/tmp/flop-scout-evidence-hardening`. The original checkout remains on
`feature/tclk-discovery`. Its pre-existing `flop_scout.py` and
`test_flop_scout.py` edits were copied into this worktree before implementation.
Diffs against HEAD therefore include those existing Kibble/verification changes.

The production `~/.flop_scout/observer.sqlite`, identity, and LaunchAgent were not
modified. No identity was regenerated. The supplied persistent DID remains
`did:key:z6MkfJnczowbivU9SEDcZ77MEpKUfQTVbcD3i1gcwsfo4yL1`.
Process inspection was restricted, so the running process was not inspected;
isolation avoided depending on which checkout it uses.

## Files changed

- `flop_scout.py`: integration, writer/read-only connections, guarded observation,
  atomic cursor updates, malformed-page retention, poll metrics, local CLI, and
  state-directory override. Includes the user's carried-forward edits.
- `scout_evidence.py`: raw storage, migration, classification, duplicate analysis,
  collections, integrity, feed, report, and status metrics. No network or key-file
  dependencies.
- `test_scout_evidence.py`: 39 new focused tests.
- `test_flop_scout.py`: existing suite retained; HTTP-read test mock updated for
  redirect blocking. Includes the user's carried-forward tests.
- `watch_collections.default.json`: documented defaults.
- `README.md`, `docs/evidence-feed.md`: architecture and operational contract.
- `docs/evidence-hardening-report.md`: this report.

## Schema changes

Added `evidence_schema`, `raw_network_records`, `observed_events`,
`watch_collections`, `watch_collection_sources`, `raw_record_watch_membership`,
`evidence_settings`, `evidence_metrics`, `evidence_poll_cycles`,
`evidence_retrievals`, and `compatibility_evidence_links`.

Raw insert/update/delete protection, composite raw-ID/hash foreign keys, and
indexes support immutable evidence, deterministic feed cursors, provenance lookup,
classification filters, duplicate lookup, collection queries, and reporting.
Existing tables remain intact as compatibility indexes.

## Raw evidence model

Exact valid UTF-8 text, nonce digits, signature, DID, timestamps, room, generation,
endpoint, retrieval time, and available HTTP metadata are retained. Envelope JSON
is labelled as reconstructed; signed text is never normalized. Invalid strings
or non-object envelopes survive in ASCII-escaped JSON with an explicit hash-basis
fallback. Raw identity includes complete decoded envelope provenance and excludes
retrieval time and pagination URL. Replays suppress another event; changed
records remain separate. Conflicting payloads at one source position are counted.

Each raw page and its primary derived events persist before legacy parsing and
cursor advancement. Generation, sequence, and continuity update atomically.
Malformed compatibility parsers cannot discard primary raw/feed evidence or block
unrelated records. Header/body generation conflicts and exposed retention gaps
preserve evidence while withholding cursor advancement.

## Derived event model

Every `observed_events` row references a raw ID and hash via a composite foreign
key. It includes stable increasing local ID, parser/classification versions,
classification reason, signature/parse statuses, structured claims, and duplicate
metadata. Integrity checks also audit raw hashes/identities, missing events,
foreign keys, conflicts, and compatibility-source links. `evidence repair` is an
explicit local writer for missing events.

## Watch collections

Nine configurable defaults cover faucet, kibble, consensus_layer, tclk,
a2a_mesh_router, external_work_offers, registry_announcements,
official_protocol_announcements, and competitor_projects. Unknown announcement
and external-work sources remain empty. Existing service/mailbox/validation rooms
continue to work. Many-to-many memberships do not duplicate raw evidence. Local
config accepts only room names; config never creates a web scraper.

## Classification rules

Deterministic declared JSON types and anchored lexical rules cover all requested
initial classes, plus versioned Kibble event classes and explicit unknown state.
TCLK syntax and sender-binding failures are distinguished. Official announcements
are self-declarations, not assertions of official authority. Every parsed claim
states that correctness has not been verified. No LLM dependency was introduced.

## Duplicate detection

Exact reposts use raw text hashes; immutable-record replays produce no new event.
Promotional templates may mask explicit timestamps, nonces, sequence numbers,
UUIDs, and job IDs in derived analysis. Capability, amount, result, and other
substantive changes remain distinct. Work results never use template masking.
Classification describes observed content and similarity, not reputation or truth.

## Evidence feed

SQLite plus JSONL use `flop-scout-evidence/v1`, ordered by exclusive `--since-id`.
Collection, classification, and sequence filters are available. Raw source/hash,
source endpoint, generation, timestamps, parsed content, watch associations,
duplicate metadata, and provenance completeness travel with each event.
Operator relationship is unknown unless established outside remote claims.

Router, Bench, and Sentinel own separate local checkpoint files/databases. Commit
consumer results before advancing its checkpoint; use event-ID deduplication for
replay. No consumer can mark evidence globally consumed. Read-only database
connections and OS permissions keep consumers away from raw mutation.

## Daily report

Local UTC retrieval-date reports include first-seen DIDs/locations, work events,
malformed records, signature failures, DID mismatches, conflicts, TCLK frames and
rail claims, watch changes, duplicate groups, and scoped safety counters. Reports
are JSON and never rescan the network. Exports and reports refuse to overwrite
existing output files.

## SQLite concurrency changes

Writer and read-only connections are separate. Writers use WAL, foreign keys,
five-second busy timeout, version-gated migration, and configuration change
checks. Status/report/feed/export do not initialize schema, import history,
commit, or access the network. Tests hold an active `BEGIN IMMEDIATE` transaction
while status, report, and export succeed through read-only connections.

## Security invariants

Observation blocks private-key loading and signed-write helper calls. Room reads
reject HTTP redirects. Remote URLs, commands, payment instructions, and secret
requests remain inert strings. Safety counters cover network writes, URL follows,
wallet access, faucet claims, TCLK actions, Kibble claims, and private-key access.
They remain zero in validation. These are observation-path counters, not a
host-wide audit. Existing approved publishing commands retain `--yes` gating.

## Test results

- Full current suite: **166 tests passed** (`python -m unittest -v`), including
  127 existing tests and 39 added tests.
- Scout local Ed25519 self-test: **PASS**.
- `git diff --check`: **PASS**.
- Temporary empty-state CLI init/integrity/status/report/feed: **PASS**.
- Temporary populated fixture: **3 raw records, 3 parsed events**, zero orphaned
  events, hash/identity mismatches, missing events, unlinked compatibility records,
  and foreign-key errors; integrity **PASS**.
- Local filtered JSONL export, daily report output, and soak-status: **PASS**.
- Restart/replay, 450 records in 200+200+50 pages, budget exhaustion, crash before
  cursor update, raw-only repair, transactional migration rollback, raw replacement
  protection, malformed Unicode metadata, 19-digit nonce precision, generation
  changes/conflicts, retention gaps, and independent consumer checkpoints tested.

Used the existing repository virtualenv interpreter without modifying it:
`/Users/greg/Dev/flop_scout_v02/.venv/bin/python`.
Every validation process used `FLOP_SCOUT_STATE_DIR` under `/private/tmp`; unit
fixtures additionally use temporary databases. No development test used the
production database. Network polling was mocked; local CLI validation made no
network requests. Full test output is `/private/tmp/scout-final-tests.txt`.

## Migration plan

Migration is prepared, not applied to production. For a later rollout, use SQLite's
backup API to create a consistent copy of the active WAL database. Migrate the
copy with `evidence init --db PATH`, verify integrity, and measure required disk
space/time. Schedule the production writer migration deliberately after review.
No launchd changes or production restart are part of this implementation.

Historical source material is explicitly `legacy_record=1` and
`raw_completeness=PARTIAL`; missing original data is not fabricated. Old generation
values remain reported provenance. New captured records with known endpoints are
`COMPLETE`; this means capture completeness, not signature or claim validity.
No raw retention, deletion, or lossy pruning was added.

## Known limitations

- Exact HTTP transport bytes are not retained by the JSON polling adapter;
  decoded message UTF-8 suffices for signature verification. Invalid top-level
  HTTP/JSON responses are read failures and cannot supply record-level evidence.
- Server-side ephemeral history can disappear before retrieval. Scout detects
  exposed retention gaps but cannot reconstruct unseen records.
- Legacy compatibility indexes and aggregate views retain their older semantics;
  consumers must use the new feed. Historical missing provenance stays partial.
- Existing Kibble board reconciliation is a separately labelled convenience
  cache, not a replacement for or a signed event in the room feed.
- Conservative rules intentionally leave unsupported prose unclassified and do
  not infer official authority, correctness, independent operators, or reputation.
- First-seen and duplicate classifications are relative to this database's
  observations. The first duplicate-group member remains classified as unique.
- Local safety metrics cover Scout observation paths; database-error persistence
  is best-effort when storage itself fails.
- Initial migration can be large. Production data-volume timing has not been
  measured; migration should be tested against a consistent backup first.
- Soak elapsed time includes downtime and counts per-room cycles. Logs/scheduler
  records are needed to establish uninterrupted 24-hour operation.
- Bench/Router/Sentinel code is not present here; their feed adoption is a separate
  integration step. Consumer checkpoints are intentionally consumer-local.

## 24-hour soak commands

Prepared only; **not started**. Full timed-loop instructions and acceptance checks
are in [the operations guide](evidence-feed.md#safety-and-a-future-24-hour-soak).
Choose a dedicated state directory; do not start a second production worker.

```sh
export FLOP_SCOUT_STATE_DIR=/path/to/dedicated-soak-state
python flop_scout.py evidence init
# Later approved polling run:
python flop_scout.py service-poll
python flop_scout.py evidence soak-status
python flop_scout.py report daily --json
python flop_scout.py evidence verify-integrity
```

No commit, push, production migration, LaunchAgent modification/restart, live
network write, wallet action, claim, or settlement action was performed.
