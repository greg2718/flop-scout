# Bounded current Scout publication

`scout_current_publication.py` creates one separate, restartable current-evidence
enrollment under the existing A1 wire contract. It does not run the historical
bootstrap, install an outbox on Scout, alter a policy, or activate LG1/LG2/TL1.
Router configuration is not changed by this command.

```sh
.venv/bin/python scout_current_publication.py \
  --source /Users/greg/.flop_scout/observer.sqlite \
  --work /Users/greg/.flop_scout/router-current/private \
  --root /Users/greg/.flop_scout/router-current/publication \
  --router-state /Users/greg/.flop_agents/router/worker/worker_state.json
```

Selection is explicit and partial: at most 1,000 recent entries per semantic
class, then at most 10,000 newest events, subject to a 25,000 ambient-record cap
and a seven-day trusted local derivation-time cutoff. Up to 64 records per known
local identity and bounded TCLK root candidates supplement this set. Required
explicit pins are outside the ambient horizon; all admissions together are
limited to 50,000 raw records and 128 MiB of raw/event payload. Unsupported or
missing explicit pinned references fail closed. Each live-source query has a
one-second SQLite progress deadline, uses existing indexes, and releases its
read transaction after fetching its bounded result. No live schema, source
indexes, identity material or service configuration is changed.

The extract is an immutable enrolled cut. Resume uses that cut and the durable
projection ledger; it does not silently advance freshness. Repeating a completed
build produces an ordinary A1 heartbeat with the original evaluation time and
same database bytes. The separate scheduled refresh below advances the bounded
current enrollment. Do not reuse a historical projection as its working state.

Raw legacy identity/Bench reserve records retain UNKNOWN_LEGACY generation;
reported compatibility generations are not borrowed. A TCLK transcript whose
root is absent remains an explicit `scout-unresolved/v1` workflow without a
terminal event or closure claim. Raw text, nonce and signature are preserved.
This source-adapter behavior is isolated here; full source mapping and TL1
qualification rules are unchanged. Complete known workflow roots and dependencies
continue through the existing producer. Unsupported current records fail closed.

The initial pin set is explicitly empty because this Router state has no accepted
Scout snapshot or contract and no supplied pin export. An existing accepted
publication requires an explicit cumulative `--pins` artifact. The public local
Scout/Bench/Router DIDs match Router's public family registry; family evidence is
never marked independent.

## Generated artifact and validation

Root: `/Users/greg/.flop_scout/router-current/publication`

Immutable database:
`router-projection-v2-1-5d23b03aa1099af7457174ba190f9bc27da77892a150e37f385c2d30aad34da4.sqlite`

The extract selected 14,083 raw records; normal A1 selection published 13,867
messages, 13,867 provenance rows, 13,867 selection rows, 2,830 qualifications,
10 watermarks and 10 coverage-history rows. Database size: 45,113,344 bytes.
The working ledger contains 1,757 workflows, 1,569 open/unresolved. Router's
actual `ProjectionReader` accepted the immutable publication as READY in
1.178 seconds, including one Bench verification observation and 11 local-family
relationship annotations. No Router worker or input configuration was changed.

Four focused tests cover deterministic database reuse after restart, mandatory
pins for existing Router state, conservative missing-root retention, and refusal
to open historical projection state. Full live extract selection and generation
used no network requests. Detailed run and consumer-validation results are in
`scout-current-publication-result.json`. Private extraction/ledger files and the
complete plan remain under the separate private working directory.

## Automatic current refresh

`scout_current_refresh.py` is invoked by the user LaunchAgent
`com.flop-scout.current-publication` with a 600-second interval after completion, and at login/load. The
installed configuration is reproduced in
`scripts/com.flop-scout.current-publication.plist`. Failed runs retry automatically
with a 60-second launchd throttle. Scout and Router do not need to restart.

Each run reads an indexed committed source cut, then captures its evaluation
time. It selects at most eight new records per semantic class plus 128 newest
events, with an overall cap of 256 admissions per run. The same separate A1
ledger retains the source identity, epoch, dependencies, qualifications and pin
continuity. It never reads the historical projection. Source access is read-only.

A locked, atomically saved pending plan and existing staged-evaluation replay
make interrupted runs resumable. The immutable publication pointer changes only
after producer validation. Capture time remains fixed on replay; captures older
than ten minutes are not published. A nine-minute process budget plus ten-minute
cadence leaves substantial margin inside Router's one-hour snapshot age limit.
Only the private current publisher job is scheduled; the Scout core scheduler is
unmodified. `refresh-status.json` reports success or a fail-closed error.

Enrollment stops at 50,000 raw records or 512 MiB of private SQLite state. Four
immutable publications are retained. Capacity exhaustion retains the last valid
pointer and reports degradation; it cannot indefinitely certify freshness. This
is bounded current SHADOW enrollment, not full-history qualification.

Live verification on 2026-09-10 observed IDs 1 → 2 → 3. Launchd started the
second successful run automatically ten minutes after completion of the first.
ID 3 generation took 127.46 seconds and advanced expiry to 09:09:05 EDT.
Router accepted ID 3 and remained READY_IDLE without restart. Scout remained
HEALTHY with its original start time throughout observation. Eleven offline
tests passed, including staged recovery, stale-capture rejection and interruption
after publication. Results: `scout-auto-publication-result.json`.
