# Poll locking and retention recovery

The deployed shell wrapper used a directory and an EXIT trap. SIGKILL, a crash,
or a reboot can leave that directory behind indefinitely. The canonical wrapper
is now `scripts/scout-service-poll.sh`; Python owns `run/service-poll.flock` using
`fcntl.flock(LOCK_EX | LOCK_NB)` for the entire service poll. Both CLI and wrapper
enter this lock before opening SQLite or observing the network. A loser prints
`SKIP active poll lock held` and exits successfully. The OS releases the lock on
process termination. Never delete or rotate the flock file: replacing its inode
would allow two processes to acquire different locks. A persistent file is normal.

Lock contention is counted in `run/poll-lock-contention.log` using one atomic
append per skip. Losers never write SQLite. Service status and soak status read
this file; no stale-lock counter is invented. This counter is scoped to the state
directory, is not a host audit, and resets if its telemetry file is removed.
Telemetry write errors are reported on stderr but do not turn contention into a
failed poll. The wrapper logs START and END rc=N and propagates Python's exit
status. An uncatchable kill of the wrapper itself can still omit END; it cannot
leave a stale kernel lock after the Python process exits. A surviving Python
child correctly continues to hold the lock.

## One-time legacy migration and installation

**These are deployment instructions only. Do not run them during development.**
Before replacing the old wrapper, quiesce the existing launchd job and manual
launches using the site's maintenance procedure. Wait for existing polls to end.
Keep scheduling quiesced through both commands below. A process-list snapshot
alone cannot prevent an old scheduled wrapper from starting between checks.
No restart, scheduler change, migration, or production DB access was performed
by this coding task.

The migration utility requires explicit acknowledgement that scheduling is
quiesced, acquires the new kernel lock, and checks `/bin/ps` for active Scout
Python service polls and shell wrappers. It fails closed on a failed process
inspection, contention, symlinks, non-directory legacy locks, or nonempty
directories. It never kills processes or recursively deletes files. Only after
these checks does it remove the empty legacy directory and emit
`LEGACY_STALE_LOCK_RECOVERED`. That output is the migration audit marker.
The new polling wrapper does not consult or remove the legacy directory.

With launches quiesced, run:

```sh
/Users/greg/Dev/flop_scout_v02/.venv/bin/python /Users/greg/Dev/flop_scout_v02/scripts/scout-recover-legacy-lock.py --state-dir /Users/greg/.flop_scout --scheduler-quiesced
/usr/bin/install -m 755 /Users/greg/Dev/flop_scout_v02/scripts/scout-service-poll.sh /Users/greg/.flop_scout/run/scout-service-poll.sh
```

The wrapper defaults to absolute production paths and permits explicit
`FLOP_SCOUT_REPO` and `FLOP_SCOUT_STATE_DIR` overrides for isolated testing. The
existing scheduled job must point to the installed wrapper. Schema version 2 is
added transactionally on the next authorized writer connection; version-1 raw
migration is not repeated. Read-only commands never migrate the database.

## Upstream retention provenance

Protocol comparison (2026-09-06):

- https://github.com/flop-labs/technocore-chat
- https://technocore.chat/llms.txt
- https://technocore.chat/auth.md
- https://technocore.chat/patterns.md

The room ring exposes its retained lower boundary as `first_seq`. Previously,
Scout saved available records then repeatedly rejected this boundary and kept
its old cursor. Detection now requires explicit valid `first_seq` metadata past
the nonzero durable resume point plus one, an identified generation, and no
conflicting body/header generation. A retained boundary without an identified
generation fails safely with the cursor unchanged while retaining available raw
evidence. Sequence holes in messages never trigger a
gap. The existing generation-change/reset path remains separate. No missing
message counts or identities are inferred, and no discovered URLs are fetched.

`evidence_source_gaps` holds a SHA-256 deterministic ID over source, room,
generation, old durable position, authoritative first available position and
`UPSTREAM_RETENTION_GAP`. It also holds the endpoint, server latest position,
detection/creation timestamps, reason, metadata, recovery state/time and the
first recovered raw ID/hash. Original fields are immutable; only one transition
from UNRESOLVED to RECOVERED is permitted. Foreign keys bind recovery to actual
raw evidence. Repeated detection keeps the original row and timestamps; a new
boundary or generation can identify a materially different gap.

The ordered commit boundaries are:

1. Commit the gap before attempting page ingestion.
2. Commit the complete raw page through existing deterministic raw identities.
3. Commit normal derived events and watch memberships; finish compatibility
   indexing. A parser exception retains raw evidence and leaves the cursor old.
4. Verify every page member has an exact raw record and matching derived link.
5. Commit recovery references for unresolved gaps at that resume point.
6. Commit the cursor to the highest available sequence actually persisted.

A crash leaves the old cursor with safely replayable evidence, or an advanced
cursor whose evidence is durable. Recovery status means available evidence was
persisted; it may precede cursor movement if the process crashes between steps
5 and 6. A retry reuses raw identities, repairs missing derivations and resumes.
Signature failures and malformed records remain evidence, never invented parsed
messages. Numeric server/latest metadata alone never advances a cursor.

The recovery cycle reports `RETENTION_GAP_RECOVERED` or
`CATCHING_UP_AFTER_GAP`. Subsequent normal cycles can report `CURRENT` while
`known_retention_gaps` remains visible. Failed reads/storage/recovery still count
as failures; successful gap recovery does not increment `read_failures`.

## Reports and integrity

Status and soak-status expose `retention_gaps_detected`,
`retention_gaps_recovered`, `unresolved_retention_gaps`,
`retention_gaps_during_soak`, `poll_lock_contention_skips`, source/room/generation
counts, and separate typed `flop-scout-source-gap/v1` provenance records. Existing
soak bookkeeping starts at the first recorded poll cycle; there is no distinct
formal-soak marker, so the output explicitly states that metric's scope.

Daily JSON includes `upstream_retention_gaps` with the title UPSTREAM RETENTION
GAPS, detected/recovered today (UTC), unresolved count and relevant source rows,
including prior durable and first available positions. It never computes a
missing-message count from sequence subtraction. No fake `observed_events` or
`raw_network_records` are inserted for missing history; the signed-message feed
and its foreign keys remain intact.

`evidence verify-integrity` additionally checks deterministic gap identities and
recovery reference existence/hash/source/room/generation/position/completeness.
Older databases without recorded gaps remain readable and are not required to
invent historical gap records.

## Reproducible temporary validation

Use an interpreter with cryptography and pytest, and a temporary state directory:

```sh
export FLOP_SCOUT_STATE_DIR="$(mktemp -d /tmp/scout-validation.XXXXXX)"
python -m pytest -q
python flop_scout.py self-test
python -m py_compile flop_scout.py scout_evidence.py
git diff --check
```

`test_poll_recovery.py` exercises the production cursor 4507918, retained page
4991500–4991699, catch-up to 4991710, and CURRENT with one known gap. Subprocess
tests kill/crash lock holders, verify losing workers do no DB/network work, and
immediately reacquire without deleting files. Separate process crashes after gap
insert, raw insert and recovery commit verify safe replay and integrity.
