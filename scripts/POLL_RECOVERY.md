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

## Coverage correction supersedes the v2 retention model

The former claim that room-read `first_seq` is the retained lower boundary was
incorrect. It is the first record of a capped newest-record window. Schema v3
uses a separate coverage cursor, export-backed backfill, confirmed loss records,
and append-only reassessments. See [COVERAGE_WORKER.md](COVERAGE_WORKER.md).

The lock architecture and legacy migration instructions above remain applicable.
The new long-running worker and manual service-poll share that same kernel lock.
