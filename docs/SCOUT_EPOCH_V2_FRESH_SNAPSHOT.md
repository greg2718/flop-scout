# Scout Epoch-V2 fresh snapshot authority

`scout_epoch_fresh_snapshot.py` is an offline preparation command. It is not a
publisher, planner, artifact builder, installer, or Router command.

It accepts only explicit absolute paths and an operator-supplied source
identity/epoch, bridge binding, bridge cut, fixed timestamp, output budget, and
reserve. It opens the observer source only through SQLite URI `mode=ro`; it
never uses `immutable=1`, so committed WAL content participates in the backup.
It never opens the source writable.

The authoritative event cut, schema hash, row counts, and semantic checkpoint
are derived from the completed backup—not from a separate read of the live
source. The command then reopens the staged backup read-only, verifies it
again, fsyncs it, and atomically hard-links it into a previously nonexistent
output path. A source inode replacement, symlink, output collision, schema or
integrity failure, insufficient budget, or non-advancing cut fails closed.

The result is redacted JSON only: descriptor, checkpoint counts, authority
commitment, timing, and RSS. It does not include message text or raw evidence.

## Later isolated live-backup command — not executed

Replace every angle-bracketed value during a separately authorized maintenance
preflight. The output parent must be a private, same-filesystem directory with
at least the stated budget plus reserve available.

```sh
cd /Users/greg/Dev/flop_scout_capacity_design && \
/Users/greg/Dev/flop_scout_v02/.venv/bin/python -m scout_epoch_fresh_snapshot \
  --source <ABSOLUTE_LIVE_OBSERVER_SQLITE> \
  --output <ABSOLUTE_NONEXISTENT_ISOLATED_SNAPSHOT_SQLITE> \
  --source-id <BRIDGE_SOURCE_ID> \
  --source-epoch <BRIDGE_SOURCE_EPOCH> \
  --bridge-binding-sha256 <VERIFIED_BRIDGE_BINDING_SHA256> \
  --minimum-cut <VERIFIED_BRIDGE_CUT> \
  --created-at <FIXED_UTC_RFC3339_TIMESTAMP> \
  --disk-budget-bytes <EXPLICIT_MAX_SNAPSHOT_BYTES> \
  --reserve-bytes <EXPLICIT_REMAINING_FREE_BYTES>
```

The emitted descriptor and authority must be independently checked before any
fresh planner or publication work. This command alone does not authorize those
later operations.
