#!/bin/zsh
set -u
REPO="${FLOP_SCOUT_REPO:-/Users/greg/Dev/flop_scout_v02}"
PY="$REPO/.venv/bin/python"
SCOUT="$REPO/flop_scout.py"
STATE="${FLOP_SCOUT_STATE_DIR:-/Users/greg/.flop_scout}"
LOG="$STATE/logs/service-poll.log"
mkdir -p "$STATE/logs" || exit 1
printf '\n%s START\n' "$(date -u +%FT%TZ)" >> "$LOG"
if cd "$REPO"; then
    "$PY" "$SCOUT" service-poll >> "$LOG" 2>&1
    RC=$?
else
    RC=1
fi
printf '%s END rc=%s\n' "$(date -u +%FT%TZ)" "$RC" >> "$LOG"
exit "$RC"
