"""Read-only adapter for normalized planner records; no default source path."""
import sqlite3
from scout_epoch_planner import PlanError

def records_from_current_source(path, limit=50000):
    if not path.is_absolute() or type(limit) is not int or not 1<=limit<=50000: raise PlanError('PLAN_ADAPTER_INPUT','explicit path and bounded limit required')
    conn=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True); conn.row_factory=sqlite3.Row
    try:
        conn.execute('PRAGMA query_only=ON')
        tables={r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'raw_network_records','observed_events'}<=tables: raise PlanError('PLAN_ADAPTER_SCHEMA','current-source schema is incomplete')
        rows=conn.execute('SELECT e.event_id,r.raw_record_id,r.raw_text_sha256,r.room,r.generation FROM observed_events e JOIN raw_network_records r ON r.raw_record_id=e.raw_record_id ORDER BY e.event_id DESC LIMIT ?', (limit,)).fetchall()
        return [dict(record_id=r['raw_record_id'],content_sha256=r['raw_text_sha256'],source_position=r['event_id'],room=r['room'],generation=r['generation'] or 'UNKNOWN_LEGACY',domain='messages',observation_class='UNRESOLVED',recency=r['event_id'],mandatory_reasons=['UNRESOLVED_DEPENDENCIES'],dependencies=[],archive_required=True,retained_floor=None) for r in rows]
    finally: conn.close()
