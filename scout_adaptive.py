"""Bounded, measured adaptive coverage scheduling (no protocol-rate constants)."""
from __future__ import annotations
from dataclasses import dataclass, asdict

POLL_WINDOW_SATURATED = 'POLL_WINDOW_SATURATED'

@dataclass
class RoomFollower:
    current_cursor: int = 0
    latest_observed_seq: int = 0
    recent_sequence_velocity: float = 0.0
    recent_peak_velocity: float = 0.0
    current_poll_interval: float = 60.0
    response_count: int = 0
    saturated_response_count: int = 0
    gap_count: int = 0
    unread_record_estimate: float = 0.0
    buffered_messages: int = 0
    last_successful_poll: str | None = None
    last_error: str | None = None
    following: bool = False

    def observe(self, *, cursor, newest_seq, records, maximum_window, elapsed, base_interval, stamp, gap=False, error=None, target_utilization=.5):
        if maximum_window < 1 or not 0 < target_utilization <= 1:
            raise ValueError('Invalid adaptive coverage configuration')
        self.current_cursor = int(cursor)
        self.response_count += 1
        saturated = records == maximum_window
        if saturated: self.saturated_response_count += 1
        if gap: self.gap_count += 1
        delta = max(0, int(newest_seq or 0) - self.latest_observed_seq)
        rate = delta / max(float(elapsed), .001)
        # Decay old peaks, retain a burst long enough to catch its next window.
        self.recent_peak_velocity = max(rate, self.recent_peak_velocity * .75)
        self.recent_sequence_velocity = self.recent_sequence_velocity * .5 + rate * .5
        self.latest_observed_seq = max(self.latest_observed_seq, int(newest_seq or 0))
        self.unread_record_estimate = max(0.0, self.recent_peak_velocity * self.current_poll_interval - records)
        self.buffered_messages = int(records)
        self.last_error = str(error) if error else None
        if not error: self.last_successful_poll = stamp
        if gap or saturated: self.following = True
        capacity = maximum_window * target_utilization
        measured = capacity / max(self.recent_peak_velocity, .000001)
        # Saturation proves only an incomplete window and always shortens cadence.
        desired = min(base_interval, measured)
        if saturated: desired = min(desired, self.current_poll_interval * .5)
        self.current_poll_interval = max(.5, desired)
        return POLL_WINDOW_SATURATED if saturated else None

    def export(self): return asdict(self)

def choose_followers(states, budget):
    """Promote neediest rooms; demote by measured need, never lexical room order."""
    if budget < 0: raise ValueError('Follower budget cannot be negative')
    ranked = sorted(states.items(), key=lambda item: (item[1].gap_count > 0 or item[1].saturated_response_count > 0,
        item[1].unread_record_estimate, item[1].recent_peak_velocity), reverse=True)
    selected = {room for room, state in ranked[:budget] if state.following}
    for room, state in states.items(): state.following = room in selected
    return selected
