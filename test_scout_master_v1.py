import json
import sqlite3
import unittest
from pathlib import Path

import scout_adaptive as adaptive
import scout_contactability as contact
from scout_contest_monitor import ContestMonitor, ReadOnlyBoundaryError


class ScoutMasterV1Tests(unittest.TestCase):
    def test_mailbox_statuses_and_history(self):
        self.assertEqual(contact.classify('mb-good_1'), contact.MAILBOX_VALID)
        self.assertEqual(contact.classify('Mb-Good'), contact.MAILBOX_INVALID_NAME)
        self.assertEqual(contact.classify(None), contact.MAILBOX_MISSING)
        db = sqlite3.connect(':memory:'); db.row_factory = sqlite3.Row
        contact.install_schema(db)
        contact.observe(db, 'did:key:ztest', 'mb-good', note_provenance='note-a', observed_at='2026-01-01T00:00:00+00:00')
        contact.observe(db, 'did:key:ztest', 'BadValue', note_provenance='note-b', observed_at='2026-01-02T00:00:00+00:00')
        self.assertEqual(db.execute('select count(*) from mailbox_observations').fetchone()[0], 2)
        self.assertEqual(contact.latest(db, 'did:key:ztest')['mailbox_status'], contact.MAILBOX_INVALID_NAME)
        with self.assertRaises(ValueError): contact.guard_self_publication('BadValue')

    def test_saturation_and_burst_promote(self):
        follower = adaptive.RoomFollower(current_poll_interval=60)
        self.assertEqual(follower.observe(cursor=0, newest_seq=1, records=1, maximum_window=200,
            elapsed=60, base_interval=60, stamp='now'), None)
        before = follower.current_poll_interval
        self.assertEqual(follower.observe(cursor=1, newest_seq=201, records=200, maximum_window=200,
            elapsed=1, base_interval=60, stamp='now'), adaptive.POLL_WINDOW_SATURATED)
        self.assertTrue(follower.following)
        self.assertLess(follower.current_poll_interval, before)

    def test_monitor_is_read_only_and_not_authoritative(self):
        monitor = ContestMonitor('did:key:zscout', 'request-1', 'did:key:zreferee')
        observed = monitor.observe({'did': 'did:key:zforged', 'text': 'registration request-1 did:key:zscout'})
        self.assertFalse(observed['authoritative'])
        self.assertEqual(monitor.missing_receipt_state()['state'], 'PENDING_OR_UNKNOWN')
        with self.assertRaises(ReadOnlyBoundaryError): monitor.write()

    def test_router_contactability_fixture(self):
        path = Path(__file__).parent / 'tests' / 'fixtures' / 'scout-contactability-router-v1.json'
        self.assertEqual(json.loads(path.read_text())['mapping'], contact.ROUTER_CONTACTABILITY)


if __name__ == '__main__': unittest.main()
