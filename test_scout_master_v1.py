import unittest

import scout_adaptive as adaptive


class ScoutMasterV1Tests(unittest.TestCase):
    def test_saturation_and_burst_promote(self):
        follower = adaptive.RoomFollower(current_poll_interval=60)
        self.assertEqual(follower.observe(cursor=0, newest_seq=1, records=1, maximum_window=200,
            elapsed=60, base_interval=60, stamp='now'), None)
        before = follower.current_poll_interval
        self.assertEqual(follower.observe(cursor=1, newest_seq=201, records=200, maximum_window=200,
            elapsed=1, base_interval=60, stamp='now'), adaptive.POLL_WINDOW_SATURATED)
        self.assertTrue(follower.following)
        self.assertLess(follower.current_poll_interval, before)
