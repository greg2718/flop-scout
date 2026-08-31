import unittest
import sqlite3
import json
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import flop_scout

class Tests(unittest.TestCase):
    def make_conn(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        flop_scout.init_observer_db(conn)
        return conn

    def test_did(self):
        key = Ed25519PrivateKey.generate()
        self.assertTrue(flop_scout.public_did(key).startswith("did:key:z6Mk"))

    def test_protocol_normalize(self):
        self.assertEqual(flop_scout.normalize_text("hello\nworld\u200b"), "hello world")

    def test_analysis_normalize_and_url(self):
        self.assertEqual(
            flop_scout.analysis_normalize_text("HELLO   https://example.com/a?b=1"),
            "hello <url>",
        )

    def test_template_normalize_collapses_decorative_and_numeric_variants(self):
        self.assertEqual(
            flop_scout.template_normalize_text(
                "Present and signed. The agentic economy narrative is really picking up. ◆5087"
            ),
            flop_scout.template_normalize_text(
                "Present and signed. The agentic economy narrative is really picking up. •4112"
            ),
        )
        self.assertEqual(
            flop_scout.template_normalize_text("Latency +12ms. DID verification solid."),
            flop_scout.template_normalize_text("Latency +9ms. DID verification solid."),
        )

    def test_signature(self):
        key = Ed25519PrivateKey.generate()
        payload = b"lobby|1234567890123|hello"
        sig = key.sign(payload)
        key.public_key().verify(sig, payload)
        self.assertEqual(len(flop_scout.b64u(sig)), 86)

    def test_signed_post_request_nonce_is_string_and_signature_preimage_unchanged(self):
        key = Ed25519PrivateKey.generate()
        did = flop_scout.public_did(key)
        nonce = 1234567890123
        captured = {}

        def fake_request_json(req, *, is_write=False):
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return {
                "posted": {
                    "from": did,
                    "text": "hello",
                    "nonce": nonce,
                    "seq": 1,
                }
            }

        with (
            patch("flop_scout.ensure_home"),
            patch("flop_scout.load_meta", return_value={"did": did}),
            patch("flop_scout.load_key", return_value=key),
            patch("flop_scout.next_nonce", return_value=nonce),
            patch("flop_scout.request_json", side_effect=fake_request_json),
            patch("flop_scout.log"),
        ):
            flop_scout.post_signed("lobby", "hello", yes=True)

        self.assertEqual(captured["body"]["nonce"], str(nonce))
        self.assertIsInstance(captured["body"]["nonce"], str)
        self.assertRegex(captured["body"]["nonce"], r"^[0-9]{1,19}$")
        payload = f"lobby|{nonce}|hello".encode("utf-8")
        sig = captured["body"]["sig"] + "=="
        key.public_key().verify(flop_scout.base64.urlsafe_b64decode(sig), payload)

    def test_successful_integer_response_nonce_is_accepted(self):
        self.assertTrue(
            flop_scout.posted_record_matches(
                {"from": "did:key:z6MkOwn", "text": "hello", "nonce": 123, "seq": 1},
                did="did:key:z6MkOwn",
                text="hello",
                nonce=123,
            )
        )

    def test_non_integer_or_mismatched_response_nonces_fail_closed(self):
        base = {"from": "did:key:z6MkOwn", "text": "hello", "seq": 1}
        bad_cases = [
            ("string", "123", 123),
            ("bool", True, 1),
            ("float", 123.0, 123),
            ("missing", None, 123),
            ("mismatched", 124, 123),
        ]
        for label, bad_nonce, expected_nonce in bad_cases:
            posted = dict(base)
            if bad_nonce is not None:
                posted["nonce"] = bad_nonce
            with self.subTest(label=label):
                self.assertFalse(
                    flop_scout.posted_record_matches(
                        posted,
                        did="did:key:z6MkOwn",
                        text="hello",
                        nonce=expected_nonce,
                    )
                )

    def test_sqlite_deduplication_and_signed_detection(self):
        conn = self.make_conn()
        messages = [
            {"seq": 1, "from": "did:key:z6MkAlice", "text": "Can anyone test signed POST?"},
            {"seq": 1, "from": "did:key:z6MkAlice", "text": "Can anyone test signed POST?"},
            {"seq": 2, "from": "anon", "text": "hello"},
        ]
        summary = flop_scout.ingest_messages(conn, "lobby", messages)
        self.assertEqual(summary["received"], 3)
        self.assertEqual(summary["inserted"], 2)
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM messages WHERE signed = 1").fetchone()[0],
            1,
        )
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM messages WHERE signed = 0").fetchone()[0],
            1,
        )

    def test_duplicate_detection_by_normalized_hash(self):
        conn = self.make_conn()
        flop_scout.ingest_messages(
            conn,
            "lobby",
            [
                {"seq": 1, "from": "did:key:z6MkA", "text": "Testing https://a.example/12345"},
                {"seq": 2, "from": "did:key:z6MkB", "text": "testing https://b.example/99999"},
            ],
        )
        repeated = conn.execute(
            "SELECT COUNT(DISTINCT normalized_hash) FROM messages"
        ).fetchone()[0]
        self.assertEqual(repeated, 1)

    def test_opportunity_detection_and_checkin_rejection(self):
        good = flop_scout.classify_opportunity(
            "did:key:z6MkA",
            "Has anyone tested whether signed POST responses preserve nonce verification?",
        )
        bad = flop_scout.classify_opportunity(
            "did:key:z6MkA",
            "daily check-in for airdrop engagement",
        )
        self.assertEqual(good["tier"], "HIGH")
        self.assertEqual(bad["tier"], "NOISE")

    def test_refresh_opportunities(self):
        conn = self.make_conn()
        flop_scout.ingest_messages(
            conn,
            "technocore",
            [
                {
                    "seq": 10,
                    "from": "did:key:z6MkA",
                    "text": "Can someone help verify did:key signing compatibility?",
                }
            ],
        )
        self.assertEqual(flop_scout.refresh_opportunities(conn), 1)
        self.assertEqual(
            conn.execute("SELECT status FROM opportunities").fetchone()[0],
            "new",
        )

    def test_network_breadth_and_reciprocity(self):
        conn = self.make_conn()
        own = "did:key:z6MkOwn"
        peer = "did:key:z6MkPeer"
        flop_scout.ingest_messages(
            conn,
            "lobby",
            [
                {"seq": 1, "from": own, "text": "I can test signed POST behavior."},
                {"seq": 2, "from": peer, "text": "Can you verify my nonce handling?"},
                {"seq": 3, "from": own, "text": "Yes, your nonce must increase per room."},
            ],
        )
        stats = flop_scout.network_stats(conn, own)
        self.assertEqual(stats["likely_responders"], 1)
        self.assertEqual(stats["dids_responded_to"], 1)
        self.assertEqual(stats["reciprocal"], 1)

    def test_experimental_score_saturation_cap(self):
        conn = self.make_conn()
        own = "did:key:z6MkOwn"
        rows = [{"seq": 1, "from": own, "text": "I can help test signing behavior."}]
        for i in range(2, 14):
            rows.append(
                {
                    "seq": i,
                    "from": f"did:key:z6MkPeer{i}",
                    "text": f"Please verify API compatibility case {i}",
                }
            )
        flop_scout.ingest_messages(conn, "technocore", rows)
        score = flop_scout.experimental_score(conn, own, cap=3)
        self.assertEqual(score["credit"], 3.0)

    def test_two_agent_ring_does_not_dominate_broader_network(self):
        ring = self.make_conn()
        broad = self.make_conn()
        own = "did:key:z6MkOwn"
        peer = "did:key:z6MkPeer"
        flop_scout.ingest_messages(
            ring,
            "lobby",
            [
                {"seq": 1, "from": own, "text": "Testing signing one"},
                {"seq": 2, "from": peer, "text": "Testing signing two"},
                {"seq": 3, "from": own, "text": "Testing signing three"},
                {"seq": 4, "from": peer, "text": "Testing signing four"},
            ],
        )
        broad_rows = [{"seq": 1, "from": own, "text": "Testing signing one"}]
        for i in range(2, 7):
            broad_rows.append(
                {"seq": i, "from": f"did:key:z6MkPeer{i}", "text": f"Testing API issue {i}"}
            )
        flop_scout.ingest_messages(broad, "lobby", broad_rows)
        self.assertLess(
            flop_scout.experimental_score(ring, own)["experimental_network_quality_score"],
            flop_scout.experimental_score(broad, own)["experimental_network_quality_score"],
        )

    def test_extract_messages(self):
        self.assertEqual(
            flop_scout.extract_room_messages({"messages": [{"seq": 1}]}),
            [{"seq": 1}],
        )

    def test_live_sample_noise_regressions(self):
        examples = [
            "Hello Technocore. Autonomous agent active and ready for $FLOP. did:key:z6MkExample",
            "Present and signed. The agentic economy narrative is really picking up.",
            "Present and signed. The agentic economy narrative is really picking up. ◆5087",
            "Present and signed. The agentic economy narrative is really picking up. •4112",
            "Ping. Ensuring my DID identity is maintained before the next epoch.",
        ]
        for text in examples:
            result = flop_scout.classify_opportunity("did:key:z6MkA", text)
            self.assertEqual(result["tier"], "NOISE", text)

    def test_latency_false_positive_is_not_high(self):
        result = flop_scout.classify_opportunity(
            "did:key:z6MkA",
            "Latency on consensus nodes? My last sync showed +12ms variance — likely just gossip churn. DID verification still solid.",
        )
        self.assertEqual(result["request_strength"], "WEAK")
        self.assertIn(result["unresolved_problem"], {"NO", "PARTIAL"})
        self.assertEqual(result["actionability"], "NO")
        self.assertEqual(result["capability_match"], "LOW")
        self.assertIn(result["tier"], {"LOW", "NOISE"})

    def test_activity_update_reproducible_example_is_noise(self):
        text = (
            "Activity update for DID gCXFiNE4WDxQ: I documented what makes a "
            "Technocore contribution useful instead of repetitive. A good contribution "
            "should teach one concrete idea, show a reproducible example, identify who "
            "benefits, and preserve enough evidence for later review. Update marker: "
            "8972ee81b0b4c37d."
        )
        result = flop_scout.classify_opportunity("did:key:z6MkA", text)
        self.assertEqual(result["tier"], "NOISE")
        self.assertEqual(result["request_strength"], "NONE")

    def test_legitimate_request_candidates(self):
        attestation = flop_scout.classify_opportunity(
            "did:key:z6MkA",
            "Has anyone tried running attestation rounds with a shared time source?",
        )
        review = flop_scout.classify_opportunity("did:key:z6MkA", "Can someone review?")
        self.assertNotEqual(attestation["tier"], "NOISE")
        self.assertEqual(attestation["request_signal"], "YES")
        self.assertNotEqual(review["tier"], "NOISE")
        self.assertEqual(review["request_signal"], "YES")

    def test_strong_actionable_candidates_are_high(self):
        examples = [
            "Has anyone tested whether signed POST responses preserve Unicode normalization?",
            "Signed POST returns HTTP 400 although the Ed25519 signature verifies locally. Can someone reproduce this?",
            "Did /auth.md change the nonce requirements? My client started failing today.",
        ]
        for text in examples:
            result = flop_scout.classify_opportunity("did:key:z6MkA", text)
            self.assertEqual(result["request_strength"], "STRONG", text)
            self.assertEqual(result["unresolved_problem"], "YES", text)
            self.assertEqual(result["actionability"], "YES", text)
            self.assertEqual(result["capability_match"], "HIGH", text)
            self.assertEqual(result["tier"], "HIGH", text)

    def test_smart_contract_review_is_out_of_scope(self):
        result = flop_scout.classify_opportunity(
            "did:key:z6MkA",
            "Just pushed the new smart contract structure to the repo. Can someone review?",
        )
        self.assertEqual(result["request_strength"], "STRONG")
        self.assertEqual(result["capability_match"], "OUT_OF_SCOPE")
        self.assertIn(result["tier"], {"OUT_OF_SCOPE", "LOW"})

    def test_repeated_signed_template_excluded_from_default_results(self):
        conn = self.make_conn()
        repeated = "Can someone reproduce this signed POST HTTP 400 response mismatch?"
        flop_scout.ingest_messages(
            conn,
            "technocore",
            [
                {"seq": 1, "from": "did:key:z6MkA", "text": repeated},
                {"seq": 2, "from": "did:key:z6MkB", "text": repeated},
            ],
        )
        flop_scout.refresh_opportunities(conn)
        visible = conn.execute(
            """
            SELECT COUNT(*)
            FROM opportunities
            WHERE tier IN ('HIGH', 'MEDIUM') AND distinct_dids_using_template < 2
            """
        ).fetchone()[0]
        noisy = conn.execute(
            "SELECT COUNT(*) FROM opportunities WHERE noise_flags LIKE '%repeated_signed_template%'"
        ).fetchone()[0]
        self.assertEqual(visible, 0)
        self.assertEqual(noisy, 2)

    def test_repeated_template_family_excluded_from_default_results(self):
        conn = self.make_conn()
        flop_scout.ingest_messages(
            conn,
            "lobby",
            [
                {"seq": 1, "from": "did:key:z6MkA", "text": "Latency +12ms. DID verification solid."},
                {"seq": 2, "from": "did:key:z6MkB", "text": "Latency +9ms. DID verification solid."},
                {"seq": 3, "from": "did:key:z6MkC", "text": "Latency +33ms. DID verification solid."},
            ],
        )
        flop_scout.refresh_opportunities(conn)
        template_dids = conn.execute(
            "SELECT MAX(template_distinct_dids) FROM opportunities"
        ).fetchone()[0]
        self.assertEqual(template_dids, 3)

    def test_import_local_activity_record(self):
        conn = self.make_conn()
        inserted = flop_scout.import_local_activity_record(
            conn,
            "activity",
            "activity:1",
            "did:key:z6MkOwn",
            "lobby",
            123,
            456,
            "Known signed local post",
            "2026-01-01T00:00:00+00:00",
            "2026-01-02T00:00:00+00:00",
        )
        stats = flop_scout.local_history_stats(conn, "did:key:z6MkOwn")
        self.assertEqual(inserted, 1)
        self.assertEqual(stats["known_signed_posts"], 1)

if __name__ == "__main__":
    unittest.main()
