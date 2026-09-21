import copy
import json
from pathlib import Path

import pytest

import scout_epoch_v2 as e


FIXTURE = Path(__file__).parent / "docs/fixtures/scout-router-epoch-rollover-v2-conformance.json"


def h(char):
    return char * 64


def _legacy_transition():
    predecessor = {"publication_id": 900, "content_id": 800,
                   "manifest_sha256": h("a"), "artifact_sha256": h("b"),
                   "artifact_size_bytes": 42, "epoch_id": "v1:predecessor",
                   "epoch_number": 0,
                   "source_cut": {"source_id": "scout-source", "epoch": "source-epoch",
                                  "committed_event_id": 7, "cut_evidence_sha256": h("c")},
                   "accepted_state_hash": h("d")}
    archive = {"schema": "flop-scout-epoch-archive/v1", "archive_id": "ea2:archive",
               "artifact_sha256": h("e"), "size_bytes": 42,
               "database_schema_version": "scout-observer/v1", "locator": "archives/epoch-0.sqlite",
               "previous_epoch_id": "v1:predecessor", "previous_manifest_sha256": h("a"),
               "preservation": "IMMUTABLE_RETAINED"}
    archive["archive_commitment_sha256"] = e.commitment("archive-descriptor", archive)
    floors = {"entries": [{"room": "room-a", "generation": "1", "domain": "messages",
                            "retained_floor": 4, "omitted_ranges": [[1, 3]]}],
              "selection_policy_version": "epoch-v2-policy/1",
              "mandatory_proof_closure": ["proof-a"],
              "durable_qualification_history": ["qualification-a"],
              "coverage_witnesses": ["coverage-a"],
              "permanent_pinned_evidence": ["pin-a"], "omitted_history": ["row-a"]}
    items = (("mandatory_proof_closure", "mandatory_proof_closure_sha256", "mandatory-closure"),
             ("durable_qualification_history", "durable_qualification_history_sha256", "durable-qualification-history"),
             ("coverage_witnesses", "coverage_witnesses_sha256", "coverage-witnesses"),
             ("permanent_pinned_evidence", "permanent_pinned_evidence_sha256", "permanent-pinned-evidence"),
             ("omitted_history", "omitted_history_sha256", "omitted-history"))
    for body, digest, domain in items:
        floors[digest] = e.commitment(domain, floors[body])
    floors["retained_floor_commitment_sha256"] = e.commitment("retained-floor-declaration", floors)
    value = {"schema": e.SCHEMA, "contract_revision": e.REVISION, "epoch_number": 1,
             "epoch_id": "se2:epoch-one", "created_at": "2026-01-01T00:00:00Z",
             "source_binding": {"source_id": "scout-source", "epoch": "source-epoch", "descriptor_sha256": h("f")},
             "source_cut": {"source_id": "scout-source", "epoch": "source-epoch", "committed_event_id": 8, "cut_evidence_sha256": h("0")},
             "predecessor": predecessor, "archive": archive, "retained_floor_commitment": floors,
             "active_epoch": {"target": 40000, "headroom": 9000, "reserve": 1000,
                              "hard_max": 50000, "mandatory_closure_count": 12000}}
    value["commitments"] = {
        "predecessor_sha256": e.commitment("predecessor", predecessor),
        "archive_descriptor_sha256": e.commitment("archive-descriptor", {k: v for k, v in archive.items() if k != "archive_commitment_sha256"}),
        "retained_floor_declaration_sha256": e.commitment("retained-floor-declaration", {k: v for k, v in floors.items() if k != "retained_floor_commitment_sha256"}),
        "mandatory_closure_sha256": floors["mandatory_proof_closure_sha256"],
        "durable_qualification_history_sha256": floors["durable_qualification_history_sha256"],
        "coverage_witnesses_sha256": floors["coverage_witnesses_sha256"],
        "permanent_pinned_evidence_sha256": floors["permanent_pinned_evidence_sha256"]}
    complete = copy.deepcopy(value)
    value["commitments"]["transition_sha256"] = e.commitment("complete-transition", complete)
    return value


def make_transition():
    old = _legacy_transition(); predecessor = old.pop("predecessor")
    anchor = {"publication_sequence": predecessor["publication_id"], "content_id": predecessor["content_id"],
              "manifest_sha256": predecessor["manifest_sha256"], "artifact_sha256": predecessor["artifact_sha256"],
              "artifact_size": predecessor["artifact_size_bytes"], "source_kind": predecessor["source_cut"]["epoch"],
              "source_id": predecessor["source_cut"]["source_id"], "source_cut": predecessor["source_cut"]["committed_event_id"]}
    bridge = copy.deepcopy(anchor)
    old["accepted_anchor"] = anchor
    old["bridge_predecessor"] = bridge
    old["bridge_binding_sha256"] = e.commitment("a1-bridge-binding", {"accepted_anchor": anchor, "bridge_predecessor": bridge})
    old["archive"]["previous_manifest_sha256"] = bridge["manifest_sha256"]
    old["archive"]["previous_bridge_binding_sha256"] = old["bridge_binding_sha256"]
    old["archive"]["archive_commitment_sha256"] = e.commitment("archive-descriptor", {k:v for k,v in old["archive"].items() if k != "archive_commitment_sha256"})
    old["commitments"] = {"accepted_anchor_sha256": e.commitment("accepted-anchor", anchor),
        "bridge_predecessor_sha256": e.commitment("bridge-predecessor", bridge),
        "bridge_binding_sha256": old["bridge_binding_sha256"],
        "archive_descriptor_sha256": e.commitment("archive-descriptor", {k:v for k,v in old["archive"].items() if k != "archive_commitment_sha256"}),
        "retained_floor_declaration_sha256": old["retained_floor_commitment"]["retained_floor_commitment_sha256"],
        "mandatory_closure_sha256": old["retained_floor_commitment"]["mandatory_proof_closure_sha256"],
        "durable_qualification_history_sha256": old["retained_floor_commitment"]["durable_qualification_history_sha256"],
        "coverage_witnesses_sha256": old["retained_floor_commitment"]["coverage_witnesses_sha256"],
        "permanent_pinned_evidence_sha256": old["retained_floor_commitment"]["permanent_pinned_evidence_sha256"]}
    old["commitments"]["transition_sha256"] = e.commitment("complete-transition", {**{k:v for k,v in old.items() if k != "commitments"}, "commitments": old["commitments"]})
    return old


def code(call):
    with pytest.raises(e.V2ValidationError) as caught:
        call()
    return caught.value.code


def apply_case(value, name):
    if name == "none":
        return
    if name == "epoch-zero":
        value["epoch_number"] = 0
    elif name == "first-source-change":
        value["source_binding"]["source_id"] = "other-source"
        value["source_cut"]["source_id"] = "other-source"
    elif name == "predecessor-mismatch":
        value["accepted_anchor"]["content_id"] = 1
    elif name == "source-cut-rollback":
        value["source_cut"]["committed_event_id"] = 6
    elif name == "forged-floor":
        value["retained_floor_commitment"]["entries"][0]["retained_floor"] = 5
    elif name == "capacity-overflow":
        value["active_epoch"].update(target=45000, headroom=6000)
    else:
        raise AssertionError("unknown synthetic Slice 1 case")


def test_documented_conformance_vectors_are_available():
    vectors = json.loads(FIXTURE.read_text())["vectors"]
    names = {item["name"] for item in vectors}
    assert {"valid-direct", "valid-cumulative", "forged-bridge-binding",
            "wrong-archive-bridge-binding", "transition-hash-regression"} <= names


@pytest.mark.parametrize("case", json.loads(FIXTURE.read_text())["slice1_cases"], ids=lambda item: item["name"])
def test_slice1_cases_are_driven_by_documented_fixture(case):
    value = make_transition(); prior = copy.deepcopy(value["accepted_anchor"])
    apply_case(value, case["mutation"])
    if case["expect"] == "PASS":
        assert e.validate_transition(value, prior, 0, True)["epoch_number"] == 1
    else:
        assert code(lambda: e.validate_transition(value, prior, 0, True)) == case["expect"]


def test_valid_first_transition_and_deterministic_canonicalization():
    value = make_transition()
    assert e.validate_transition(value, copy.deepcopy(value["accepted_anchor"]), 0, True)["epoch_number"] == 1
    assert e.canonical_json({"b": 1, "a": [True, None]}) == e.canonical_json({"a": [True, None], "b": 1})


@pytest.mark.parametrize("raw, expected", [
    (b'{"x":1,"x":2}', "EPOCH_DUPLICATE_KEY"), (b'{"x":1.2}', "EPOCH_NUMBER"),
    (b'{"x":"\xff"}', "EPOCH_UTF8")])
def test_parser_rejects_ambiguous_or_invalid_json(raw, expected):
    assert code(lambda: e.parse_json(raw)) == expected


def test_parser_bounds_and_unknown_fields():
    assert code(lambda: e.parse_json(b"[" * 17 + b"0" + b"]" * 17)) == "EPOCH_NESTING"
    assert code(lambda: e.parse_json(b'{"x":"' + b"a" * 4097 + b'"}')) == "EPOCH_STRING_BOUNDS"
    assert code(lambda: e.parse_json(("[" + ",".join("0" for _ in range(257)) + "]").encode("ascii"))) == "EPOCH_LIST_BOUNDS"
    assert code(lambda: e.parse_json(json.dumps({str(i): 0 for i in range(65)}).encode("ascii"))) == "EPOCH_MAP_BOUNDS"
    value = make_transition(); value["unexpected"] = 1
    assert code(lambda: e.validate_transition(value, make_transition()["accepted_anchor"], 0, True)) == "EPOCH_FIELDS"


@pytest.mark.parametrize("mutate, expected", [
    (lambda x: x.update(epoch_number=0), "EPOCH_NUMBER"),
    (lambda x: (x["source_binding"].update(source_id="other-source"), x["source_cut"].update(source_id="other-source")), "EPOCH_SOURCE_BINDING"),
    (lambda x: x["accepted_anchor"].update(content_id=1), "EPOCH_ACCEPTED_ANCHOR"),
    (lambda x: x["source_cut"].update(committed_event_id=6), "EPOCH_SOURCE_CUT"),
    (lambda x: x["retained_floor_commitment"]["entries"][0].update(retained_floor=5), "EPOCH_RETAINED_FLOOR"),
    (lambda x: x["active_epoch"].update(target=45000, headroom=6000), "EPOCH_CAPACITY")])
def test_validation_failures_are_stable(mutate, expected):
    value = make_transition(); prior = copy.deepcopy(value["accepted_anchor"]); mutate(value)
    assert code(lambda: e.validate_transition(value, prior, 0, True)) == expected


def test_commitments_are_domain_separated_and_sensitive():
    assert e.commitment("a1-bridge-binding", {"x": 1}) != e.commitment("archive-descriptor", {"x": 1})
    assert e.commitment("a1-bridge-binding", {"x": 1}) != e.commitment("a1-bridge-binding", {"x": 2})
    assert code(lambda: e.commitment("Wrong", {})) == "EPOCH_DOMAIN"


def test_wrong_domain_commitment_fails_validation():
    value = make_transition(); prior = copy.deepcopy(value["accepted_anchor"])
    value["commitments"]["accepted_anchor_sha256"] = e.commitment("archive-descriptor", value["accepted_anchor"])
    assert code(lambda: e.validate_transition(value, prior, 0, True)) == "EPOCH_COMMITMENT"


def test_error_does_not_echo_untrusted_payload():
    value = "REMOTE_UNTRUSTED_PAYLOAD_MUST_NOT_ECHO" * 200
    with pytest.raises(e.V2ValidationError) as caught:
        e.parse_json(("{\"x\":\"%s\"}" % value).encode("ascii"))
    assert value not in str(caught.value)


@pytest.mark.parametrize("vector", json.loads(FIXTURE.read_text())["vectors"], ids=lambda x: x["name"])
def test_frozen_wire_vectors_execute_declared_outcome(vector):
    transition = vector["transition"]
    call = lambda: e.validate_transition(transition, vector["accepted_anchor"], vector["accepted_epoch_number"], vector["first_transition"])
    if vector["expect"] == "PASS":
        assert call()["epoch_number"] == 1
    else:
        assert code(call) == vector["expect"]


@pytest.mark.parametrize("field", ["bridge_valid", "bridge_mode", "validation_success", "verified_receipt", "router_private_state_hash"])
def test_producer_proof_claims_are_unknown_fields(field):
    value = make_transition(); value[field] = True
    assert code(lambda: e.validate_transition(value, value["accepted_anchor"], 0, True)) == "EPOCH_FIELDS"


def test_complete_bridge_binding_and_archive_bind_bridge_not_anchor():
    value = make_transition(); bridge = value["bridge_predecessor"]
    assert e.validate_transition(value, value["accepted_anchor"], 0, True)["epoch_number"] == 1
    value["archive"]["previous_bridge_binding_sha256"] = "0" * 64
    assert code(lambda: e.validate_transition(value, value["accepted_anchor"], 0, True)) == "EPOCH_ARCHIVE_HASH"
    assert bridge != {**bridge, "artifact_sha256": "0" * 64}


def test_cumulative_bridge_is_derived_from_complete_descriptor_inequality():
    value = make_transition(); value["bridge_predecessor"] = dict(value["bridge_predecessor"], publication_sequence=901, content_id=801, source_cut=8)
    value["bridge_binding_sha256"] = e.commitment("a1-bridge-binding", {"accepted_anchor": value["accepted_anchor"], "bridge_predecessor": value["bridge_predecessor"]})
    value["archive"]["previous_manifest_sha256"] = value["bridge_predecessor"]["manifest_sha256"]
    value["archive"]["previous_bridge_binding_sha256"] = value["bridge_binding_sha256"]
    value["archive"]["archive_commitment_sha256"] = e.commitment("archive-descriptor", {k:v for k,v in value["archive"].items() if k != "archive_commitment_sha256"})
    value["commitments"]["bridge_predecessor_sha256"] = e.commitment("bridge-predecessor", value["bridge_predecessor"])
    value["commitments"]["bridge_binding_sha256"] = value["bridge_binding_sha256"]
    value["commitments"]["archive_descriptor_sha256"] = e.commitment("archive-descriptor", {k:v for k,v in value["archive"].items() if k != "archive_commitment_sha256"})
    value["commitments"]["transition_sha256"] = e.commitment("complete-transition", {**{k:v for k,v in value.items() if k != "commitments"}, "commitments": {k:v for k,v in value["commitments"].items() if k != "transition_sha256"}})
    assert e.validate_transition(value, value["accepted_anchor"], 0, True)["epoch_number"] == 1
