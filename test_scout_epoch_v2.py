import copy
import hashlib
import json
from pathlib import Path

import pytest

import scout_epoch_v2 as e
from scout_legacy_a1_recovery import validate_descriptor as validate_recovery_descriptor


FIXTURE = Path(__file__).parent / "docs/fixtures/scout-router-epoch-rollover-v2-conformance.json"
BUNDLE_FIXTURE = Path(__file__).parent / "docs/fixtures/scout-epoch-v2-publication-bundle-v1.json"
BUNDLE_FIXTURE_SHA256 = "d3dca144bacaad1f47a1b0ad5a7ee4ec2c35eaa60c946bcc282d5b5b607bb8a4"


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
              "selection_policy_version": "epoch-v2-policy/1"}
    items = (("mandatory_proof_closure", ["proof-a"], "mandatory-closure"),
             ("durable_qualification_history", ["qualification-a"], "durable-qualification-history"),
             ("coverage_witnesses", ["coverage-a"], "coverage-witnesses"),
             ("permanent_pinned_evidence", ["pin-a"], "permanent-pinned-evidence"),
             ("omitted_history", ["row-a"], "omitted-history"))
    for name, body, domain in items:
        floors[name + "_count"] = len(body)
        floors[name + "_sha256"] = e.bounded_commitment(domain, body)
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
    old["source_binding"] = e.first_transition_source_binding(bridge, old["bridge_binding_sha256"])
    old["source_cut"] = e.first_transition_source_cut(old["source_binding"], bridge, old["bridge_binding_sha256"])
    old["archive"]["previous_manifest_sha256"] = bridge["manifest_sha256"]
    old["archive"]["previous_bridge_binding_sha256"] = old["bridge_binding_sha256"]
    old["archive"]["archive_commitment_sha256"] = e.commitment("archive-descriptor", {k:v for k,v in old["archive"].items() if k != "archive_commitment_sha256"})
    old["active_artifact"] = {"schema": "scout-router-projection/v2", "content_id": 801,
        "locator": "router-projection-v2-801.sqlite", "artifact_sha256": h("1"), "size_bytes": 43,
        "database_schema_version": "scout-router-projection/v2"}
    old["active_set_plan"] = {"schema": "flop-scout-epoch-active-set-plan/v1",
        "locator": "epoch-active-set-v2-801.json", "sha256": h("2"), "size_bytes": 1024,
        "plan_commitment_sha256": h("3"), "recovery_commitment_sha256": h("4")}
    old["commitments"] = {"accepted_anchor_sha256": e.commitment("accepted-anchor", anchor),
        "bridge_predecessor_sha256": e.commitment("bridge-predecessor", bridge),
        "bridge_binding_sha256": old["bridge_binding_sha256"],
        "archive_descriptor_sha256": e.commitment("archive-descriptor", {k:v for k,v in old["archive"].items() if k != "archive_commitment_sha256"}),
        "active_artifact_descriptor_sha256": e.commitment("active-artifact-descriptor", old["active_artifact"]),
        "active_set_plan_descriptor_sha256": e.commitment("active-set-plan-descriptor", old["active_set_plan"]),
        "retained_floor_declaration_sha256": old["retained_floor_commitment"]["retained_floor_commitment_sha256"],
        "mandatory_closure_sha256": old["retained_floor_commitment"]["mandatory_proof_closure_sha256"],
        "durable_qualification_history_sha256": old["retained_floor_commitment"]["durable_qualification_history_sha256"],
        "coverage_witnesses_sha256": old["retained_floor_commitment"]["coverage_witnesses_sha256"],
        "permanent_pinned_evidence_sha256": old["retained_floor_commitment"]["permanent_pinned_evidence_sha256"]}
    old["epoch_id"] = e.derive_epoch_id(old)
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


def test_frozen_publication_bundle_fixture_hash_is_stable():
    assert hashlib.sha256(BUNDLE_FIXTURE.read_bytes()).hexdigest() == BUNDLE_FIXTURE_SHA256


def test_frozen_compact_candidate_identity_is_path_free_and_exact():
    value = json.loads(BUNDLE_FIXTURE.read_text())["compact_candidate_279_243"]
    assert value["transition_size_bytes"] == 5697
    assert value["counts"] == {"eligible": 49808, "mandatory_closure": 10427,
                               "selected": 43840, "omitted": 5968}
    assert all("/" not in item for item in value.values() if isinstance(item, str))


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


def test_build_first_transition_recomputes_every_wire_binding():
    value = make_transition()
    built = e.build_first_transition(value["accepted_anchor"], value["bridge_predecessor"],
                                     value["archive"], value["active_artifact"], value["active_set_plan"],
                                     value["retained_floor_commitment"], value["active_epoch"], value["created_at"])
    assert e.validate_transition(built, value["accepted_anchor"], 0, True)["epoch_number"] == 1
    assert built["epoch_id"] == value["epoch_id"]


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


def test_compact_retained_floor_binds_counts_and_reconstructable_sets():
    entries = [{"room": "room-a", "generation": "1", "domain": "messages",
                "retained_floor": 4, "omitted_ranges": [[1, 3]]}]
    sets = {"mandatory_proof_closure": ["proof-a"],
            "durable_qualification_history": ["qualification-a"],
            "coverage_witnesses": ["coverage-a"],
            "permanent_pinned_evidence": ["pin-a"],
            "omitted_history": ["row-a"]}
    compact = e.compact_retained_floor(entries, "epoch-v2-policy/1", sets)
    assert compact["mandatory_proof_closure_count"] == 1
    assert compact["mandatory_proof_closure_sha256"] == e.bounded_commitment("mandatory-closure", ["proof-a"])
    assert "mandatory_proof_closure" not in compact
    compact["omitted_history_count"] = 2
    assert code(lambda: e._floors(compact)) == "EPOCH_RETAINED_FLOOR"
    assert code(lambda: e.bounded_commitment("mandatory-closure", ["proof-b", "proof-a"])) == "EPOCH_FLOOR_ORDER"
    assert code(lambda: e.bounded_commitment("mandatory-closure", ["proof-a", "proof-a"])) == "EPOCH_FLOOR_ORDER"


@pytest.mark.parametrize("mutate", [
    lambda x: x["retained_floor_commitment"].update(mandatory_proof_closure_count=2),
    lambda x: x["retained_floor_commitment"].update(mandatory_proof_closure_sha256=h("0")),
    lambda x: x["retained_floor_commitment"].update(mandatory_proof_closure=["legacy"]),
    lambda x: x["retained_floor_commitment"].pop("omitted_history_count"),
    lambda x: x["retained_floor_commitment"].update(unexpected="x"),
])
def test_compact_retained_floor_rejects_summary_mismatch_and_obsolete_arrays(mutate):
    value = make_transition(); mutate(value)
    assert code(lambda: e.validate_transition(value, value["accepted_anchor"], 0, True)) in {
        "EPOCH_RETAINED_FLOOR", "EPOCH_FIELDS", "EPOCH_COMMITMENT"}


def test_first_transition_source_authority_derivations_are_exact_and_domain_separated():
    value = make_transition(); bridge = value["bridge_predecessor"]; binding = value["bridge_binding_sha256"]
    assert value["source_binding"] == e.first_transition_source_binding(bridge, binding)
    assert value["source_cut"] == e.first_transition_source_cut(value["source_binding"], bridge, binding)
    assert e.source_binding_descriptor(bridge, binding) != e.source_cut_evidence(value["source_binding"], bridge, binding)


def _legacy_bridge(bridge):
    return {"publication_id": str(bridge["publication_sequence"]), "content_id": str(bridge["content_id"]),
            "manifest_sha256": bridge["manifest_sha256"], "artifact_sha256": bridge["artifact_sha256"],
            "artifact_size": bridge["artifact_size"], "source_checkpoint": {"source_id": bridge["source_id"],
            "epoch": bridge["source_kind"], "committed_event_id": str(bridge["source_cut"])}}


def test_normalize_legacy_a1_bridge_descriptor_is_closed_and_exact():
    bridge = make_transition()["bridge_predecessor"]; legacy = _legacy_bridge(bridge)
    assert e.normalize_legacy_a1_bridge_descriptor(legacy, bridge["manifest_sha256"], bridge) == bridge
    assert code(lambda: e.validate_transition(legacy, bridge, 0, True)) == "EPOCH_FIELDS"


def test_legacy_a1_recovery_descriptor_from_normalized_is_exact_and_local_only():
    bridge = make_transition()["bridge_predecessor"]
    recovery = e.legacy_a1_bridge_descriptor_from_normalized(bridge)
    assert recovery == {
        "content_id": "800", "manifest_sha256": bridge["manifest_sha256"],
        "artifact_sha256": bridge["artifact_sha256"], "artifact_size": 42,
        "source_kind": "source-epoch", "source_id": "scout-source",
        "source_epoch": "source-epoch", "source_cut": 7,
    }
    assert validate_recovery_descriptor(recovery, recovery) == recovery
    assert code(lambda: e.validate_transition(recovery, bridge, 0, True)) == "EPOCH_FIELDS"


@pytest.mark.parametrize("mutate", [
    lambda x: x.update(unexpected="x"), lambda x: x.update(manifest_sha256="A" * 64),
    lambda x: x.update(artifact_sha256="a" * 63), lambda x: x.update(publication_sequence=True),
    lambda x: x.update(content_id=True), lambda x: x.update(artifact_size=True),
    lambda x: x.update(source_cut=True), lambda x: x.update(publication_sequence=0),
    lambda x: x.update(content_id=0), lambda x: x.update(artifact_size=0),
    lambda x: x.update(source_cut=-1), lambda x: x.update(source_cut=e.MAX_INT + 1),
    lambda x: x.update(publication_sequence="01"), lambda x: x.update(content_id="800"),
    lambda x: x.update(artifact_size="42"), lambda x: x.update(source_cut="7"),
])
def test_legacy_a1_recovery_descriptor_from_normalized_rejects_bad_bridge(mutate):
    bridge = make_transition()["bridge_predecessor"]
    mutate(bridge)
    assert code(lambda: e.legacy_a1_bridge_descriptor_from_normalized(bridge)) == "EPOCH_LEGACY_BRIDGE_DESCRIPTOR"


@pytest.mark.parametrize("field", e.DESCRIPTOR)
def test_legacy_a1_recovery_descriptor_from_normalized_requires_every_normalized_field(field):
    bridge = make_transition()["bridge_predecessor"]
    bridge.pop(field)
    assert code(lambda: e.legacy_a1_bridge_descriptor_from_normalized(bridge)) == "EPOCH_LEGACY_BRIDGE_DESCRIPTOR"


@pytest.mark.parametrize("field", ("unknown", "publication_id", "source_checkpoint"))
def test_legacy_a1_recovery_descriptor_from_normalized_rejects_every_unknown_shape(field):
    bridge = make_transition()["bridge_predecessor"]
    bridge[field] = "x"
    assert code(lambda: e.legacy_a1_bridge_descriptor_from_normalized(bridge)) == "EPOCH_LEGACY_BRIDGE_DESCRIPTOR"


def test_legacy_a1_recovery_descriptor_from_normalized_uses_canonical_decimal_forms():
    bridge = make_transition()["bridge_predecessor"]
    bridge.update(publication_sequence=123, content_id=456, source_cut=0)
    recovery = e.legacy_a1_bridge_descriptor_from_normalized(bridge)
    assert recovery["content_id"] == "456"
    assert type(recovery["source_cut"]) is int and recovery["source_cut"] == 0
    assert validate_recovery_descriptor(recovery, recovery) == recovery


@pytest.mark.parametrize("mutate", [
    lambda x: x.update(publication_id="0"), lambda x: x.update(content_id="01"),
    lambda x: x.update(manifest_sha256="A" * 64), lambda x: x.update(artifact_sha256="a" * 63),
    lambda x: x.update(artifact_size=True), lambda x: x["source_checkpoint"].update(committed_event_id="+7"),
    lambda x: x["source_checkpoint"].update(committed_event_id=" 7"),
    lambda x: x["source_checkpoint"].update(committed_event_id="01"),
    lambda x: x["source_checkpoint"].update(committed_event_id=True),
    lambda x: x.update(extra="x"), lambda x: x["source_checkpoint"].update(extra="x")])
def test_normalize_legacy_a1_bridge_descriptor_rejects_every_bad_shape(mutate):
    bridge = make_transition()["bridge_predecessor"]; legacy = _legacy_bridge(bridge); mutate(legacy)
    assert code(lambda: e.normalize_legacy_a1_bridge_descriptor(legacy, bridge["manifest_sha256"], bridge)) == "EPOCH_LEGACY_BRIDGE_DESCRIPTOR"


@pytest.mark.parametrize("mutate,expected", [
    (lambda x: x["source_binding"].update(source_id="other"), "EPOCH_SOURCE_BINDING"),
    (lambda x: x["source_binding"].update(epoch="other"), "EPOCH_SOURCE_BINDING"),
    (lambda x: x["source_binding"].update(descriptor_sha256=h("0")), "EPOCH_SOURCE_DESCRIPTOR"),
    (lambda x: x["source_cut"].update(cut_evidence_sha256=h("0")), "EPOCH_SOURCE_CUT_EVIDENCE"),
    (lambda x: x["source_cut"].update(committed_event_id=9), "EPOCH_FIRST_SOURCE_CUT"),
    (lambda x: x["source_binding"].update(extra="x"), "EPOCH_FIELDS")])
def test_first_transition_source_authority_rejects_mutation(mutate, expected):
    value = make_transition(); mutate(value)
    assert code(lambda: e.validate_transition(value, value["accepted_anchor"], 0, True)) == expected


def _plan_for(transition):
    selected = {"projection_row_id": "sm1:" + h("5"), "raw_record_id": h("5"),
                "raw_text_sha256": h("6"), "scout_event_id": "9", "reasons": ["mandatory"]}
    omitted = {"projection_row_id": "sm1:" + h("7"), "raw_record_id": h("7"),
               "raw_text_sha256": h("8"), "scout_event_id": "10", "reasons": ["optional"]}
    value = {"schema": "flop-scout-epoch-active-set-plan/v1", "selection_policy_version": "epoch-v2-policy/1",
             "candidate_source": {"source_binding": transition["source_binding"], "source_cut": transition["source_cut"]},
             "archive_descriptor_sha256": e.commitment("archive-descriptor", e._without(transition["archive"], "archive_commitment_sha256")),
             "recovery_commitment_sha256": transition["active_set_plan"]["recovery_commitment_sha256"],
             "retained_floor_commitment_sha256": transition["retained_floor_commitment"]["retained_floor_commitment_sha256"],
             "omission_commitment_sha256": transition["retained_floor_commitment"]["omitted_history_sha256"],
             "capacity": transition["active_epoch"], "selected": [selected], "omitted": [omitted],
             "counts": {"selected": 1, "omitted": 1, "eligible": 2}}
    value["plan_commitment_sha256"] = e.commitment("active-set-plan", value)
    return value


def _bind_plan_bytes(transition, plan):
    raw = e.canonical_json(plan)
    transition["active_set_plan"].update(sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw),
                                         plan_commitment_sha256=plan["plan_commitment_sha256"])
    transition["commitments"]["active_set_plan_descriptor_sha256"] = e.commitment("active-set-plan-descriptor", transition["active_set_plan"])
    transition["epoch_id"] = e.derive_epoch_id(transition)
    transition["commitments"]["transition_sha256"] = e.commitment("complete-transition", {**{k:v for k,v in transition.items() if k != "commitments"}, "commitments": transition["commitments"]})
    return e.canonical_json(plan)


def test_active_set_plan_is_bounded_redacted_and_bound_to_transition():
    transition = make_transition(); plan = _plan_for(transition)
    assert e.validate_active_set_plan(plan, transition)["counts"]["eligible"] == 2
    raw = e.canonical_json(plan)
    assert e.parse_active_set_plan(raw) == plan and b'"raw_text":' not in raw
    # A real sidecar additionally binds its canonical bytes and logical hash.
    raw = _bind_plan_bytes(transition, plan)
    assert e.validate_active_set_plan_bytes(raw, transition)["counts"]["eligible"] == 2


@pytest.mark.parametrize("mutate,expected", [
    (lambda x: x.update(archive_descriptor_sha256=h("0")), "EPOCH_PLAN_BINDING"),
    (lambda x: x["omitted"].append(dict(x["selected"][0])), "EPOCH_PLAN_COUNTS"),
    (lambda x: x.update(plan_commitment_sha256=h("0")), "EPOCH_PLAN_COMMITMENT")])
def test_active_set_plan_rejects_mismatch_and_duplicate_records(mutate, expected):
    transition = make_transition(); plan = _plan_for(transition); mutate(plan)
    assert code(lambda: e.validate_active_set_plan(plan, transition)) == expected


def test_plan_byte_and_epoch_identity_bounds_are_fail_closed():
    assert code(lambda: e.parse_active_set_plan(b"x" * (e.MAX_PLAN_BYTES + 1))) == "EPOCH_PLAN_BOUNDS"
    assert code(lambda: e.parse_active_set_plan(("[" + ",".join("0" for _ in range(e.MAX_PLAN_RECORDS + 1)) + "]").encode("ascii"))) == "EPOCH_PLAN_BOUNDS"
    value = make_transition(); value["active_artifact"]["artifact_sha256"] = h("0")
    assert code(lambda: e.validate_transition(value, value["accepted_anchor"], 0, True)) == "EPOCH_ID"


def _manifest_for(transition):
    active = transition["active_artifact"]
    return {"schema": e.MANIFEST_SCHEMA, "contract_revision": e.REVISION, "snapshot_id": 901,
            "publication_kind": "CONTENT", "database_content_id": active["content_id"],
            "database": active["locator"], "sha256": active["artifact_sha256"],
            "size_bytes": active["size_bytes"], "database_schema_version": active["database_schema_version"],
            "selection_policy": "epoch-v2-policy/1", "selection_policy_sha256": h("9"),
            "content_created_at": "2026-01-01T00:00:00Z", "selection_evaluated_at": "2026-01-01T00:00:00Z",
            "produced_at": "2026-01-01T00:00:00Z", "source_checkpoint": {}, "next_expiry_at": "2026-01-02T00:00:00Z",
            "row_counts": {}, "watermarks": {}, "coverage_history": {},
            "epoch_transition": {"schema": e.SCHEMA, "locator": "epoch-transition-v2.json", "sha256": h("a"),
                                 "size_bytes": 1, "transition_sha256": transition["commitments"]["transition_sha256"]}}


def test_v2_manifest_is_strict_content_only_and_matches_transition():
    transition = make_transition(); manifest = _manifest_for(transition)
    assert e.validate_v2_manifest(manifest, transition)["publication_kind"] == "CONTENT"
    heartbeat = dict(manifest, publication_kind="HEARTBEAT")
    assert code(lambda: e.validate_v2_manifest(heartbeat, transition)) == "EPOCH_PUBLICATION_KIND"
    bad = dict(manifest, database_content_id=999)
    assert code(lambda: e.validate_v2_manifest(bad, transition)) == "EPOCH_MANIFEST_BINDING"


def test_wrong_domain_commitment_fails_validation():
    value = make_transition(); prior = copy.deepcopy(value["accepted_anchor"])
    value["commitments"]["accepted_anchor_sha256"] = e.commitment("archive-descriptor", value["accepted_anchor"])
    assert code(lambda: e.validate_transition(value, prior, 0, True)) == "EPOCH_COMMITMENT"


def test_error_does_not_echo_untrusted_payload():
    value = "REMOTE_UNTRUSTED_PAYLOAD_MUST_NOT_ECHO" * 200
    with pytest.raises(e.V2ValidationError) as caught:
        e.parse_json(("{\"x\":\"%s\"}" % value).encode("ascii"))
    assert value not in str(caught.value)


def _bundle_mutation(value, name):
    if name == "none": return
    if name == "artifact-hash": value["active_artifact"]["artifact_sha256"] = h("0")
    elif name == "plan-descriptor": value["active_set_plan"]["sha256"] = h("0")
    elif name == "epoch-id": value["epoch_id"] = "se2:" + h("0")
    elif name == "artifact-locator": value["active_artifact"]["locator"] = "other.sqlite"
    elif name == "manifest-hash": value["manifest_sha256"] = h("0")
    else: raise AssertionError(name)


@pytest.mark.parametrize("case", json.loads(BUNDLE_FIXTURE.read_text())["transition_cases"], ids=lambda x: x["name"])
def test_frozen_publication_bundle_vectors_execute_declared_outcome(case):
    value = make_transition()
    if case["mutation"] == "heartbeat":
        assert code(lambda: e.validate_transition(value, value["accepted_anchor"], 0, True, "HEARTBEAT")) == case["expect"]
        return
    _bundle_mutation(value, case["mutation"])
    call = lambda: e.validate_transition(value, value["accepted_anchor"], 0, True)
    if case["expect"] == "PASS": assert call()["epoch_number"] == 1
    else: assert code(call) == case["expect"]


@pytest.mark.parametrize("case", json.loads(BUNDLE_FIXTURE.read_text())["plan_cases"], ids=lambda x: x["name"])
def test_frozen_active_set_plan_vectors_execute_declared_outcome(case):
    transition = make_transition(); plan = _plan_for(transition)
    if case["mutation"] == "artifact": plan["archive_descriptor_sha256"] = h("0")
    elif case["mutation"] == "duplicate": plan["omitted"].append(dict(plan["selected"][0]))
    elif case["mutation"] == "oversized":
        assert code(lambda: e.parse_active_set_plan(b"x" * (e.MAX_PLAN_BYTES + 1))) == case["expect"]; return
    call = lambda: e.validate_active_set_plan(plan, transition)
    if case["expect"] == "PASS": assert call()["counts"]["eligible"] == 2
    else: assert code(call) == case["expect"]


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
    value["source_binding"] = e.first_transition_source_binding(value["bridge_predecessor"], value["bridge_binding_sha256"])
    value["source_cut"] = e.first_transition_source_cut(value["source_binding"], value["bridge_predecessor"], value["bridge_binding_sha256"])
    value["archive"]["previous_manifest_sha256"] = value["bridge_predecessor"]["manifest_sha256"]
    value["archive"]["previous_bridge_binding_sha256"] = value["bridge_binding_sha256"]
    value["archive"]["archive_commitment_sha256"] = e.commitment("archive-descriptor", {k:v for k,v in value["archive"].items() if k != "archive_commitment_sha256"})
    value["commitments"]["bridge_predecessor_sha256"] = e.commitment("bridge-predecessor", value["bridge_predecessor"])
    value["commitments"]["bridge_binding_sha256"] = value["bridge_binding_sha256"]
    value["commitments"]["archive_descriptor_sha256"] = e.commitment("archive-descriptor", {k:v for k,v in value["archive"].items() if k != "archive_commitment_sha256"})
    value["epoch_id"] = e.derive_epoch_id(value)
    value["commitments"]["transition_sha256"] = e.commitment("complete-transition", {**{k:v for k,v in value.items() if k != "commitments"}, "commitments": {k:v for k,v in value["commitments"].items() if k != "transition_sha256"}})
    assert e.validate_transition(value, value["accepted_anchor"], 0, True)["epoch_number"] == 1
