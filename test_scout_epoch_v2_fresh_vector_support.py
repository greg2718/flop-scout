"""Focused tests for the path-free fresh-vector transport builders."""
import copy
import base64
import json
import hashlib
from pathlib import Path

import pytest

import scout_epoch_v2 as e
from scout_epoch_v2_fresh_vector_support import (
    blob,
    build_accepted_predecessor,
    build_active_artifact_transport,
    build_archive_transport,
    build_deterministic_fresh_chain,
    build_deterministic_fresh_fixture_bytes,
    build_plan_transport,
    build_retained_floor,
    digest,
    snapshot,
)


FRESH_FIXTURE = Path(__file__).parent / (
    "docs/fixtures/scout-epoch-v2-fresh-cut-continuation-v1.json")
HISTORICAL_FIXTURES = {
    "scout-router-epoch-rollover-v2-conformance.json": (
        "d5892167d8221613f3ee07bfa6925280d7f39617ba999c5f5c72dd72d457daef"),
    "scout-epoch-v2-publication-bundle-v1.json": (
        "d3dca144bacaad1f47a1b0ad5a7ee4ec2c35eaa60c946bcc282d5b5b607bb8a4"),
    "scout-epoch-v2-publication-bundle-compact-v3.json": (
        "c7cee620934589e1a41bb26bbb0cb1af80a49811d99290d048618c21186ba735"),
}


def _code(call):
    with pytest.raises(e.V2ValidationError) as caught:
        call()
    return caught.value.code


def _bridge(label):
    return {
        "publication_sequence": 11,
        "content_id": 21,
        "manifest_sha256": digest(label + ":manifest"),
        "artifact_sha256": digest(label + ":artifact"),
        "artifact_size": len(blob(label + ":artifact")),
        "source_kind": "test-epoch",
        "source_id": "test-source",
        "source_cut": 100,
    }


def _fresh_root(label="root"):
    anchor = _bridge(label + ":anchor")
    bridge = _bridge(label + ":bridge")
    binding = e.commitment("a1-bridge-binding", {
        "accepted_anchor": anchor, "bridge_predecessor": bridge})
    archive, archive_bytes = build_archive_transport(
        label + ":archive", previous_epoch_id="a1-epoch",
        previous_manifest_sha256=bridge["manifest_sha256"],
        previous_bridge_binding_sha256=binding)
    floor = build_retained_floor(label + ":floor")[0]
    plan, plan_bytes, _ = build_plan_transport(
        label + ":plan", archive=archive, retained_floor=floor,
        source_cut=101)
    artifact, artifact_bytes = build_active_artifact_transport(
        label + ":artifact", content_id=22)
    source, _ = snapshot()
    root = e.build_fresh_first_transition(
        publication_id=12, content_id=22, source_id="test-source",
        source_epoch="test-epoch", source_cut=101,
        created_at="2026-01-01T00:00:00Z",
        selection_policy_sha256=digest(label + ":policy"), snapshot=source,
        snapshot_bytes=blob("fresh-source-snapshot"), archive=archive,
        archive_bytes=archive_bytes, plan=plan, plan_bytes=plan_bytes,
        active_artifact=artifact, active_artifact_bytes=artifact_bytes,
        retained_floor=floor, accepted_anchor=anchor, bridge_predecessor=bridge)
    return root


def test_transport_builders_are_deterministic_and_byte_validated():
    floor = build_retained_floor("alpha")[0]
    archive_a = build_archive_transport("alpha")
    archive_b = build_archive_transport("alpha")
    artifact_a = build_active_artifact_transport("alpha", content_id=22)
    artifact_b = build_active_artifact_transport("alpha", content_id=22)
    plan_a = build_plan_transport("alpha", archive=archive_a[0], retained_floor=floor)
    plan_b = build_plan_transport("alpha", archive=archive_a[0], retained_floor=floor)
    assert archive_a == archive_b
    assert artifact_a == artifact_b
    assert plan_a == plan_b
    assert archive_a[0]["artifact_sha256"] == hashlib.sha256(archive_a[1]).hexdigest()
    assert artifact_a[0]["artifact_sha256"] == hashlib.sha256(artifact_a[1]).hexdigest()
    assert plan_a[0]["sha256"] == hashlib.sha256(plan_a[1]).hexdigest()
    assert plan_a[0]["plan_commitment_sha256"] == e.active_set_plan_commitment(
        {k: v for k, v in plan_a[2].items() if k != "plan_commitment_sha256"})


@pytest.mark.parametrize("builder,validator", [
    (lambda: build_archive_transport("mutation"), e.validate_archive_descriptor_bytes),
    (lambda: build_active_artifact_transport("mutation", content_id=22),
     e.validate_active_artifact_bytes),
])
def test_transport_byte_mutation_is_rejected(builder, validator):
    descriptor, raw = builder()
    changed = raw[:-1] + bytes([raw[-1] ^ 1])
    assert _code(lambda: validator(descriptor, changed)) in {
        "EPOCH_ARCHIVE_BYTES", "EPOCH_ARTIFACT_BYTES"}


def test_plan_byte_mutation_is_rejected():
    floor = build_retained_floor("plan-mutation")[0]
    archive, _ = build_archive_transport("plan-mutation")
    descriptor, raw, _ = build_plan_transport(
        "plan-mutation", archive=archive, retained_floor=floor)
    changed = raw[:-1] + bytes([raw[-1] ^ 1])
    assert _code(lambda: e.validate_plan_descriptor_bytes(descriptor, changed)) == "EPOCH_PLAN_BYTES"


def test_retained_floor_is_canonical_and_cannot_remove_protected_history():
    first = build_retained_floor("first")
    second = build_retained_floor("second", predecessor=first)
    for name, rows in first[1].items():
        assert set(map(e.canonical_json, rows)).issubset(
            set(map(e.canonical_json, second[1][name])))
        assert second[0][name + "_count"] == first[0][name + "_count"] + 1
        assert second[0][name + "_sha256"] == e.bounded_commitment(
            {"mandatory_proof_closure": "mandatory-closure",
             "durable_qualification_history": "durable-qualification-history",
             "coverage_witnesses": "coverage-witnesses",
             "permanent_pinned_evidence": "permanent-pinned-evidence",
             "omitted_history": "omitted-history"}[name], second[1][name])
    bad = (copy.deepcopy(first[0]), copy.deepcopy(first[1]))
    bad[1]["omitted_history"].append(dict(bad[1]["omitted_history"][0]))
    with pytest.raises(ValueError, match="duplicates"):
        build_retained_floor("third", predecessor=bad)


def test_accepted_predecessor_is_exactly_derived_from_validated_root():
    root = _fresh_root()
    manifest = blob("fresh-manifest")
    predecessor = build_accepted_predecessor(root, manifest)
    payload = root["payload"]
    assert predecessor == {
        "schema": "flop-scout-epoch-accepted-predecessor/v1",
        "publication_id": payload["publication_id"], "content_id": payload["content_id"],
        "epoch_id": payload["epoch_id"],
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "transition_sha256": root["transition_sha256"],
        "artifact_sha256": payload["active_artifact"]["artifact_sha256"],
        "artifact_size": payload["active_artifact"]["size_bytes"],
        "source_id": payload["source_id"], "source_epoch": payload["source_epoch"],
        "source_cut": payload["source_cut"],
        "selection_policy_sha256": payload["selection_policy_sha256"],
        "archive_commitment_sha256": payload["archive"]["archive_commitment_sha256"],
        "retained_floor_commitment_sha256": (
            payload["retained_floor"]["retained_floor_commitment_sha256"]),
    }
    forged = copy.deepcopy(root)
    forged["transition_sha256"] = digest("forged-transition")
    with pytest.raises(e.V2ValidationError):
        build_accepted_predecessor(forged, manifest)


def test_deterministic_fresh_chain_has_exact_successor_links_and_continuity():
    chain = build_deterministic_fresh_chain()
    fresh = chain["fresh_first"]
    first = chain["successor_1"]
    second = chain["successor_2"]
    roots = [fresh["root"], first["root"], second["root"]]
    payloads = [root["payload"] for root in roots]
    assert {payload["epoch_id"] for payload in payloads} == {payloads[0]["epoch_id"]}
    assert [payload["publication_id"] for payload in payloads] == [12, 13, 14]
    assert [payload["content_id"] for payload in payloads] == [22, 23, 24]
    assert [payload["source_cut"] for payload in payloads] == [101, 102, 103]
    assert [payload["created_at"] for payload in payloads] == [
        "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", "2026-01-01T00:02:00Z"]
    assert first["root"]["payload"]["predecessor"] == fresh["predecessor"]
    assert second["root"]["payload"]["predecessor"] == first["predecessor"]
    assert len({item["artifact"]["artifact_sha256"] for item in (fresh, first, second)}) == 3
    assert len({item["plan"]["sha256"] for item in (fresh, first, second)}) == 3
    assert len({hashlib.sha256(item["manifest_bytes"]).hexdigest()
                for item in (fresh, first, second)}) == 3
    assert len({root["transition_sha256"] for root in roots}) == 3
    for payload in payloads[1:]:
        assert payload["selection_policy_sha256"] == payloads[0]["selection_policy_sha256"]
        assert payload["archive"]["archive_commitment_sha256"] == (
            payloads[0]["archive"]["archive_commitment_sha256"])
        assert payload["retained_floor"]["retained_floor_commitment_sha256"] == (
            payloads[0]["retained_floor"]["retained_floor_commitment_sha256"])


def test_deterministic_fresh_chain_regenerates_identically_and_revalidates_roots():
    first = build_deterministic_fresh_chain()
    second = build_deterministic_fresh_chain()
    assert first == second
    e.validate_fresh_first_transition(
        first["fresh_first"]["root"],
        first["fresh_first"]["root"]["payload"]["accepted_anchor"])
    e.validate_content_successor(first["successor_1"]["root"],
                                 first["fresh_first"]["predecessor"])
    e.validate_content_successor(first["successor_2"]["root"],
                                 first["successor_1"]["predecessor"])


def test_chain_rejects_transition_and_predecessor_mutations():
    chain = build_deterministic_fresh_chain()
    forged = copy.deepcopy(chain["successor_1"]["root"])
    forged["payload"]["predecessor"]["manifest_sha256"] = digest("substitute")
    assert _code(lambda: e.validate_content_successor(
        forged, chain["fresh_first"]["predecessor"])) == "EPOCH_SUCCESSOR_GAP"
    rollback = copy.deepcopy(chain["successor_2"]["root"])
    rollback["payload"]["source_cut"] = 102
    assert _code(lambda: e.validate_content_successor(
        rollback, chain["successor_1"]["predecessor"])) == "EPOCH_SUCCESSOR_ROLLBACK"
    changed = copy.deepcopy(chain["successor_2"]["root"])
    changed["transition_sha256"] = digest("forged-root")
    assert _code(lambda: build_accepted_predecessor(
        changed, chain["successor_2"]["manifest_bytes"])) == "EPOCH_SUCCESSOR_TRANSITION"


def _fixture_bytes(item, name):
    transport = item["transports"][name]
    return base64.b64decode(transport["bytes_base64"], validate=True)


def _validate_fresh_fixture(value):
    assert set(value) == {"schema", "vectors"}
    assert value["schema"] == "scout-epoch-v2-fresh-cut-continuation-v1"
    assert type(value["vectors"]) is list and len(value["vectors"]) == 3
    assert [item.get("id") for item in value["vectors"]] == [
        "fresh-first", "successor-1", "successor-2"]
    predecessors = []
    for index, item in enumerate(value["vectors"]):
        assert set(item) == {"id", "root", "transports"}
        expected = {"archive", "active_artifact", "active_set_plan",
                    "manifest_bytes_base64"}
        if index == 0:
            expected.add("source_snapshot")
        assert set(item["transports"]) == expected
        root = item["root"]
        archive = item["transports"]["archive"]
        active = item["transports"]["active_artifact"]
        plan = item["transports"]["active_set_plan"]
        assert set(archive) == {"descriptor", "bytes_base64"}
        assert set(active) == {"descriptor", "bytes_base64"}
        assert set(plan) == {"descriptor", "bytes_base64"}
        archive_bytes = _fixture_bytes(item, "archive")
        active_bytes = _fixture_bytes(item, "active_artifact")
        plan_bytes = _fixture_bytes(item, "active_set_plan")
        e.validate_archive_descriptor_bytes(archive["descriptor"], archive_bytes)
        logical_plan = e.validate_plan_descriptor_bytes(plan["descriptor"], plan_bytes)
        e.validate_active_artifact_bytes(active["descriptor"], active_bytes)
        payload = root["payload"]
        assert payload["archive"] == archive["descriptor"]
        assert payload["plan"] == plan["descriptor"]
        assert payload["active_artifact"] == active["descriptor"]
        assert logical_plan["plan_commitment_sha256"] == (
            plan["descriptor"]["plan_commitment_sha256"])
        manifest = base64.b64decode(item["transports"]["manifest_bytes_base64"],
                                    validate=True)
        if index == 0:
            snapshot = item["transports"]["source_snapshot"]
            assert set(snapshot) == {"descriptor", "bytes_base64"}
            snapshot_bytes = _fixture_bytes(item, "source_snapshot")
            assert len(snapshot_bytes) == snapshot["descriptor"]["size_bytes"]
            assert hashlib.sha256(snapshot_bytes).hexdigest() == (
                snapshot["descriptor"]["sha256"])
            assert payload["fresh_cut_authority"]["snapshot"] == snapshot["descriptor"]
            e.validate_fresh_first_transition(root, payload["accepted_anchor"])
        else:
            assert payload["predecessor"] == predecessors[-1]
            e.validate_content_successor(root, predecessors[-1])
        predecessors.append(build_accepted_predecessor(root, manifest))
    return predecessors


def test_frozen_fresh_fixture_is_exact_generator_output_and_revalidates_everything():
    raw = FRESH_FIXTURE.read_bytes()
    assert raw == build_deterministic_fresh_fixture_bytes()
    fixture = json.loads(raw.decode("ascii"))
    predecessors = _validate_fresh_fixture(fixture)
    roots = [item["root"] for item in fixture["vectors"]]
    assert [root["transition_sha256"] for root in roots] == [
        "672557597329377ebf69626c18d034777ba8e03b3ae5f7acb49b78a3d698010f",
        "ed95784d5505076440aad7d7e87f3866155166cc072eaba10063c1971dac9cdd",
        "450aa193e849d9c50c5c6ad8cfb478937708e442c4e27d4339fba87f500fe8cc",
    ]
    epoch = "se2:63dcce4fa7e5c4d0de207068f3ef46f168cc157d4e4ce3bbf88816b6eedf0545"
    assert [root["payload"]["epoch_id"] for root in roots] == [epoch, epoch, epoch]
    assert predecessors[1] == roots[2]["payload"]["predecessor"]
    assert roots[0]["payload"]["epoch_id"] == (
        "se2:" + e.fresh_first_payload_identity(roots[0]["payload"]))
    assert roots[0]["transition_sha256"] == e.commitment(
        "fresh-first-transition", roots[0]["payload"])
    for root in roots[1:]:
        assert root["transition_sha256"] == e.commitment(
            "content-successor-transition", root["payload"])


def test_frozen_fresh_fixture_rejects_vector_and_schema_inventory_changes():
    fixture = json.loads(FRESH_FIXTURE.read_text())
    missing = copy.deepcopy(fixture)
    missing["vectors"].pop()
    with pytest.raises(AssertionError):
        _validate_fresh_fixture(missing)
    extra = copy.deepcopy(fixture)
    extra["vectors"].append(copy.deepcopy(extra["vectors"][0]))
    with pytest.raises(AssertionError):
        _validate_fresh_fixture(extra)
    field = copy.deepcopy(fixture)
    field["vectors"][0]["root"]["unexpected"] = True
    with pytest.raises(e.V2ValidationError):
        _validate_fresh_fixture(field)


def test_historical_fixtures_remain_byte_for_byte_unchanged():
    fixture_dir = FRESH_FIXTURE.parent
    for name, expected in HISTORICAL_FIXTURES.items():
        assert hashlib.sha256((fixture_dir / name).read_bytes()).hexdigest() == expected
