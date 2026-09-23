"""Path-free, deterministic inputs for Epoch-V2 fresh-cut model tests only.

The helpers construct tiny canonical transport objects, then pass them through
the production byte validators. They are not a runtime producer.
"""
import base64
import hashlib

from scout_epoch_v2 import (
    active_set_plan_commitment,
    build_content_successor,
    build_fresh_first_transition,
    canonical_json,
    commitment,
    compact_retained_floor,
    validate_active_artifact_bytes,
    validate_archive_descriptor_bytes,
    validate_content_successor,
    validate_fresh_first_transition,
    validate_plan_descriptor_bytes,
    validate_successor_predecessor,
)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def blob(label):
    """Return canonical labelled synthetic bytes without filesystem context."""
    if type(label) is not str or not label:
        raise ValueError("test label must be a nonempty string")
    return canonical_json({"schema": "scout-epoch-v2-test-blob/v1", "label": label})


def digest(label):
    return _sha(blob(label))


def _identifier(prefix, label):
    return prefix + "-" + digest(label)[:24]


def _record(label, reason):
    return {
        "projection_row_id": "sm1:" + digest(label + ":projection"),
        "raw_record_id": digest(label + ":raw-record"),
        "raw_text_sha256": digest(label + ":raw-text"),
        "scout_event_id": str(int(digest(label + ":event")[:12], 16)),
        "reasons": [reason],
    }


def _floor_sets(label, predecessor_sets):
    names = (
        "mandatory_proof_closure",
        "durable_qualification_history",
        "coverage_witnesses",
        "permanent_pinned_evidence",
        "omitted_history",
    )
    out = {}
    for name in names:
        prior = list((predecessor_sets or {}).get(name, ()))
        added = {"schema": "flop-scout-epoch-test-protected-item/v1",
                 "kind": name, "id": _identifier("item", label + ":" + name)}
        rows = prior + [added]
        encoded = [canonical_json(item) for item in rows]
        if len(encoded) != len(set(encoded)):
            raise ValueError("predecessor protected history contains duplicates")
        out[name] = [item for _, item in sorted(zip(encoded, rows))]
    return out


def build_retained_floor(label, predecessor=None):
    """Return ``(floor, protected_sets)`` with monotonic protected history.

    ``predecessor`` is either ``None`` or the exact two-tuple returned by this
    function. The compact floor holds only summaries; the companion sets let
    the test helper prove no predecessor-protected item was removed.
    """
    if predecessor is None:
        predecessor_floor, predecessor_sets = None, None
    elif (type(predecessor) is tuple and len(predecessor) == 2 and
          type(predecessor[0]) is dict and type(predecessor[1]) is dict):
        predecessor_floor, predecessor_sets = predecessor
    else:
        raise ValueError("predecessor must be a retained-floor builder result")
    sets = _floor_sets(label, predecessor_sets)
    entries = [{"room": "test-room", "generation": "1", "domain": "messages",
                "retained_floor": 1, "omitted_ranges": [[2, 2]]}]
    floor = compact_retained_floor(entries, "epoch-v2-test-policy/1", sets)
    if predecessor_floor is not None:
        for name, rows in predecessor_sets.items():
            if not set(map(canonical_json, rows)).issubset(
                    set(map(canonical_json, sets[name]))):
                raise ValueError("protected history removal")
    return floor, sets


def build_archive_transport(label, *, previous_epoch_id=None,
                            previous_manifest_sha256=None,
                            previous_bridge_binding_sha256=None):
    """Return a validated archive descriptor and canonical synthetic bytes."""
    raw = blob("archive:" + label)
    body = {
        "schema": "flop-scout-epoch-archive/v1",
        "archive_id": _identifier("ea2", label),
        "artifact_sha256": _sha(raw),
        "size_bytes": len(raw),
        "database_schema_version": "flop-scout-epoch-source-evidence/v1",
        "locator": "archive-" + digest(label)[:16] + ".sqlite",
        "previous_epoch_id": previous_epoch_id or _identifier("a1", label + ":epoch"),
        "previous_manifest_sha256": previous_manifest_sha256 or digest(label + ":manifest"),
        "previous_bridge_binding_sha256": (
            previous_bridge_binding_sha256 or digest(label + ":bridge-binding")),
        "preservation": "IMMUTABLE_RETAINED",
    }
    value = dict(body)
    value["archive_commitment_sha256"] = commitment("archive-descriptor", body)
    validate_archive_descriptor_bytes(value, raw)
    return value, raw


def build_active_artifact_transport(label, *, content_id):
    """Return a validated active-artifact descriptor and synthetic bytes."""
    raw = blob("active-artifact:" + label)
    value = {
        "schema": "scout-router-projection/v2",
        "content_id": content_id,
        "locator": "active-" + digest(label)[:16] + ".sqlite",
        "artifact_sha256": _sha(raw),
        "size_bytes": len(raw),
        "database_schema_version": "scout-router-projection/v2",
    }
    validate_active_artifact_bytes(value, raw)
    return value, raw


def build_plan_transport(label, *, archive, retained_floor, source_id="test-source",
                         source_epoch="test-epoch", source_cut=101,
                         recovery_commitment_sha256=None):
    """Return ``(descriptor, canonical_bytes, logical_plan)`` after validation."""
    recovery = recovery_commitment_sha256 or digest(label + ":recovery")
    plan = {
        "schema": "flop-scout-epoch-active-set-plan/v1",
        "selection_policy_version": "epoch-v2-test-policy/1",
        "candidate_source": {"source_binding": {
            "source_id": source_id, "epoch": source_epoch,
            "descriptor_sha256": digest(label + ":source-binding")},
            "source_cut": source_cut},
        "archive_descriptor_sha256": archive["archive_commitment_sha256"],
        "recovery_commitment_sha256": recovery,
        "retained_floor_commitment_sha256": (
            retained_floor["retained_floor_commitment_sha256"]),
        "omission_commitment_sha256": retained_floor["omitted_history_sha256"],
        "capacity": {"target": 10, "headroom": 2, "reserve": 1,
                     "hard_max": 50000, "mandatory_closure_count": 1},
        "selected": [_record(label + ":selected", "mandatory")],
        "omitted": [_record(label + ":omitted", "optional")],
        "counts": {"selected": 1, "omitted": 1, "eligible": 2},
    }
    plan["plan_commitment_sha256"] = active_set_plan_commitment(plan)
    raw = canonical_json(plan)
    descriptor = {
        "schema": "flop-scout-epoch-active-set-plan/v1",
        "locator": "plan-" + digest(label)[:16] + ".json",
        "sha256": _sha(raw), "size_bytes": len(raw),
        "plan_commitment_sha256": plan["plan_commitment_sha256"],
        "recovery_commitment_sha256": recovery,
    }
    if validate_plan_descriptor_bytes(descriptor, raw) != plan:
        raise AssertionError("production plan validator returned a different plan")
    return descriptor, raw, plan


def build_accepted_predecessor(root, manifest_bytes):
    """Derive an exact predecessor descriptor from either validated root schema."""
    if type(root) is not dict:
        raise ValueError("root must be a transition object")
    payload = root.get("payload")
    if type(payload) is not dict:
        raise ValueError("transition root has no payload")
    if root.get("schema") == "flop-scout-epoch-fresh-first-transition/v1":
        validate_fresh_first_transition(root, payload.get("accepted_anchor"))
    elif root.get("schema") == "flop-scout-epoch-content-successor/v1":
        validate_content_successor(root, payload.get("predecessor"))
    else:
        raise ValueError("root has an unsupported transition schema")
    if type(manifest_bytes) is not bytes or not manifest_bytes:
        raise ValueError("manifest bytes must be nonempty canonical bytes")
    active, archive, floor = (payload["active_artifact"], payload["archive"],
                              payload["retained_floor"])
    value = {
        "schema": "flop-scout-epoch-accepted-predecessor/v1",
        "publication_id": payload["publication_id"], "content_id": payload["content_id"],
        "epoch_id": payload["epoch_id"], "manifest_sha256": _sha(manifest_bytes),
        "transition_sha256": root["transition_sha256"],
        "artifact_sha256": active["artifact_sha256"],
        "artifact_size": active["size_bytes"], "source_id": payload["source_id"],
        "source_epoch": payload["source_epoch"], "source_cut": payload["source_cut"],
        "selection_policy_sha256": payload["selection_policy_sha256"],
        "archive_commitment_sha256": archive["archive_commitment_sha256"],
        "retained_floor_commitment_sha256": floor["retained_floor_commitment_sha256"],
    }
    return validate_successor_predecessor(value)


def snapshot():
    raw = blob("fresh-source-snapshot")
    return ({"schema": "flop-scout-epoch-source-snapshot/v1",
             "locator": "snapshots/fresh.sqlite", "sha256": _sha(raw),
             "size_bytes": len(raw), "sqlite_schema_sha256": digest("fresh-source-schema"),
             "semantic_checkpoint_sha256": digest("fresh-source-checkpoint")}, raw)


def _bridge_descriptor(label, publication_sequence, content_id, source_cut):
    raw = blob(label + ":artifact")
    return {
        "publication_sequence": publication_sequence,
        "content_id": content_id,
        "manifest_sha256": digest(label + ":manifest"),
        "artifact_sha256": _sha(raw),
        "artifact_size": len(raw),
        "source_kind": "test-epoch",
        "source_id": "test-source",
        "source_cut": source_cut,
    }


def _manifest_bytes(label, root):
    """Canonical synthetic manifest bytes binding the generated root identity."""
    return canonical_json({
        "schema": "flop-scout-epoch-test-manifest/v1",
        "label": label,
        "publication_id": root["payload"]["publication_id"],
        "content_id": root["payload"]["content_id"],
        "transition_sha256": root["transition_sha256"],
    })


def build_deterministic_fresh_chain():
    """Build a complete, path-free fresh-first plus two-successor test chain.

    Every transition is built through its production constructor.  The return
    value intentionally keeps transport bytes beside descriptors so tests can
    independently prove all descriptor bindings without touching a filesystem.
    """
    accepted_anchor = _bridge_descriptor("chain:anchor", 10, 20, 99)
    bridge_predecessor = _bridge_descriptor("chain:bridge", 11, 21, 100)
    bridge_binding = commitment("a1-bridge-binding", {
        "accepted_anchor": accepted_anchor,
        "bridge_predecessor": bridge_predecessor,
    })
    archive, archive_bytes = build_archive_transport(
        "chain:archive", previous_epoch_id="a1-epoch",
        previous_manifest_sha256=bridge_predecessor["manifest_sha256"],
        previous_bridge_binding_sha256=bridge_binding)
    floor, protected_sets = build_retained_floor("chain:floor")
    source_snapshot, source_snapshot_bytes = snapshot()
    policy = digest("chain:policy")

    plan0, plan0_bytes, plan0_value = build_plan_transport(
        "chain:plan-0", archive=archive, retained_floor=floor, source_cut=101)
    artifact0, artifact0_bytes = build_active_artifact_transport(
        "chain:artifact-0", content_id=22)
    fresh = build_fresh_first_transition(
        publication_id=12, content_id=22, source_id="test-source",
        source_epoch="test-epoch", source_cut=101,
        created_at="2026-01-01T00:00:00Z", selection_policy_sha256=policy,
        snapshot=source_snapshot, snapshot_bytes=source_snapshot_bytes,
        archive=archive, archive_bytes=archive_bytes, plan=plan0,
        plan_bytes=plan0_bytes, active_artifact=artifact0,
        active_artifact_bytes=artifact0_bytes, retained_floor=floor,
        accepted_anchor=accepted_anchor, bridge_predecessor=bridge_predecessor)
    manifest0 = _manifest_bytes("chain:manifest-0", fresh)
    predecessor0 = build_accepted_predecessor(fresh, manifest0)

    plan1, plan1_bytes, plan1_value = build_plan_transport(
        "chain:plan-1", archive=archive, retained_floor=floor, source_cut=102)
    artifact1, artifact1_bytes = build_active_artifact_transport(
        "chain:artifact-1", content_id=23)
    successor1 = build_content_successor(
        predecessor=predecessor0, publication_id=13, content_id=23,
        source_cut=102, created_at="2026-01-01T00:01:00Z", plan=plan1,
        plan_bytes=plan1_bytes, active_artifact=artifact1,
        active_artifact_bytes=artifact1_bytes, archive=archive,
        archive_bytes=archive_bytes, retained_floor=floor)
    manifest1 = _manifest_bytes("chain:manifest-1", successor1)
    predecessor1 = build_accepted_predecessor(successor1, manifest1)

    plan2, plan2_bytes, plan2_value = build_plan_transport(
        "chain:plan-2", archive=archive, retained_floor=floor, source_cut=103)
    artifact2, artifact2_bytes = build_active_artifact_transport(
        "chain:artifact-2", content_id=24)
    successor2 = build_content_successor(
        predecessor=predecessor1, publication_id=14, content_id=24,
        source_cut=103, created_at="2026-01-01T00:02:00Z", plan=plan2,
        plan_bytes=plan2_bytes, active_artifact=artifact2,
        active_artifact_bytes=artifact2_bytes, archive=archive,
        archive_bytes=archive_bytes, retained_floor=floor)
    manifest2 = _manifest_bytes("chain:manifest-2", successor2)

    return {
        "snapshot": {"descriptor": source_snapshot, "bytes": source_snapshot_bytes},
        "archive": {"descriptor": archive, "bytes": archive_bytes},
        "retained_floor": {"value": floor, "sets": protected_sets},
        "fresh_first": {"root": fresh, "plan": plan0, "plan_bytes": plan0_bytes,
                        "plan_value": plan0_value, "artifact": artifact0,
                        "artifact_bytes": artifact0_bytes, "manifest_bytes": manifest0,
                        "predecessor": predecessor0},
        "successor_1": {"root": successor1, "plan": plan1, "plan_bytes": plan1_bytes,
                        "plan_value": plan1_value, "artifact": artifact1,
                        "artifact_bytes": artifact1_bytes, "manifest_bytes": manifest1,
                        "predecessor": predecessor1},
        "successor_2": {"root": successor2, "plan": plan2, "plan_bytes": plan2_bytes,
                        "plan_value": plan2_value, "artifact": artifact2,
                        "artifact_bytes": artifact2_bytes, "manifest_bytes": manifest2},
    }


def build_deterministic_fresh_fixture_bytes():
    """Return the frozen valid-vector fixture bytes derived from the chain."""
    chain = build_deterministic_fresh_chain()

    def transport(descriptor, raw):
        return {"descriptor": descriptor,
                "bytes_base64": base64.b64encode(raw).decode("ascii")}

    vectors = []
    for name, stage in (("fresh-first", "fresh_first"),
                        ("successor-1", "successor_1"),
                        ("successor-2", "successor_2")):
        item = chain[stage]
        transports = {
            "archive": transport(chain["archive"]["descriptor"],
                                   chain["archive"]["bytes"]),
            "active_artifact": transport(item["artifact"], item["artifact_bytes"]),
            "active_set_plan": transport(item["plan"], item["plan_bytes"]),
            "manifest_bytes_base64": base64.b64encode(
                item["manifest_bytes"]).decode("ascii"),
        }
        if stage == "fresh_first":
            transports["source_snapshot"] = transport(
                chain["snapshot"]["descriptor"], chain["snapshot"]["bytes"])
        vectors.append({"id": name, "root": item["root"],
                        "transports": transports})
    fixture = {"schema": "scout-epoch-v2-fresh-cut-continuation-v1",
               "vectors": vectors}
    return canonical_json(fixture)
