import copy
import hashlib

import pytest

import scout_epoch_active_set_plan as p


def _hex(number): return "%064x" % number


def _approved():
    selected = [{"projection_row_id": "sm1:" + _hex(i), "raw_record_id": _hex(i),
                 "raw_text_sha256": _hex(i + 50000), "scout_event_id": str(i)}
                for i in range(1, 43841)]
    omitted = [{"projection_row_id": "sm1:" + _hex(i), "raw_record_id": _hex(i),
                "raw_text_sha256": _hex(i + 50000), "scout_event_id": str(i),
                "reason_class": "DETERMINISTIC_OPTIONAL_OMISSION"}
               for i in range(43841, 49809)]
    return {"selection_policy_version": "epoch-v2-policy/1", "selected": selected, "omitted": omitted,
            "mandatory_reasons": {row["projection_row_id"]: ["mandatory"] for row in selected[:2]},
            "capacity": {"target": 43840, "headroom": 5904, "reserve": 256, "hard_max": 50000,
                         "mandatory_count": 2}, "recovery_commitment": _hex(8),
            "retained_floor_commitment_sha256": _hex(9), "omission_commitment_sha256": _hex(10)}


def _candidate():
    return {"source_binding": {"source_id": "source", "epoch": "epoch", "descriptor_sha256": _hex(1)},
            "source_cut": {"source_id": "source", "epoch": "epoch", "committed_event_id": 12,
                           "cut_evidence_sha256": _hex(2)}}


def code(call):
    with pytest.raises(p.ActiveSetPlanError) as caught: call()
    return caught.value.code


def test_canonical_sidecar_is_bounded_redacted_and_deterministic(tmp_path):
    approved = _approved(); first, raw = p.from_approved(approved, _candidate(), _hex(3))
    second, raw2 = p.from_approved(copy.deepcopy(approved), _candidate(), _hex(3))
    assert raw == raw2 and first == second and len(raw) <= 16 * 1024 * 1024
    assert first["counts"] == {"selected": 43840, "omitted": 5968, "eligible": 49808}
    assert b'"raw_text":' not in raw and "epoch_id" not in first and "active_artifact" not in first
    output = (tmp_path / "active-plan.json").resolve()
    written = p.write(approved, _candidate(), _hex(3), "plans/active.json", output)
    assert p.read(output, written["descriptor"])["plan_commitment_sha256"] == first["plan_commitment_sha256"]
    assert output.stat().st_mode & 0o777 == 0o600


def test_forbidden_cycle_fields_and_transport_tampering_fail_closed(tmp_path):
    value, raw = p.from_approved(_approved(), _candidate(), _hex(3))
    value["epoch_id"] = "se2:" + _hex(4)
    assert code(lambda: p.descriptor(value, raw, "plans/x.json")) == "ACTIVE_SET_PLAN_VALIDATION"
    output = (tmp_path / "active-plan.json").resolve()
    written = p.write(_approved(), _candidate(), _hex(3), "plans/active.json", output)
    output.write_bytes(output.read_bytes() + b" ")
    assert code(lambda: p.read(output, written["descriptor"])) == "ACTIVE_SET_PLAN_BYTES"


def test_locator_and_preexisting_output_are_rejected(tmp_path):
    out = (tmp_path / "exists.json").resolve(); out.write_bytes(b"x")
    assert code(lambda: p.write(_approved(), _candidate(), _hex(3), "../x", out)) == "ACTIVE_SET_PLAN_PATH"
