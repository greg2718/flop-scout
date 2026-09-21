import copy
import hashlib
import json
import sqlite3

import pytest

from scout_legacy_a1_recovery import (DOMAIN, MAX_RECORDS, MAX_TEXT_BYTES,
                                      RecoveryError, canonical, parse_json,
                                      raw_record_id, resolve)
from scout_legacy_a1_recovery_sqlite import recover


def sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def descriptor():
    return {"content_id": "42", "manifest_sha256": "a" * 64, "artifact_sha256": "b" * 64,
            "artifact_size": 9, "source_kind": "bounded-current", "source_id": "source-a",
            "source_epoch": "epoch-a", "source_cut": 9}


def fixture():
    text = "exact source text"; envelope = {"text": text, "seq": 4, "nonce": 7, "from": "did:key:z"}
    rid = raw_record_id("technocore_room", "room", "1", None, envelope)
    raw = {"raw_record_id": rid, "source": "technocore_room", "room": "room", "generation": "1",
           "reported_generation": None, "raw_text": text, "raw_text_sha256": sha(text), "envelope": envelope}
    provenance = {"entity_type": "message", "projection_row_id": "sm1:" + rid,
                  "source_namespace": "technocore_room", "source_record_locator": rid,
                  "scout_event_id": "9", "raw_record_id": rid, "raw_record_sha256": None}
    row = {"provenance": provenance, "raw": raw, "event": [{"event_id": 9, "raw_text_sha256": sha(text)}],
           "cache_rows": {key: [] for key in ("messages", "evidence_records", "tclk_frames", "kibble_events")}}
    membership = [{"projection_row_id": "sm1:" + rid, "retain_until": None, "pin_roots_json": "[]", "retention_class": "TCLK_LIFECYCLE"}]
    qualification = json.dumps({"source_ref": {"kind": "PROJECTED_MESSAGE", "id": "sm1:" + rid}})
    message = {"projection_row_id": "sm1:" + rid, "room": "room", "generation": "1", "seq": 4}
    coverage = [{"room": "room", "generation": "1", "max_ever_projected_seq": 4,
                 "witness_source_locator": rid,
                 "witness_record_sha256": hashlib.sha256(canonical(message)).hexdigest(), "message": message}]
    return descriptor(), [row], membership, [qualification], coverage


def call(data=None):
    data = fixture() if data is None else data
    return resolve(data[0], copy.deepcopy(data[0]), *data[1:])


def code(callable_):
    with pytest.raises(RecoveryError) as caught:
        callable_()
    return caught.value.code


def test_success_is_sorted_minimal_and_deterministic():
    result = call()
    assert result["validated_records"] == result["closure_count"] == 1
    assert result["closure"][0]["reasons"] == ["coverage_witness", "durable_qualification", "permanent_or_pinned", "tclk_or_work_lifecycle"]
    assert result["reason_counts"] == {reason: 1 for reason in result["closure"][0]["reasons"]}
    assert "exact source text" not in repr(result)
    assert result["commitment"] == call()["commitment"]
    assert DOMAIN == "scout/legacy-a1-provenance-recovery-closure/v1"


def test_descriptor_and_raw_identity_fail_closed():
    data = fixture(); observed = copy.deepcopy(data[0]); observed["content_id"] = "43"
    assert code(lambda: resolve(data[0], observed, *data[1:])) == "RECOVERY_DESCRIPTOR"
    data = fixture(); data[1][0]["raw"]["envelope"]["seq"] = 5
    assert code(lambda: call(data)) == "RECOVERY_RAW_ID"
    data = fixture(); data[1][0]["raw"]["raw_text"] = "different"
    assert code(lambda: call(data)) == "RECOVERY_RAW_TEXT"
    data = fixture(); secret = "do-not-echo-this-source-text"; data[1][0]["raw"]["raw_text"] = secret
    with pytest.raises(RecoveryError) as caught:
        call(data)
    assert caught.value.code == "RECOVERY_RAW_TEXT" and secret not in str(caught.value)
    data = fixture(); data[1][0]["raw"]["raw_text_sha256"] = "0" * 64
    assert code(lambda: call(data)) == "RECOVERY_RAW_HASH"


@pytest.mark.parametrize("mutation, expected", [
    (lambda data: data[1][0].update(event=[]), "RECOVERY_EVENT"),
    (lambda data: data[1][0].update(event=[data[1][0]["event"][0], data[1][0]["event"][0]]), "RECOVERY_EVENT"),
    (lambda data: data[1][0]["event"][0].update(event_id=10), "RECOVERY_EVENT"),
    (lambda data: data[1][0]["cache_rows"].update(messages=[{"raw_text_sha256": "0" * 64}]), "RECOVERY_CACHE"),
    (lambda data: data[1][0]["cache_rows"].update(messages=[{}, {}]), "RECOVERY_CACHE"),
])
def test_event_and_cache_failures(mutation, expected):
    data = fixture(); mutation(data)
    assert code(lambda: call(data)) == expected


def test_source_cut_overrun_fails_closed():
    data = fixture(); data[0]["source_cut"] = 8
    assert code(lambda: call(data)) == "RECOVERY_SOURCE_CUT"


def test_missing_closure_provenance_and_commitment_mutation_fail_closed():
    data = fixture(); data[2][0]["projection_row_id"] = "sm1:missing"
    assert code(lambda: call(data)) == "RECOVERY_CLOSURE"
    result = call(); changed = copy.deepcopy(fixture()); changed[1][0]["event"][0]["event_id"] = 8
    changed[1][0]["provenance"]["scout_event_id"] = "8"
    assert call(changed)["commitment"] != result["commitment"]


def test_bounded_malformed_and_order_independent_inputs_fail_closed():
    data = list(fixture()); data[1] *= MAX_RECORDS + 1
    assert code(lambda: call(data)) == "RECOVERY_BOUNDS"
    data = fixture(); data[1].append(copy.deepcopy(data[1][0]))
    assert code(lambda: call(data)) == "RECOVERY_PROVENANCE"
    data = fixture(); data[1][0]["raw"] = None
    assert code(lambda: call(data)) == "RECOVERY_RAW"
    with pytest.raises(RecoveryError) as caught:
        parse_json('{"x":', "RECOVERY_RAW_ID")
    assert caught.value.code == "RECOVERY_RAW_ID"
    with pytest.raises(RecoveryError) as caught:
        raw_record_id("source", "room", "1", None, {"text": "x" * (MAX_TEXT_BYTES + 1)})
    assert caught.value.code == "RECOVERY_BOUNDS"
    data = fixture(); reversed_result = resolve(data[0], copy.deepcopy(data[0]), list(reversed(data[1])), list(reversed(data[2])), list(reversed(data[3])), list(reversed(data[4])))
    assert reversed_result == call()


def _sqlite_fixture(tmp_path):
    projection = tmp_path / "projection.sqlite"; source = tmp_path / "source.sqlite"
    text = "read-only secret fixture text"; envelope = {"text": text, "seq": 4, "nonce": 7, "from": "did:key:z"}
    rid = raw_record_id("technocore_room", "room", "1", None, envelope); text_sha = sha(text); pid = "sm1:" + rid
    with sqlite3.connect(source) as conn:
        conn.executescript("""
            CREATE TABLE raw_network_records(raw_record_id TEXT PRIMARY KEY,source TEXT,room TEXT,generation TEXT,reported_generation TEXT,raw_text TEXT,raw_text_sha256 TEXT,raw_record_json TEXT);
            CREATE TABLE observed_events(event_id INTEGER,raw_record_id TEXT,raw_text_sha256 TEXT);
            CREATE TABLE compatibility_evidence_links(cache_table TEXT,cache_rowid INTEGER,raw_record_id TEXT,raw_text_sha256 TEXT);
            CREATE TABLE messages(dummy TEXT); CREATE TABLE evidence_records(dummy TEXT);
            CREATE TABLE tclk_frames(dummy TEXT); CREATE TABLE kibble_events(dummy TEXT);
        """)
        conn.execute("INSERT INTO raw_network_records VALUES(?,?,?,?,?,?,?,?)", (rid, "technocore_room", "room", "1", None, text, text_sha, json.dumps(envelope)))
        conn.execute("INSERT INTO observed_events VALUES(?,?,?)", (9, rid, text_sha))
    message = {"projection_row_id": pid, "room": "room", "generation": "1", "seq": 4, "text": text}
    with sqlite3.connect(projection) as conn:
        conn.executescript("""
            CREATE TABLE source_provenance(entity_type TEXT,projection_row_id TEXT,source_namespace TEXT,source_record_locator TEXT,scout_event_id TEXT,raw_record_id TEXT,raw_record_sha256 TEXT,annotations_json TEXT);
            CREATE TABLE selection_membership(entity_type TEXT,projection_row_id TEXT,retention_class TEXT,first_observed_at TEXT,retain_until TEXT,pin_roots_json TEXT);
            CREATE TABLE durable_qualifications(qualification_id TEXT,record_json TEXT);
            CREATE TABLE coverage_history(room TEXT,generation TEXT,max_ever_projected_seq INTEGER,witness_source_locator TEXT,witness_record_sha256 TEXT);
            CREATE TABLE messages(projection_row_id TEXT,room TEXT,generation TEXT,seq INTEGER,text TEXT);
        """)
        conn.execute("INSERT INTO source_provenance VALUES(?,?,?,?,?,?,?,?)", ("message", pid, "technocore_room", rid, "9", rid, None, "{}"))
        conn.execute("INSERT INTO selection_membership VALUES(?,?,?,?,?,?)", ("message", pid, "TCLK_LIFECYCLE", "now", None, "[]"))
        conn.execute("INSERT INTO durable_qualifications VALUES(?,?)", ("q", json.dumps({"source_ref": {"kind": "PROJECTED_MESSAGE", "id": pid}})))
        conn.execute("INSERT INTO messages VALUES(?,?,?,?,?)", tuple(message.values()))
        conn.execute("INSERT INTO coverage_history VALUES(?,?,?,?,?)", ("room", "1", 4, rid, hashlib.sha256(canonical(message)).hexdigest()))
    descriptor_value = {"content_id": "1", "manifest_sha256": "a" * 64,
                        "artifact_sha256": hashlib.sha256(projection.read_bytes()).hexdigest(),
                        "artifact_size": projection.stat().st_size, "source_kind": "bounded-current",
                        "source_id": "source-a", "source_epoch": "epoch-a", "source_cut": 9}
    return projection, source, descriptor_value, text


def test_sqlite_adapter_is_read_only_and_rejects_artifact_mismatch(tmp_path):
    projection, source, item, secret = _sqlite_fixture(tmp_path)
    before = [(path.stat().st_size, path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest()) for path in (projection, source)]
    result = recover(projection, source, item, copy.deepcopy(item))
    after = [(path.stat().st_size, path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest()) for path in (projection, source)]
    assert result["closure_count"] == 1 and before == after and secret not in repr(result)
    wrong = copy.deepcopy(item); wrong["artifact_size"] += 1
    assert code(lambda: recover(projection, source, wrong, wrong)) == "RECOVERY_DESCRIPTOR"
    wrong = copy.deepcopy(item); wrong["artifact_sha256"] = "0" * 64
    assert code(lambda: recover(projection, source, wrong, wrong)) == "RECOVERY_DESCRIPTOR"


@pytest.mark.parametrize("target, statement", [
    ("source", "INSERT INTO raw_network_records(raw_record_id) WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<=50000) SELECT 'extra-' || x FROM n"),
    ("projection", "INSERT INTO source_provenance(entity_type,projection_row_id) WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<=50000) SELECT 'message','sm1:extra-' || x FROM n"),
])
def test_sqlite_source_and_projection_count_overflow_fail_before_materialization(tmp_path, target, statement):
    projection, source, item, _secret = _sqlite_fixture(tmp_path)
    with sqlite3.connect(source if target == "source" else projection) as conn:
        conn.execute(statement)
    if target == "projection":
        item["artifact_size"] = projection.stat().st_size
        item["artifact_sha256"] = hashlib.sha256(projection.read_bytes()).hexdigest()
    assert code(lambda: recover(projection, source, item, copy.deepcopy(item))) == "RECOVERY_BOUNDS"
