import hashlib
import sqlite3
from pathlib import Path

import pytest

import scout_epoch_active_set_adapter as adapter


def _hex(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _fixture(tmp_path, count=3):
    projection = (tmp_path / "projection.sqlite").resolve()
    source = (tmp_path / "source.sqlite").resolve()
    for path in (projection, source):
        con = sqlite3.connect(path)
        if path == projection:
            con.executescript("""
            CREATE TABLE source_provenance(entity_type TEXT,projection_row_id TEXT,raw_record_id TEXT,raw_record_sha256 TEXT,scout_event_id TEXT);
            CREATE TABLE selection_membership(entity_type TEXT,projection_row_id TEXT,retention_class TEXT,retain_until TEXT,pin_roots_json TEXT);
            CREATE TABLE messages(projection_row_id TEXT,room TEXT,generation TEXT,seq INTEGER);
            CREATE TABLE coverage_history(room TEXT,generation TEXT,max_ever_projected_seq INTEGER);
            """)
        else:
            con.executescript("CREATE TABLE raw_records(raw_record_id TEXT,raw_text_sha256 TEXT);CREATE TABLE observed_event_witnesses(event_id INTEGER,raw_record_id TEXT);")
        con.close()
    c=sqlite3.connect(projection); s=sqlite3.connect(source); closure=[]
    for i in range(count):
        raw="%064x" % (i+1); sha=_hex(raw); pid="sm1:"+raw
        c.execute("INSERT INTO source_provenance VALUES(?,?,?,?,?)",("message",pid,raw,None,str(i+10)))
        c.execute("INSERT INTO selection_membership VALUES(?,?,?,?,?)",("message",pid,"PINNED" if i == 0 else "CONTEXT",None,"[]"))
        c.execute("INSERT INTO messages VALUES(?,?,?,?)",(pid,"room","1",i))
        s.execute("INSERT INTO raw_records VALUES(?,?)",(raw,sha));s.execute("INSERT INTO observed_event_witnesses VALUES(?,?)",(i+10,raw))
        if i == 0: closure.append({"projection_row_id":pid,"raw_record_id":raw,"raw_text_sha256":sha,"scout_event_id":str(i+10),"reasons":["permanent_or_pinned"]})
    c.execute("INSERT INTO coverage_history VALUES(?,?,?)",("room","1",2));c.commit();s.commit();c.close();s.close()
    return projection,source,{"closure":closure,"closure_count":1}


def test_records_is_bounded_redacted_and_carries_recovered_hashes(tmp_path):
    projection, source, recovery = _fixture(tmp_path)
    records = adapter._records(projection, source, recovery, 3)
    assert len(records) == 3
    assert records[0]["mandatory_reasons"] == ["permanent_or_pinned"]
    assert all("raw_text" not in row and "envelope" not in row for row in records)
    assert {row["retained_floor"] for row in records} == {2}


@pytest.mark.parametrize("change,code", [("missing", "ACTIVE_SET_CLOSURE"), ("duplicate", "ACTIVE_SET_DUPLICATE")])
def test_records_fail_closed_for_dependency_loss_and_duplicates(tmp_path, change, code):
    projection, source, recovery = _fixture(tmp_path)
    if change == "missing":
        recovery["closure"][0]["projection_row_id"] = "sm1:" + "f" * 64
    else:
        c = sqlite3.connect(projection)
        row=c.execute("SELECT * FROM source_provenance LIMIT 1").fetchone()
        c.execute("INSERT INTO source_provenance VALUES(?,?,?,?,?)",row)
        c.commit();c.close()
    with pytest.raises(adapter.ActiveSetError) as caught:
        adapter._records(projection, source, recovery, 3 if change == "missing" else 4)
    assert caught.value.code == code


def test_records_fail_closed_for_missing_recovery_or_closure_over_target(tmp_path, monkeypatch):
    projection, source, recovery = _fixture(tmp_path)
    with pytest.raises(adapter.ActiveSetError) as caught:
        adapter._records(projection, source, {}, 3)
    assert caught.value.code == "ACTIVE_SET_CLOSURE"
    monkeypatch.setattr(adapter, "TARGET", 0)
    with pytest.raises(adapter.ActiveSetError) as caught:
        adapter._records(projection, source, recovery, 3)
    assert caught.value.code == "ACTIVE_SET_CLOSURE"


def test_recovery_comparison_rejects_substitution():
    item={"descriptor":{},"validated_records":1,"closure_count":0,"closure":[],"reason_counts":{},"commitment":"a"*64}
    assert adapter._same_recovery(item, dict(item))
    altered=dict(item);altered["commitment"]="b"*64
    assert not adapter._same_recovery(item, altered)


def test_large_omission_commitment_is_deterministic_without_array_materialization():
    values = [{"record_id": "sm1:%064x" % index, "sha256": "%064x" % index} for index in range(6000)]
    assert adapter._set_commitment("scout/test/v1", values) == adapter._set_commitment("scout/test/v1", list(values))


def test_build_plan_rejects_archive_manifest_substitution_before_selection(tmp_path, monkeypatch):
    projection = (tmp_path / "projection.sqlite").resolve(); projection.touch()
    source = (tmp_path / "source.sqlite").resolve(); source.write_bytes(b"member")
    manifest_hash = _hex("manifest")
    descriptor = {"artifact_sha256": manifest_hash, "previous_epoch_id": "se1:prior"}
    authorized = {"artifact_sha256": _hex(""), "artifact_size": 0, "source_cut": 1}
    recovery = {"descriptor": {}, "validated_records": 1, "closure_count": 0, "closure": [], "reason_counts": {}, "commitment": "a" * 64}
    monkeypatch.setattr(adapter, "validate_archive", lambda *args: {"manifest": {"members": [{"role": "source_evidence_sqlite", "sha256": _hex("member"), "size_bytes": 6}]}, "recovery": recovery})
    monkeypatch.setattr(adapter, "validate_source", lambda *args: {"recovery": recovery})
    monkeypatch.setattr(adapter, "_records", lambda *args: [])
    with pytest.raises(adapter.ActiveSetError) as caught:
        adapter.build_plan(projection, source, tmp_path, authorized, dict(authorized), {}, descriptor, "b" * 64, expected_eligible_count=1)
    assert caught.value.code == "ACTIVE_SET_ARCHIVE"


def test_build_plan_rejects_projection_bytes_before_archive_validation(tmp_path, monkeypatch):
    projection = (tmp_path / "projection.sqlite").resolve(); projection.write_bytes(b"wrong")
    source = (tmp_path / "source.sqlite").resolve(); source.write_bytes(b"member")
    monkeypatch.setattr(adapter, "validate_archive", lambda *args: pytest.fail("archive validation must not run"))
    with pytest.raises(adapter.ActiveSetError) as caught:
        adapter.build_plan(projection, source, tmp_path, {}, {}, {}, {}, "a" * 64, expected_eligible_count=1)
    assert caught.value.code == "ACTIVE_SET_PROJECTION"
