import sqlite3
from pathlib import Path

import pytest

import scout_epoch_active_artifact as artifact


RAW = "a" * 64
OMITTED = "b" * 64
HASH = "c" * 64


def _plan():
    return {"selected": [{"projection_row_id": "sm1:" + RAW, "raw_record_id": RAW,
                           "raw_text_sha256": HASH, "scout_event_id": "7"}],
            "omitted": [{"projection_row_id": "sm1:" + OMITTED}],
            "eligible_count": 2, "capacity": {"selected_count": 1}}


def _database(path, *, candidate=False, provenance_hash=None, witness=RAW, durable="{}"):
    conn = sqlite3.connect(path)
    conn.executescript("""
    CREATE TABLE messages(projection_row_id TEXT PRIMARY KEY);
    CREATE TABLE selection_membership(entity_type TEXT,projection_row_id TEXT);
    CREATE TABLE source_provenance(entity_type TEXT,projection_row_id TEXT,raw_record_id TEXT,raw_record_sha256 TEXT,scout_event_id TEXT);
    CREATE TABLE durable_qualifications(qualification_id TEXT PRIMARY KEY,record_json TEXT);
    CREATE TABLE qualification_events(event_id TEXT PRIMARY KEY,event_json TEXT);
    CREATE TABLE coverage_history(room TEXT,generation TEXT,max_ever_projected_seq INTEGER,witness_source_locator TEXT,witness_record_sha256 TEXT);
    """)
    rid = "sm1:" + RAW
    conn.execute("INSERT INTO messages VALUES(?)", (rid,))
    conn.execute("INSERT INTO selection_membership VALUES(?,?)", ("message", rid))
    conn.execute("INSERT INTO source_provenance VALUES(?,?,?,?,?)", ("message", rid, RAW, provenance_hash if candidate else None, "7"))
    conn.execute("INSERT INTO durable_qualifications VALUES(?,?)", ("q", durable))
    conn.execute("INSERT INTO coverage_history VALUES(?,?,?,?,?)", ("room", "0", 1, witness, "d" * 64))
    conn.commit(); conn.close()


def _code(call):
    with pytest.raises(artifact.ActiveArtifactError) as caught:
        call()
    return caught.value.code


def test_plan_row_validation_preserves_selected_hashes_and_dependencies(tmp_path):
    bridge = (tmp_path / "bridge.sqlite").resolve(); candidate = (tmp_path / "candidate.sqlite").resolve()
    _database(bridge); _database(candidate, candidate=True, provenance_hash=HASH)
    artifact._validate_plan_rows(candidate, bridge, _plan())


@pytest.mark.parametrize("kind,code", [("provenance", "ACTIVE_ARTIFACT_PROVENANCE"),
                                         ("coverage", "ACTIVE_ARTIFACT_COVERAGE"),
                                         ("durable", "ACTIVE_ARTIFACT_DEPENDENCY")])
def test_plan_row_validation_fails_closed_for_provenance_or_dependency_loss(tmp_path, kind, code):
    bridge = (tmp_path / "bridge.sqlite").resolve(); candidate = (tmp_path / "candidate.sqlite").resolve()
    _database(bridge, witness=OMITTED if kind == "coverage" else RAW)
    if kind == "provenance": _database(candidate, candidate=True, provenance_hash="e" * 64)
    elif kind == "coverage": _database(candidate, candidate=True, provenance_hash=HASH, witness=OMITTED)
    else: _database(candidate, candidate=True, provenance_hash=HASH, durable='{"changed":true}')
    assert _code(lambda: artifact._validate_plan_rows(candidate, bridge, _plan())) == code


def test_output_and_plan_paths_fail_closed(tmp_path):
    existing = (tmp_path / "existing.sqlite").resolve(); existing.touch()
    assert _code(lambda: artifact._path(existing, "output", output=True)) == "ACTIVE_ARTIFACT_PATH"
    link = tmp_path / "link.sqlite"; link.symlink_to(existing)
    assert _code(lambda: artifact._path(link, "output", output=True)) == "ACTIVE_ARTIFACT_PATH"
    plan = (tmp_path / "bad.json").resolve(); plan.write_text('{"x":1,"x":2}')
    assert _code(lambda: artifact._strict_plan(plan)) == "ACTIVE_ARTIFACT_PLAN"


def test_logical_plan_comparison_rejects_archive_or_recovery_substitution():
    base = {key: key for key in artifact._PLAN_CORE}
    assert artifact._same_plan(base, dict(base))
    changed = dict(base); changed["archive_manifest_sha256"] = "different"
    assert not artifact._same_plan(base, changed)
    changed = dict(base); changed["recovery_commitment"] = "different"
    assert not artifact._same_plan(base, changed)


def test_sidecar_rejects_individually_well_formed_but_different_rows_or_hashes():
    row = {"projection_row_id": "sm1:" + RAW, "raw_record_id": RAW,
           "raw_text_sha256": HASH, "scout_event_id": "7"}
    derived = {"selected": [row], "omitted": [], "eligible_count": 1,
               "recovery_commitment": "a", "retained_floor_commitment_sha256": "b",
               "omission_commitment_sha256": "c"}
    sidecar = {"selected": [dict(row)], "omitted": [], "counts": {"selected": 1, "omitted": 0, "eligible": 1},
               "recovery_commitment_sha256": "a", "retained_floor_commitment_sha256": "b", "omission_commitment_sha256": "c"}
    assert artifact._same_sidecar(sidecar, derived)
    sidecar["selected"][0]["raw_text_sha256"] = "d" * 64
    assert not artifact._same_sidecar(sidecar, derived)
