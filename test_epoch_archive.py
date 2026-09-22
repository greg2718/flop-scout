import hashlib
import json
import os
from pathlib import Path

import pytest

from scout_epoch_archive import (ArchiveError, MANIFEST_DOMAIN, _descriptor,
                                 _manifest, _path, recovery_bytes)

FIXTURE = Path(__file__).parent / "docs/fixtures/scout-router-epoch-rollover-v2-conformance.json"


def _recovery():
    return {"descriptor": {"content_id": "42", "artifact_sha256": "a" * 64},
            "validated_records": 1, "closure_count": 1,
            "closure": [{"raw_record_id": "a" * 64, "raw_text_sha256": "b" * 64,
                         "scout_event_id": "9", "reasons": ["coverage_witness"]}],
            "reason_counts": {"coverage_witness": 1}, "commitment": "c" * 64}


def _context():
    return {"accepted_anchor": {"content_id": "41"}, "bridge_predecessor": {"content_id": "42"},
            "source_checkpoint": {"source_id": "source", "source_epoch": "epoch", "source_cut": 9},
            "previous_bridge_binding_sha256": "d" * 64}


def test_recovery_member_is_canonical_redacted_and_deterministic():
    first = recovery_bytes(_recovery()); second = recovery_bytes(_recovery())
    assert first == second and b'"raw_text":' not in first and b'"envelope":' not in first
    changed = _recovery(); changed["commitment"] = "e" * 64
    assert recovery_bytes(changed) != first


def test_manifest_and_descriptor_are_deterministic():
    members = [{"role": "bridge_projection_sqlite", "locator": "members/bridge-projection.sqlite", "schema": "scout-router-projection/v2", "sha256": "a" * 64, "size_bytes": 1},
               {"role": "legacy_recovery_json", "locator": "members/legacy-recovery.json", "schema": "scout-legacy-a1-provenance-recovery/v1", "sha256": "b" * 64, "size_bytes": 2},
               {"role": "source_evidence_sqlite", "locator": "members/source-evidence.sqlite", "schema": "flop-scout-epoch-source-evidence/v1", "sha256": "c" * 64, "size_bytes": 3}]
    spec = {"archive_id": "a1:test", "previous_epoch_id": "epoch", "previous_manifest_sha256": "e" * 64, "locator": "archives/a1/manifest.json"}
    manifest = _manifest(_context(), spec, members, _recovery())
    assert manifest == _manifest(_context(), spec, list(reversed(members)), _recovery())
    assert _descriptor(spec, _context(), manifest) == _descriptor(spec, _context(), manifest)


@pytest.mark.parametrize("checkpoint", [
    {"source_id": "source", "epoch": "epoch", "committed_event_id": 9},
    {"source_id": "source", "source_epoch": "epoch", "source_cut": 9, "committed_event_id": 9},
])
def test_archive_checkpoint_rejects_legacy_and_mixed_key_sets(checkpoint):
    context = _context(); context["source_checkpoint"] = checkpoint
    with pytest.raises(ArchiveError):
        _manifest(context, {"archive_id":"a", "previous_epoch_id":"e", "previous_manifest_sha256":"a" * 64, "locator":"a/manifest.json"}, [], _recovery())


def test_frozen_valid_archive_vector_uses_archive_checkpoint_schema():
    vector = next(case for case in json.loads(FIXTURE.read_text())["archive_format_cases"] if case["name"] == "archive-manifest-valid")
    assert set(vector["manifest"]["source_checkpoint"]) == {"source_id", "source_epoch", "source_cut"}


def test_paths_reject_existing_output_and_symlink(tmp_path):
    out = tmp_path / "out"; out.mkdir()
    with pytest.raises(ArchiveError): _path(out.resolve(), True)
    target = tmp_path / "target"; target.write_bytes(b"x"); link = tmp_path / "link"; link.symlink_to(target)
    with pytest.raises(ArchiveError): _path(link)
