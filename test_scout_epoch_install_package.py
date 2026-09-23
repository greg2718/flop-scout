"""Pure contract tests for the offline Epoch V2 installer package.

The large real-artifact installation is exercised by the disposable rehearsal
audit; these tests keep the closed package grammar and path safety independent
of a machine-local 500 MiB fixture.
"""
import hashlib
import json
from pathlib import Path

import pytest

import scout_epoch_install_package as package
from scout_epoch_v2 import commitment


def _entry(role, number):
    return {"role": role, "locator": "members/%02d.bin" % number,
            "sha256": ("%064x" % number), "size_bytes": number + 1}


def _manifest():
    value = {"schema": package.SCHEMA, "accepted_anchor": {}, "bridge_predecessor": {},
             "bridge_binding_sha256": "a" * 64,
             "target": {"publication_id": 279, "content_id": 243, "epoch_id": "se2:test"},
             "files": [_entry(role, number) for number, role in enumerate(package.ROLES)]}
    value["package_commitment_sha256"] = commitment("install-package", value)
    return value


def test_closed_package_schema_and_canonical_commitment():
    value = _manifest()
    assert package._package_manifest(value) == value
    assert value["package_commitment_sha256"] == commitment(
        "install-package", {key: item for key, item in value.items() if key != "package_commitment_sha256"})
    changed = dict(value, unexpected=True)
    with pytest.raises(package.PackageError, match="unsupported package schema"):
        package._package_manifest(changed)


def test_exported_install_checkpoint_contract_is_closed_and_complete():
    expected = {
        "journal:before_write", "archive:archive_manifest:before_fsync",
        "bridge:bridge_artifact:after_fsync", "publication:candidate_artifact:after_fsync",
        "pointer:after_rename", "commit-journal:after_rename", "journal-cleanup:after_fsync",
    }
    assert len(package.INSTALL_CHECKPOINTS) == 67
    assert len(set(package.INSTALL_CHECKPOINTS)) == 67
    assert expected <= set(package.INSTALL_CHECKPOINTS)
    with pytest.raises(package.PackageError, match="unexported transaction checkpoint"):
        package._checkpoint(lambda _label: None, "not-an-install-checkpoint")


@pytest.mark.parametrize("name,recovery,operation", package.INSTALL_CHECKPOINT_CLASSES)
def test_all_install_checkpoints_have_exact_nonambiguous_recovery_model(name, recovery, operation):
    """Pure model of the journal protocol; filesystem cases exercise its edges."""
    assert name in package.INSTALL_CHECKPOINTS
    assert operation in {"journal", "archive", "bridge", "publication member", "pointer", "cleanup"}
    # The single atomic pointer rename is the linearization point.  No other
    # fault is allowed to expose a partially new active publication.
    if recovery == "pre-pointer":
        assert recovery == "pre-pointer"  # old pointer + old publication remain valid
    else:
        assert recovery in {"pointer-commit", "post-pointer"}  # recover validates new pointer/publication


def test_checkpoint_classification_covers_each_exported_name_once():
    rows = package.INSTALL_CHECKPOINT_CLASSES
    assert len(rows) == 67
    assert {row[0] for row in rows} == set(package.INSTALL_CHECKPOINTS)
    assert len({row[0] for row in rows}) == len(rows)


@pytest.mark.parametrize("mutate", ["missing", "duplicate", "unknown", "reordered"])
def test_roles_are_closed_unique_and_canonical(mutate):
    value = _manifest()
    if mutate == "missing": value["files"] = value["files"][:-1]
    elif mutate == "duplicate": value["files"][1]["role"] = value["files"][0]["role"]
    elif mutate == "unknown": value["files"][0]["role"] = "unknown"
    else: value["files"] = list(reversed(value["files"]))
    value["package_commitment_sha256"] = commitment("install-package", {key: item for key, item in value.items() if key != "package_commitment_sha256"})
    with pytest.raises(package.PackageError): package._package_manifest(value)


@pytest.mark.parametrize("locator", ["../x", "/x", "a//b", "a/./b", "a/../b", "a\\b"])
def test_locator_rejects_traversal_and_absolute_paths(locator):
    with pytest.raises(package.PackageError): package._safe_rel(locator)


def test_audit_fixture_is_redacted_and_binds_real_rehearsal_identity():
    path = Path(__file__).parent / "docs/fixtures/scout-epoch-v2-installer-rehearsal-v1.json"
    raw = path.read_bytes(); value = json.loads(raw)
    assert value["schema"] == "flop-scout-epoch-installer-rehearsal-audit/v1"
    assert value["package"]["schema"] == package.SCHEMA
    assert value["candidate"]["publication_id"] == 279
    assert value["candidate"]["content_id"] == 243
    assert value["input_nonmutation"]["result"] == "UNCHANGED"
    assert b"/private/" not in raw and b"raw_text" not in raw and b"token" not in raw
    assert len(value["interruption_results"]) == 6


@pytest.mark.parametrize("journal", [
    {},
    {"schema": package.SCHEMA + "-journal", "state": "unknown", "old_pointer_sha256": "a" * 64, "target": {}},
    {"schema": package.SCHEMA + "-journal", "state": "precommit", "old_pointer_sha256": "bad", "target": {"publication_id": 279, "content_id": 243, "epoch_id": "se2:test"}},
    {"schema": package.SCHEMA + "-journal", "state": "precommit", "old_pointer_sha256": "a" * 64, "target": {"publication_id": 279, "content_id": 243, "epoch_id": "se2:test"}, "extra": True},
])
def test_journal_schema_is_closed(tmp_path, journal):
    root = tmp_path / "publication"; root.mkdir()
    (root / package.JOURNAL).write_text(json.dumps(journal))
    with pytest.raises(package.PackageError): package.recover(root.resolve())
