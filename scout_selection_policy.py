"""Pure canonical selection-policy authority shared by A1 and Epoch V2."""
from __future__ import annotations

import copy
import hashlib
import json


_A1_POLICY = {
    "schema": "flop-router-projection-selection/v1",
    "version": "router-evidence-horizons/2",
    "classifier_version": "router-evidence-classes/2",
    "qualification_policy_version": "router-durable-qualification/v1",
    "parameters": {"context_seconds": 2592000, "capability_signal_seconds": 7776000,
                   "closed_work_seconds": 7776000, "closed_tclk_seconds": 7776000},
    "cutoff_semantics": "trusted-first-observed-strict-before-expiry/v1",
    "pinned_record_rules": "transitive-local-evidence-dependencies-no-implicit-unpin/v1",
}


def a1_selection_policy():
    """Return a detached copy of the frozen A1 policy object."""
    return copy.deepcopy(_A1_POLICY)


def canonical_policy_bytes(value):
    """The existing A1 canonical JSON policy representation."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def selection_policy_sha256(value):
    """The existing A1 policy-hash algorithm."""
    return hashlib.sha256(canonical_policy_bytes(value)).hexdigest()
