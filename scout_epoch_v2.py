"""Pure, bounded V2 epoch-rollover model and validator.

No file, database, clock, environment, network, signature, or publication I/O.
"""
import hashlib
import json
import re

from scout_selection_policy import a1_selection_policy, selection_policy_sha256

SCHEMA = "flop-scout-router-epoch-rollover/v2"
REVISION = "A1-EPOCH-V2"
MANIFEST_SCHEMA = "flop-scout-router-snapshot/v2"
MAX_INPUT_BYTES, MAX_DEPTH, MAX_STRING_BYTES = 65536, 16, 4096
MAX_PLAN_BYTES, MAX_PLAN_RECORDS = 16 * 1024 * 1024, 50000
MAX_LIST_ITEMS, MAX_MAP_ITEMS, MAX_EPOCH = 256, 64, 9007199254740991
MAX_INT = 9223372036854775807
_HEX = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[a-z][a-z0-9:._-]{0,128}$")
_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$")


class V2ValidationError(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def _fail(code, message):
    raise V2ValidationError(code, message)


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            _fail("EPOCH_DUPLICATE_KEY", "duplicate JSON object key")
        out[key] = value
    return out


def _number(_value):
    _fail("EPOCH_NUMBER", "floating-point or non-finite JSON number")


def _bounded(value, depth=0):
    if depth > MAX_DEPTH:
        _fail("EPOCH_NESTING", "JSON nesting exceeds the V2 limit")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -MAX_INT <= value <= MAX_INT:
            _fail("EPOCH_INTEGER_BOUNDS", "integer exceeds the V2 limit")
        return
    if type(value) is str:
        try:
            size = len(value.encode("ascii"))
        except UnicodeEncodeError:
            _fail("EPOCH_UNICODE", "V2 strings must be ASCII")
        if size > MAX_STRING_BYTES:
            _fail("EPOCH_STRING_BOUNDS", "string exceeds the V2 limit")
        return
    if type(value) is list:
        if len(value) > MAX_LIST_ITEMS:
            _fail("EPOCH_LIST_BOUNDS", "array exceeds the V2 limit")
        for item in value:
            _bounded(item, depth + 1)
        return
    if type(value) is dict:
        if len(value) > MAX_MAP_ITEMS:
            _fail("EPOCH_MAP_BOUNDS", "object exceeds the V2 limit")
        for key, item in value.items():
            if type(key) is not str:
                _fail("EPOCH_TYPE", "object key must be a string")
            _bounded(key, depth + 1); _bounded(item, depth + 1)
        return
    _fail("EPOCH_TYPE", "unsupported JSON value")


def parse_json(data):
    if type(data) is not bytes or len(data) > MAX_INPUT_BYTES:
        _fail("EPOCH_INPUT_BOUNDS", "JSON input exceeds the V2 limit")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        _fail("EPOCH_UTF8", "JSON input is not valid UTF-8")
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_float=_number,
                           parse_constant=_number)
    except V2ValidationError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError):
        _fail("EPOCH_JSON", "invalid JSON")
    _bounded(value)
    return value


def canonical_json(value):
    _bounded(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def commitment(domain, value):
    if type(domain) is not str or not re.match(r"^[a-z][a-z0-9-]{0,63}$", domain):
        _fail("EPOCH_DOMAIN", "invalid commitment domain")
    return hashlib.sha256(("flop-scout/epoch-v2/" + domain).encode("ascii") +
                          b"\0" + canonical_json(value)).hexdigest()


def _obj(value, fields, code="EPOCH_FIELDS"):
    if type(value) is not dict or set(value) != set(fields):
        _fail(code, "unexpected or missing object fields")


def _text(value, code="EPOCH_TYPE"):
    if type(value) is not str:
        _fail(code, "field must be a string")
    _bounded(value)
    return value


def _hash(value, code="EPOCH_HASH"):
    if type(value) is not str or not _HEX.match(value):
        _fail(code, "field must be a lower-case SHA-256 digest")
    return value


def _id(value, code="EPOCH_IDENTIFIER"):
    if type(value) is not str or not _ID.match(value):
        _fail(code, "field must be a bounded identifier")
    return value


def _integer(value, code="EPOCH_TYPE", minimum=0, maximum=MAX_INT):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(code, "field is outside the permitted integer range")
    return value


def _without(value, field):
    out = dict(value); del out[field]; return out


DESCRIPTOR = ("publication_sequence", "content_id", "manifest_sha256", "artifact_sha256",
              "artifact_size", "source_kind", "source_id", "source_cut")
CUT = ("source_id", "epoch", "committed_event_id", "cut_evidence_sha256")
ARCHIVE = ("schema", "archive_id", "artifact_sha256", "size_bytes", "database_schema_version", "locator", "previous_epoch_id", "previous_manifest_sha256", "previous_bridge_binding_sha256", "preservation", "archive_commitment_sha256")
ACTIVE_ARTIFACT = ("schema", "content_id", "locator", "artifact_sha256", "size_bytes", "database_schema_version")
ACTIVE_SET_PLAN = ("schema", "locator", "sha256", "size_bytes", "plan_commitment_sha256", "recovery_commitment_sha256")
PLAN = ("schema", "selection_policy_version", "candidate_source", "archive_descriptor_sha256", "recovery_commitment_sha256", "retained_floor_commitment_sha256", "omission_commitment_sha256", "capacity", "selected", "omitted", "counts", "plan_commitment_sha256")
PLAN_RECORD = ("projection_row_id", "raw_record_id", "raw_text_sha256", "scout_event_id", "reasons")
FLOOR = ("room", "generation", "domain", "retained_floor", "omitted_ranges")
FLOORS = ("entries", "selection_policy_version", "mandatory_proof_closure_count", "mandatory_proof_closure_sha256", "durable_qualification_history_count", "durable_qualification_history_sha256", "coverage_witnesses_count", "coverage_witnesses_sha256", "permanent_pinned_evidence_count", "permanent_pinned_evidence_sha256", "omitted_history_count", "omitted_history_sha256", "retained_floor_commitment_sha256")
ACTIVE = ("target", "headroom", "reserve", "hard_max", "mandatory_closure_count")
COMMITMENTS = ("accepted_anchor_sha256", "bridge_predecessor_sha256", "bridge_binding_sha256", "archive_descriptor_sha256", "active_artifact_descriptor_sha256", "active_set_plan_descriptor_sha256", "retained_floor_declaration_sha256", "mandatory_closure_sha256", "durable_qualification_history_sha256", "coverage_witnesses_sha256", "permanent_pinned_evidence_sha256", "transition_sha256")
TRANSITION = ("schema", "contract_revision", "epoch_number", "epoch_id", "created_at", "source_binding", "source_cut", "accepted_anchor", "bridge_predecessor", "bridge_binding_sha256", "active_artifact", "active_set_plan", "archive", "retained_floor_commitment", "active_epoch", "commitments")
MANIFEST = ("schema", "contract_revision", "snapshot_id", "publication_kind", "database_content_id", "database", "sha256", "size_bytes", "database_schema_version", "selection_policy", "selection_policy_sha256", "content_created_at", "selection_evaluated_at", "produced_at", "source_checkpoint", "next_expiry_at", "row_counts", "watermarks", "coverage_history", "epoch_transition")
MANIFEST_TRANSITION = ("schema", "locator", "sha256", "size_bytes", "transition_sha256")


def a1_selection_policy_binding(snapshot_policy_sha256):
    """Return the sole V2-eligible A1 policy after binding it to SQLite metadata.

    This deliberately uses the same canonical policy hash as A1 publication.
    The transition does not carry policy, so this binding is manifest-only.
    """
    _hash(snapshot_policy_sha256, "EPOCH_MANIFEST_POLICY")
    policy = a1_selection_policy()
    digest = selection_policy_sha256(policy)
    if snapshot_policy_sha256 != digest:
        _fail("EPOCH_MANIFEST_POLICY", "artifact selection policy differs from retained A1 policy")
    return policy, digest


def build_v2_manifest(value, transition, snapshot_policy_sha256):
    """Add the canonical retained A1 policy to a closed V2 manifest body."""
    fields = tuple(field for field in MANIFEST
                   if field not in ("selection_policy", "selection_policy_sha256"))
    _obj(value, fields, "EPOCH_MANIFEST_FIELDS")
    policy, digest = a1_selection_policy_binding(snapshot_policy_sha256)
    built = dict(value, selection_policy=policy, selection_policy_sha256=digest)
    return validate_v2_manifest(built, transition)


def _cut(value):
    _obj(value, CUT); _id(value["source_id"]); _id(value["epoch"])
    _integer(value["committed_event_id"], "EPOCH_SOURCE_CUT"); _hash(value["cut_evidence_sha256"])


def source_binding_descriptor(bridge_predecessor, bridge_binding_sha256):
    """Canonical first-transition authority, bound to the complete A1 bridge."""
    _descriptor(bridge_predecessor); _hash(bridge_binding_sha256, "EPOCH_BRIDGE_BINDING")
    return commitment("source-binding-descriptor", {
        "schema": "flop-scout-epoch-source-binding/v1",
        "source_id": bridge_predecessor["source_id"], "epoch": bridge_predecessor["source_kind"],
        "bridge_binding_sha256": bridge_binding_sha256})


def first_transition_source_binding(bridge_predecessor, bridge_binding_sha256):
    return {"source_id": bridge_predecessor["source_id"], "epoch": bridge_predecessor["source_kind"],
            "descriptor_sha256": source_binding_descriptor(bridge_predecessor, bridge_binding_sha256)}


def source_cut_evidence(source_binding, bridge_predecessor, bridge_binding_sha256):
    _obj(source_binding, ("source_id", "epoch", "descriptor_sha256"), "EPOCH_SOURCE_BINDING")
    _descriptor(bridge_predecessor); _hash(bridge_binding_sha256, "EPOCH_BRIDGE_BINDING")
    return commitment("source-cut-evidence", {
        "schema": "flop-scout-epoch-source-cut-evidence/v1", "source_binding": source_binding,
        "committed_event_id": bridge_predecessor["source_cut"], "bridge_binding_sha256": bridge_binding_sha256})


def first_transition_source_cut(source_binding, bridge_predecessor, bridge_binding_sha256):
    return {"source_id": source_binding["source_id"], "epoch": source_binding["epoch"],
            "committed_event_id": bridge_predecessor["source_cut"],
            "cut_evidence_sha256": source_cut_evidence(source_binding, bridge_predecessor, bridge_binding_sha256)}


def normalize_legacy_a1_bridge_descriptor(legacy, observed_manifest_sha256, normalized_bridge):
    """Local-only conversion of one acquired A1 descriptor; never wire parsing."""
    try:
        if type(legacy) is not dict or set(legacy) != {"publication_id", "content_id", "manifest_sha256", "artifact_sha256", "artifact_size", "source_checkpoint"}:
            raise ValueError
        checkpoint = legacy["source_checkpoint"]
        if type(checkpoint) is not dict or set(checkpoint) != {"source_id", "epoch", "committed_event_id"}:
            raise ValueError
        _hash(observed_manifest_sha256)
        if legacy["manifest_sha256"] != observed_manifest_sha256: raise ValueError
        for key in ("artifact_sha256", "manifest_sha256"): _hash(legacy[key])
        def decimal(value):
            if type(value) is not str or not re.match(r"^(0|[1-9][0-9]*)$", value): raise ValueError
            number = int(value)
            if number > MAX_INT: raise ValueError
            return number
        candidate = {"publication_sequence": decimal(legacy["publication_id"]), "content_id": decimal(legacy["content_id"]),
                     "manifest_sha256": observed_manifest_sha256, "artifact_sha256": legacy["artifact_sha256"],
                     "artifact_size": legacy["artifact_size"], "source_kind": checkpoint["epoch"],
                     "source_id": checkpoint["source_id"], "source_cut": decimal(checkpoint["committed_event_id"])}
        if type(candidate["artifact_size"]) is not int or type(candidate["artifact_size"]) is bool or candidate["artifact_size"] < 0:
            raise ValueError
        if candidate["publication_sequence"] < 1 or candidate["content_id"] < 1: raise ValueError
        _id(candidate["source_id"]); _text(candidate["source_kind"])
        _descriptor(candidate)
        _descriptor(normalized_bridge)
        if candidate != normalized_bridge: raise ValueError
        return candidate
    except (TypeError, ValueError, V2ValidationError):
        _fail("EPOCH_LEGACY_BRIDGE_DESCRIPTOR", "legacy bridge descriptor is invalid or differs from verified bridge")


def legacy_a1_bridge_descriptor_from_normalized(normalized_bridge):
    """Return recovery-only legacy compatibility data for one normalized V2 bridge.

    This is deliberately not a V2 wire parser.  The historical A1 publication
    shape is rebuilt only for the local round-trip proof below; the returned
    value is the closed descriptor shape consumed by legacy recovery.
    """
    try:
        _descriptor(normalized_bridge)
        if normalized_bridge["publication_sequence"] < 1 or normalized_bridge["content_id"] < 1:
            raise ValueError
        if normalized_bridge["artifact_size"] < 1:
            raise ValueError
        publication_descriptor = {
            "publication_id": str(normalized_bridge["publication_sequence"]),
            "content_id": str(normalized_bridge["content_id"]),
            "manifest_sha256": normalized_bridge["manifest_sha256"],
            "artifact_sha256": normalized_bridge["artifact_sha256"],
            "artifact_size": normalized_bridge["artifact_size"],
            "source_checkpoint": {
                "source_id": normalized_bridge["source_id"],
                "epoch": normalized_bridge["source_kind"],
                "committed_event_id": str(normalized_bridge["source_cut"]),
            },
        }
        if normalize_legacy_a1_bridge_descriptor(
                publication_descriptor, normalized_bridge["manifest_sha256"], normalized_bridge) != normalized_bridge:
            raise ValueError
        return {
            "content_id": str(normalized_bridge["content_id"]),
            "manifest_sha256": normalized_bridge["manifest_sha256"],
            "artifact_sha256": normalized_bridge["artifact_sha256"],
            "artifact_size": normalized_bridge["artifact_size"],
            "source_kind": normalized_bridge["source_kind"],
            "source_id": normalized_bridge["source_id"],
            "source_epoch": normalized_bridge["source_kind"],
            "source_cut": normalized_bridge["source_cut"],
        }
    except (TypeError, ValueError, V2ValidationError):
        _fail("EPOCH_LEGACY_BRIDGE_DESCRIPTOR", "normalized bridge descriptor cannot produce legacy recovery data")


def _descriptor(value):
    _obj(value, DESCRIPTOR, "EPOCH_DESCRIPTOR")
    for key in ("publication_sequence", "content_id", "artifact_size", "source_cut"):
        _integer(value[key], "EPOCH_DESCRIPTOR")
    for key in ("manifest_sha256", "artifact_sha256"):
        _hash(value[key], "EPOCH_DESCRIPTOR")
    _text(value["source_kind"], "EPOCH_DESCRIPTOR"); _id(value["source_id"], "EPOCH_DESCRIPTOR")


def _archive(value):
    _obj(value, ARCHIVE)
    if value["schema"] != "flop-scout-epoch-archive/v1" or value["preservation"] != "IMMUTABLE_RETAINED":
        _fail("EPOCH_ARCHIVE_SCHEMA", "unsupported archive schema or preservation")
    _id(value["archive_id"]); _hash(value["artifact_sha256"]); _integer(value["size_bytes"], "EPOCH_ARCHIVE_BOUNDS", 1)
    _text(value["database_schema_version"]); locator = _text(value["locator"])
    if len(locator) > 256 or locator.startswith("/") or ":" in locator or "\\" in locator or ".." in locator.split("/"):
        _fail("EPOCH_ARCHIVE_LOCATOR", "archive locator is not a safe relative identifier")
    _id(value["previous_epoch_id"]); _hash(value["previous_manifest_sha256"]); _hash(value["previous_bridge_binding_sha256"]); _hash(value["archive_commitment_sha256"])
    if value["archive_commitment_sha256"] != commitment("archive-descriptor", _without(value, "archive_commitment_sha256")):
        _fail("EPOCH_ARCHIVE_HASH", "archive descriptor commitment mismatch")


def _locator(value, code):
    value = _text(value, code)
    if not value or len(value) > 256 or value.startswith("/") or ":" in value or "\\" in value or "." in value.split("/") or ".." in value.split("/"):
        _fail(code, "locator is not a safe relative identifier")
    return value


def _active_artifact(value):
    _obj(value, ACTIVE_ARTIFACT, "EPOCH_ACTIVE_ARTIFACT")
    if value["schema"] != "scout-router-projection/v2":
        _fail("EPOCH_ACTIVE_ARTIFACT", "unsupported active artifact schema")
    _integer(value["content_id"], "EPOCH_ACTIVE_ARTIFACT", 1)
    _locator(value["locator"], "EPOCH_ACTIVE_ARTIFACT")
    _hash(value["artifact_sha256"], "EPOCH_ACTIVE_ARTIFACT")
    _integer(value["size_bytes"], "EPOCH_ACTIVE_ARTIFACT", 1)
    if value["database_schema_version"] != "scout-router-projection/v2":
        _fail("EPOCH_ACTIVE_ARTIFACT", "unsupported active database schema")


def _active_set_plan(value):
    _obj(value, ACTIVE_SET_PLAN, "EPOCH_ACTIVE_SET_PLAN")
    if value["schema"] != "flop-scout-epoch-active-set-plan/v1":
        _fail("EPOCH_ACTIVE_SET_PLAN", "unsupported active-set plan schema")
    _locator(value["locator"], "EPOCH_ACTIVE_SET_PLAN")
    _hash(value["sha256"], "EPOCH_ACTIVE_SET_PLAN")
    _integer(value["size_bytes"], "EPOCH_ACTIVE_SET_PLAN", 1, MAX_PLAN_BYTES)
    _hash(value["plan_commitment_sha256"], "EPOCH_ACTIVE_SET_PLAN")
    _hash(value["recovery_commitment_sha256"], "EPOCH_ACTIVE_SET_PLAN")


def _artifact_identity(value):
    return {key: value[key] for key in ("schema", "content_id", "artifact_sha256", "size_bytes", "database_schema_version")}


def _plan_identity(value):
    # Transport bytes bind the transition hash.  Epoch identity uses the
    # logical plan commitment; including the future descriptor hash would
    # make plan -> artifact -> epoch_id -> transition -> plan cyclic.
    return {key: value[key] for key in ("schema", "plan_commitment_sha256", "recovery_commitment_sha256")}


def epoch_identity(value):
    """The locator-free, non-circular identity view for an epoch transition."""
    return {"schema": value["schema"], "contract_revision": value["contract_revision"],
            "epoch_number": value["epoch_number"], "accepted_anchor": value["accepted_anchor"],
            "bridge_predecessor": value["bridge_predecessor"],
            "bridge_binding_sha256": value["bridge_binding_sha256"],
            "candidate_source": {"source_binding": value["source_binding"], "source_cut": value["source_cut"]},
            "active_artifact": _artifact_identity(value["active_artifact"]),
            "active_set_plan": _plan_identity(value["active_set_plan"]),
            "archive": {key: value["archive"][key] for key in ("archive_id", "artifact_sha256", "size_bytes", "database_schema_version", "previous_epoch_id", "previous_manifest_sha256", "previous_bridge_binding_sha256", "archive_commitment_sha256")},
            "capacity_policy": {**value["active_epoch"], "selection_policy_version": value["retained_floor_commitment"]["selection_policy_version"]},
            "retained_floor_commitment_sha256": value["retained_floor_commitment"]["retained_floor_commitment_sha256"],
            "omission_commitment_sha256": value["retained_floor_commitment"]["omitted_history_sha256"]}


def derive_epoch_id(value):
    return "se2:" + commitment("epoch-id", epoch_identity(value))


def build_first_transition(accepted_anchor, bridge_predecessor, archive, active_artifact,
                           active_set_plan, retained_floor_commitment, active_epoch,
                           created_at):
    """Pure construction of the first, still-unpublished compact V2 transition."""
    _descriptor(accepted_anchor); _descriptor(bridge_predecessor); _archive(archive)
    _active_artifact(active_artifact); _active_set_plan(active_set_plan)
    _floors(retained_floor_commitment); _obj(active_epoch, ACTIVE)
    if type(created_at) is not str or not _TIME.match(created_at):
        _fail("EPOCH_TIMESTAMP", "timestamp is not canonical UTC RFC3339")
    binding = commitment("a1-bridge-binding", {"accepted_anchor": accepted_anchor,
                                                 "bridge_predecessor": bridge_predecessor})
    source_binding = first_transition_source_binding(bridge_predecessor, binding)
    source_cut = first_transition_source_cut(source_binding, bridge_predecessor, binding)
    value = {"schema": SCHEMA, "contract_revision": REVISION, "epoch_number": 1,
             "epoch_id": "se2:pending", "created_at": created_at,
             "source_binding": source_binding, "source_cut": source_cut,
             "accepted_anchor": accepted_anchor, "bridge_predecessor": bridge_predecessor,
             "bridge_binding_sha256": binding, "active_artifact": active_artifact,
             "active_set_plan": active_set_plan, "archive": archive,
             "retained_floor_commitment": retained_floor_commitment,
             "active_epoch": active_epoch}
    checks = {"accepted_anchor_sha256": commitment("accepted-anchor", accepted_anchor),
              "bridge_predecessor_sha256": commitment("bridge-predecessor", bridge_predecessor),
              "bridge_binding_sha256": binding,
              "archive_descriptor_sha256": commitment("archive-descriptor", _without(archive, "archive_commitment_sha256")),
              "active_artifact_descriptor_sha256": commitment("active-artifact-descriptor", active_artifact),
              "active_set_plan_descriptor_sha256": commitment("active-set-plan-descriptor", active_set_plan),
              "retained_floor_declaration_sha256": retained_floor_commitment["retained_floor_commitment_sha256"],
              "mandatory_closure_sha256": retained_floor_commitment["mandatory_proof_closure_sha256"],
              "durable_qualification_history_sha256": retained_floor_commitment["durable_qualification_history_sha256"],
              "coverage_witnesses_sha256": retained_floor_commitment["coverage_witnesses_sha256"],
              "permanent_pinned_evidence_sha256": retained_floor_commitment["permanent_pinned_evidence_sha256"]}
    value["commitments"] = dict(checks, transition_sha256="0" * 64)
    value["epoch_id"] = derive_epoch_id(value)
    complete = _without(value, "commitments")
    complete["commitments"] = _without(value["commitments"], "transition_sha256")
    value["commitments"]["transition_sha256"] = commitment("complete-transition", complete)
    validate_transition(value, accepted_anchor, 0, True)
    return value


def _plan_bounded(value, depth=0):
    if depth > MAX_DEPTH:
        _fail("EPOCH_PLAN_NESTING", "plan nesting exceeds the limit")
    if value is None or type(value) is bool or type(value) is int:
        _bounded(value, depth); return
    if type(value) is str:
        _bounded(value, depth); return
    if type(value) is list:
        if len(value) > MAX_PLAN_RECORDS:
            _fail("EPOCH_PLAN_BOUNDS", "plan array exceeds the record limit")
        for item in value: _plan_bounded(item, depth + 1)
        return
    if type(value) is dict:
        if len(value) > MAX_MAP_ITEMS: _fail("EPOCH_PLAN_BOUNDS", "plan object exceeds the field limit")
        for key, item in value.items():
            if type(key) is not str: _fail("EPOCH_PLAN_TYPE", "plan object key must be a string")
            _plan_bounded(key, depth + 1); _plan_bounded(item, depth + 1)
        return
    _fail("EPOCH_PLAN_TYPE", "unsupported plan value")


def parse_active_set_plan(data):
    if type(data) is not bytes or not 1 <= len(data) <= MAX_PLAN_BYTES:
        _fail("EPOCH_PLAN_BOUNDS", "plan bytes exceed the limit")
    try:
        value = json.loads(data.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                           parse_float=_number, parse_constant=_number)
    except V2ValidationError: raise
    except (TypeError, ValueError, json.JSONDecodeError): _fail("EPOCH_PLAN_JSON", "invalid plan JSON")
    _plan_bounded(value)
    return value


def active_set_plan_commitment(value):
    """Large-plan commitment; unlike generic wire objects it permits 50k rows."""
    _plan_bounded(value)
    return hashlib.sha256(b"flop-scout/epoch-v2/active-set-plan\0" +
                          json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                                     allow_nan=False).encode("ascii")).hexdigest()


def bounded_commitment(domain, value):
    """Commit a canonical set which Router independently reconstructs at acceptance."""
    if type(domain) is not str or not re.match(r"^[a-z][a-z0-9-]{0,63}$", domain):
        _fail("EPOCH_DOMAIN", "invalid commitment domain")
    _plan_bounded(value)
    if type(value) is not list:
        _fail("EPOCH_FLOOR_BOUNDS", "compact commitment value must be a list")
    identities = [json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                             allow_nan=False).encode("ascii") for item in value]
    if identities != sorted(identities) or len(identities) != len(set(identities)):
        _fail("EPOCH_FLOOR_ORDER", "compact commitment values must be sorted and unique")
    return hashlib.sha256(("flop-scout/epoch-v2/" + domain).encode("ascii") + b"\0" +
                          json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                                     allow_nan=False).encode("ascii")).hexdigest()


def compact_retained_floor(entries, selection_policy_version, sets):
    """Create the compact V2 floor binding from independently reconstructable sets."""
    domains = (("mandatory_proof_closure", "mandatory-closure"),
               ("durable_qualification_history", "durable-qualification-history"),
               ("coverage_witnesses", "coverage-witnesses"),
               ("permanent_pinned_evidence", "permanent-pinned-evidence"),
               ("omitted_history", "omitted-history"))
    if type(sets) is not dict or set(sets) != {name for name, _ in domains}:
        _fail("EPOCH_RETAINED_FLOOR", "compact retained-floor sets are incomplete")
    value = {"entries": entries, "selection_policy_version": selection_policy_version}
    for name, domain in domains:
        rows = sets[name]
        if type(rows) is not list or len(rows) > MAX_PLAN_RECORDS:
            _fail("EPOCH_FLOOR_BOUNDS", "compact retained-floor set exceeds the limit")
        value[name + "_count"] = len(rows)
        value[name + "_sha256"] = bounded_commitment(domain, rows)
    value["retained_floor_commitment_sha256"] = commitment(
        "retained-floor-declaration", value)
    _floors(value)
    return value


def _plan_record(value):
    _obj(value, PLAN_RECORD, "EPOCH_PLAN_RECORD")
    _id(value["projection_row_id"], "EPOCH_PLAN_RECORD"); _hash(value["raw_record_id"], "EPOCH_PLAN_RECORD")
    _hash(value["raw_text_sha256"], "EPOCH_PLAN_RECORD")
    if type(value["scout_event_id"]) is not str or not re.match(r"^[0-9]+$", value["scout_event_id"]):
        _fail("EPOCH_PLAN_RECORD", "plan event id must be canonical decimal digits")
    if type(value["reasons"]) is not list or not value["reasons"] or value["reasons"] != sorted(set(value["reasons"])):
        _fail("EPOCH_PLAN_RECORD", "plan reasons must be sorted and nonempty")
    for reason in value["reasons"]: _id(reason, "EPOCH_PLAN_RECORD")


def _plan_commitment_view(value):
    return _without(value, "plan_commitment_sha256")


def validate_active_set_plan(value, transition):
    """Validate a bounded, redacted plan sidecar against its transition."""
    _plan_bounded(value); _obj(value, PLAN, "EPOCH_PLAN_FIELDS")
    if value["schema"] != "flop-scout-epoch-active-set-plan/v1": _fail("EPOCH_PLAN_SCHEMA", "unsupported plan schema")
    _text(value["selection_policy_version"], "EPOCH_PLAN_BINDING")
    if value["candidate_source"] != {"source_binding": transition["source_binding"], "source_cut": transition["source_cut"]}: _fail("EPOCH_PLAN_BINDING", "plan source differs")
    checks = {"archive_descriptor_sha256": commitment("archive-descriptor", _without(transition["archive"], "archive_commitment_sha256")), "recovery_commitment_sha256": transition["active_set_plan"]["recovery_commitment_sha256"], "retained_floor_commitment_sha256": transition["retained_floor_commitment"]["retained_floor_commitment_sha256"], "omission_commitment_sha256": transition["retained_floor_commitment"]["omitted_history_sha256"], "capacity": transition["active_epoch"]}
    for key, expected in checks.items():
        if value[key] != expected: _fail("EPOCH_PLAN_BINDING", "plan commitment differs")
    selected, omitted = value["selected"], value["omitted"]
    if type(selected) is not list or type(omitted) is not list or len(selected) + len(omitted) > MAX_PLAN_RECORDS:
        _fail("EPOCH_PLAN_BOUNDS", "plan record count exceeds the limit")
    records = []
    for item in selected + omitted: _plan_record(item); records.append(item)
    ids = [item["raw_record_id"] for item in records]
    if len(ids) != len(set(ids)) or value["counts"] != {"selected": len(selected), "omitted": len(omitted), "eligible": len(records)}:
        _fail("EPOCH_PLAN_COUNTS", "plan records are duplicate or counts differ")
    _hash(value["plan_commitment_sha256"], "EPOCH_PLAN_COMMITMENT")
    if value["plan_commitment_sha256"] != active_set_plan_commitment(_plan_commitment_view(value)):
        _fail("EPOCH_PLAN_COMMITMENT", "plan commitment mismatch")
    return value


def validate_active_set_plan_bytes(data, transition):
    """Bind plan transport bytes and its logical contents to a transition."""
    _active_set_plan(transition["active_set_plan"])
    if len(data) != transition["active_set_plan"]["size_bytes"] or hashlib.sha256(data).hexdigest() != transition["active_set_plan"]["sha256"]:
        _fail("EPOCH_PLAN_BYTES", "plan bytes differ from transition descriptor")
    value = validate_active_set_plan(parse_active_set_plan(data), transition)
    if value["plan_commitment_sha256"] != transition["active_set_plan"]["plan_commitment_sha256"]:
        _fail("EPOCH_PLAN_BINDING", "plan logical commitment differs")
    return value


def validate_v2_manifest(value, transition):
    """Validate the content-only V2 manifest-to-transition binding."""
    _bounded(value); _obj(value, MANIFEST, "EPOCH_MANIFEST_FIELDS")
    if value["schema"] != MANIFEST_SCHEMA or value["contract_revision"] != REVISION:
        _fail("EPOCH_MANIFEST_SCHEMA", "unsupported V2 manifest schema or revision")
    if value["publication_kind"] != "CONTENT":
        _fail("EPOCH_PUBLICATION_KIND", "V2 heartbeat or non-content publication is not permitted")
    _integer(value["snapshot_id"], "EPOCH_MANIFEST"); _integer(value["database_content_id"], "EPOCH_MANIFEST", 1)
    _locator(value["database"], "EPOCH_MANIFEST"); _hash(value["sha256"], "EPOCH_MANIFEST"); _integer(value["size_bytes"], "EPOCH_MANIFEST", 1)
    if value["database_schema_version"] != "scout-router-projection/v2": _fail("EPOCH_MANIFEST", "unsupported database schema")
    policy, digest = a1_selection_policy_binding(value["selection_policy_sha256"])
    if value["selection_policy"] != policy:
        _fail("EPOCH_MANIFEST_POLICY", "manifest selection policy is not the complete retained A1 policy")
    if value["selection_policy_sha256"] != digest:
        _fail("EPOCH_MANIFEST_POLICY", "manifest selection policy hash differs from retained A1 policy")
    sidecar = value["epoch_transition"]; _obj(sidecar, MANIFEST_TRANSITION, "EPOCH_MANIFEST_TRANSITION")
    if sidecar["schema"] != SCHEMA: _fail("EPOCH_MANIFEST_TRANSITION", "unsupported transition schema")
    _locator(sidecar["locator"], "EPOCH_MANIFEST_TRANSITION"); _hash(sidecar["sha256"], "EPOCH_MANIFEST_TRANSITION")
    _integer(sidecar["size_bytes"], "EPOCH_MANIFEST_TRANSITION", 1, MAX_INPUT_BYTES); _hash(sidecar["transition_sha256"], "EPOCH_MANIFEST_TRANSITION")
    _active_artifact(transition["active_artifact"])
    active = transition["active_artifact"]
    if {"content_id": value["database_content_id"], "locator": value["database"], "artifact_sha256": value["sha256"], "size_bytes": value["size_bytes"], "database_schema_version": value["database_schema_version"]} != {key: active[key] for key in ("content_id", "locator", "artifact_sha256", "size_bytes", "database_schema_version")}:
        _fail("EPOCH_MANIFEST_BINDING", "manifest active artifact differs from transition")
    if sidecar["transition_sha256"] != transition["commitments"]["transition_sha256"]:
        _fail("EPOCH_MANIFEST_BINDING", "manifest transition differs from sidecar")
    return value


def _floors(value):
    _obj(value, FLOORS); entries = value["entries"]
    if type(entries) is not list or len(entries) > MAX_LIST_ITEMS:
        _fail("EPOCH_FLOOR_BOUNDS", "retained-floor entries exceed the V2 limit")
    last = None
    for entry in entries:
        _obj(entry, FLOOR, "EPOCH_FLOOR_FIELDS")
        key = tuple(_text(entry[k], "EPOCH_FLOOR_FIELDS") for k in ("room", "generation", "domain"))
        if last is not None and key <= last: _fail("EPOCH_FLOOR_ORDER", "floor domains must be sorted and unique")
        last = key
        if entry["retained_floor"] is not None: _integer(entry["retained_floor"], "EPOCH_RETAINED_FLOOR")
        prior = -1
        if type(entry["omitted_ranges"]) is not list: _fail("EPOCH_OMISSION_BOUNDS", "omission ranges must be a list")
        for pair in entry["omitted_ranges"]:
            if type(pair) is not list or len(pair) != 2: _fail("EPOCH_OMISSION_RANGE", "omission range is invalid")
            start = _integer(pair[0], "EPOCH_OMISSION_RANGE"); end = _integer(pair[1], "EPOCH_OMISSION_RANGE", start)
            if start <= prior: _fail("EPOCH_OMISSION_ORDER", "omission ranges must be sorted and disjoint")
            prior = end
    _text(value["selection_policy_version"])
    pairs = (("mandatory_proof_closure_count", "mandatory_proof_closure_sha256"), ("durable_qualification_history_count", "durable_qualification_history_sha256"), ("coverage_witnesses_count", "coverage_witnesses_sha256"), ("permanent_pinned_evidence_count", "permanent_pinned_evidence_sha256"), ("omitted_history_count", "omitted_history_sha256"))
    for count, digest in pairs:
        _integer(value[count], "EPOCH_FLOOR_BOUNDS", 0, MAX_PLAN_RECORDS)
        _hash(value[digest])
    _hash(value["retained_floor_commitment_sha256"])
    if value["retained_floor_commitment_sha256"] != commitment("retained-floor-declaration", _without(value, "retained_floor_commitment_sha256")):
        _fail("EPOCH_RETAINED_FLOOR", "retained-floor commitment mismatch")


def validate_transition(value, accepted_anchor, accepted_epoch_number=0, first_transition=False,
                        publication_kind="CONTENT"):
    """Pure public-wire validation; Router verifies a cumulative bridge locally."""
    if publication_kind != "CONTENT":
        _fail("EPOCH_PUBLICATION_KIND", "V2 heartbeat or non-content publication is not permitted")
    _bounded(value); _obj(value, TRANSITION)
    if value["schema"] != SCHEMA or value["contract_revision"] != REVISION: _fail("EPOCH_SCHEMA", "unsupported epoch schema or revision")
    epoch = _integer(value["epoch_number"], "EPOCH_NUMBER", 1, MAX_EPOCH); _id(value["epoch_id"])
    if type(value["created_at"]) is not str or not _TIME.match(value["created_at"]): _fail("EPOCH_TIMESTAMP", "timestamp is not canonical UTC RFC3339")
    source = value["source_binding"]; _obj(source, ("source_id", "epoch", "descriptor_sha256")); _id(source["source_id"]); _id(source["epoch"]); _hash(source["descriptor_sha256"])
    _cut(value["source_cut"])
    if (value["source_cut"]["source_id"], value["source_cut"]["epoch"]) != (source["source_id"], source["epoch"]): _fail("EPOCH_SOURCE_BINDING", "source cut does not match source binding")
    anchor=value["accepted_anchor"]; bridge=value["bridge_predecessor"]; _descriptor(anchor); _descriptor(bridge)
    if type(accepted_anchor) is not dict or anchor != accepted_anchor: _fail("EPOCH_ACCEPTED_ANCHOR", "candidate does not match Router accepted anchor")
    _hash(value["bridge_binding_sha256"], "EPOCH_BRIDGE_BINDING")
    expected=commitment("a1-bridge-binding", {"accepted_anchor":anchor,"bridge_predecessor":bridge})
    if value["bridge_binding_sha256"] != expected: _fail("EPOCH_BRIDGE_BINDING", "bridge identity binding mismatch")
    if type(accepted_epoch_number) is not int or epoch != accepted_epoch_number + 1: _fail("EPOCH_REGRESSION", "epoch number is not next accepted epoch")
    if (anchor["source_kind"],anchor["source_id"]) != (bridge["source_kind"],bridge["source_id"]) or anchor["source_cut"] > bridge["source_cut"]: _fail("EPOCH_BRIDGE_SOURCE", "bridge source regressed or changed")
    if (source["epoch"],source["source_id"]) != (bridge["source_kind"],bridge["source_id"]): _fail("EPOCH_SOURCE_BINDING", "candidate source identity differs from bridge")
    if value["source_cut"]["committed_event_id"] < bridge["source_cut"]: _fail("EPOCH_SOURCE_CUT", "source cut regressed")
    if first_transition:
        if epoch != 1: _fail("EPOCH_FIRST_TRANSITION", "first transition must begin epoch one")
        expected_source = first_transition_source_binding(bridge, expected)
        if source != expected_source: _fail("EPOCH_SOURCE_DESCRIPTOR", "first-transition source binding differs from bridge authority")
        if value["source_cut"]["committed_event_id"] != bridge["source_cut"]:
            _fail("EPOCH_FIRST_SOURCE_CUT", "first transition must use the bridge source cut")
        if value["source_cut"] != first_transition_source_cut(source, bridge, expected):
            _fail("EPOCH_SOURCE_CUT_EVIDENCE", "first-transition source cut evidence differs from bridge authority")
    _active_artifact(value["active_artifact"])
    _active_set_plan(value["active_set_plan"])
    _archive(value["archive"])
    if value["archive"]["previous_manifest_sha256"] != bridge["manifest_sha256"] or value["archive"]["previous_bridge_binding_sha256"] != expected: _fail("EPOCH_ARCHIVE_BINDING", "archive is not bound to bridge predecessor")
    _floors(value["retained_floor_commitment"])
    active = value["active_epoch"]; _obj(active, ACTIVE)
    target = _integer(active["target"], "EPOCH_CAPACITY", 1, 50000); headroom = _integer(active["headroom"], "EPOCH_CAPACITY", 1, 50000); reserve = _integer(active["reserve"], "EPOCH_CAPACITY", 0, 50000); hard_max = _integer(active["hard_max"], "EPOCH_CAPACITY", 1, 50000); mandatory = _integer(active["mandatory_closure_count"], "EPOCH_CAPACITY", 0, 50000)
    if hard_max != 50000 or target + headroom + reserve > hard_max or mandatory > target: _fail("EPOCH_CAPACITY", "invalid target, headroom, reserve, or mandatory closure")
    if value["epoch_id"] != derive_epoch_id(value): _fail("EPOCH_ID", "epoch identity binding mismatch")
    checks = {"accepted_anchor_sha256": commitment("accepted-anchor", anchor), "bridge_predecessor_sha256": commitment("bridge-predecessor", bridge), "bridge_binding_sha256": expected, "archive_descriptor_sha256": commitment("archive-descriptor", _without(value["archive"], "archive_commitment_sha256")), "active_artifact_descriptor_sha256": commitment("active-artifact-descriptor", value["active_artifact"]), "active_set_plan_descriptor_sha256": commitment("active-set-plan-descriptor", value["active_set_plan"]), "retained_floor_declaration_sha256": commitment("retained-floor-declaration", _without(value["retained_floor_commitment"], "retained_floor_commitment_sha256")), "mandatory_closure_sha256": value["retained_floor_commitment"]["mandatory_proof_closure_sha256"], "durable_qualification_history_sha256": value["retained_floor_commitment"]["durable_qualification_history_sha256"], "coverage_witnesses_sha256": value["retained_floor_commitment"]["coverage_witnesses_sha256"], "permanent_pinned_evidence_sha256": value["retained_floor_commitment"]["permanent_pinned_evidence_sha256"]}
    _obj(value["commitments"], COMMITMENTS)
    for key, digest in checks.items():
        _hash(value["commitments"][key])
        if value["commitments"][key] != digest: _fail("EPOCH_COMMITMENT", "top-level commitment mismatch")
    _hash(value["commitments"]["transition_sha256"])
    complete = _without(value, "commitments"); complete["commitments"] = _without(value["commitments"], "transition_sha256")
    if value["commitments"]["transition_sha256"] != commitment("complete-transition", complete): _fail("EPOCH_TRANSITION_HASH", "transition commitment mismatch")
    return {"epoch_id": value["epoch_id"], "epoch_number": epoch, "source_cut": value["source_cut"]["committed_event_id"], "active_target": target}


# Fresh-cut/continuation model.  This is deliberately additive: the historical
# A1 bridge validator above remains byte-for-byte and behaviorally unchanged.
FRESH_SNAPSHOT = ("schema", "locator", "sha256", "size_bytes", "sqlite_schema_sha256", "semantic_checkpoint_sha256")
FRESH_FIRST_PAYLOAD = ("schema", "publication_id", "content_id", "source_id", "source_epoch", "source_cut", "created_at", "selection_policy_sha256", "archive", "plan", "active_artifact", "retained_floor", "accepted_anchor", "bridge_predecessor", "bridge_binding_sha256", "fresh_cut_authority", "epoch_id")
SUCCESSOR_PAYLOAD = ("schema", "publication_id", "content_id", "source_id", "source_epoch", "source_cut", "created_at", "selection_policy_sha256", "archive", "plan", "active_artifact", "retained_floor", "predecessor", "epoch_id")
FRESH_AUTHORITY = ("schema", "source_id", "epoch", "committed_event_id", "snapshot", "snapshot_checkpoint_sha256", "bridge_binding_sha256", "authority_sha256")
FRESH_FIRST = ("schema", "payload", "transition_sha256")
SUCCESSOR = ("schema", "payload", "transition_sha256")
PREDECESSOR = ("schema", "publication_id", "content_id", "epoch_id", "manifest_sha256", "transition_sha256", "artifact_sha256", "artifact_size", "source_id", "source_epoch", "source_cut", "selection_policy_sha256", "archive_commitment_sha256", "retained_floor_commitment_sha256")


def fresh_cut_authority_commitment(value):
    fields=tuple(item for item in FRESH_AUTHORITY if item != "authority_sha256")
    _obj(value, fields if "authority_sha256" not in value else FRESH_AUTHORITY, "EPOCH_FRESH_AUTHORITY_FIELDS")
    body=dict(value); body.pop("authority_sha256", None)
    return commitment("fresh-cut-authority", body)


def fresh_first_payload_identity(value):
    _obj(value, FRESH_FIRST_PAYLOAD, "EPOCH_FRESH_PAYLOAD_FIELDS")
    return commitment("fresh-first-payload", {k:v for k,v in value.items() if k != "epoch_id"})


def successor_payload_identity(value):
    _obj(value, SUCCESSOR_PAYLOAD, "EPOCH_SUCCESSOR_PAYLOAD_FIELDS")
    return commitment("content-successor-payload", {k:v for k,v in value.items() if k != "epoch_id"})


def validate_active_artifact_bytes(descriptor, data):
    _active_artifact(descriptor)
    if type(data) is not bytes or len(data) != descriptor["size_bytes"] or hashlib.sha256(data).hexdigest() != descriptor["artifact_sha256"]: _fail("EPOCH_ARTIFACT_BYTES", "artifact transport differs")
    return descriptor


def validate_plan_descriptor_bytes(descriptor, data):
    _active_set_plan(descriptor)
    if type(data) is not bytes or len(data) != descriptor["size_bytes"] or hashlib.sha256(data).hexdigest() != descriptor["sha256"]: _fail("EPOCH_PLAN_BYTES", "plan transport differs")
    plan=parse_active_set_plan(data)
    if plan["plan_commitment_sha256"] != descriptor["plan_commitment_sha256"] or active_set_plan_commitment(_without(plan,"plan_commitment_sha256")) != descriptor["plan_commitment_sha256"]: _fail("EPOCH_PLAN_COMMITMENT", "plan logical commitment differs")
    return plan


def validate_archive_descriptor_bytes(descriptor, data):
    _archive(descriptor)
    if type(data) is not bytes or len(data) != descriptor["size_bytes"] or hashlib.sha256(data).hexdigest() != descriptor["artifact_sha256"]: _fail("EPOCH_ARCHIVE_BYTES", "archive transport differs")
    if descriptor["archive_commitment_sha256"] != commitment("archive-descriptor", _without(descriptor,"archive_commitment_sha256")): _fail("EPOCH_ARCHIVE_HASH", "archive commitment differs")
    return descriptor


def validate_successor_predecessor(value):
    _obj(value, PREDECESSOR, "EPOCH_SUCCESSOR_PREDECESSOR")
    if value["schema"] != "flop-scout-epoch-accepted-predecessor/v1": _fail("EPOCH_SUCCESSOR_PREDECESSOR", "unsupported predecessor")
    for key in ("publication_id","content_id","artifact_size","source_cut"): _integer(value[key], "EPOCH_SUCCESSOR_PREDECESSOR", 1)
    for key in ("manifest_sha256","transition_sha256","artifact_sha256","selection_policy_sha256","archive_commitment_sha256","retained_floor_commitment_sha256"): _hash(value[key], "EPOCH_SUCCESSOR_PREDECESSOR")
    _id(value["epoch_id"], "EPOCH_SUCCESSOR_PREDECESSOR"); _id(value["source_id"], "EPOCH_SUCCESSOR_PREDECESSOR"); _id(value["source_epoch"], "EPOCH_SUCCESSOR_PREDECESSOR")
    return value


def validate_fresh_first_payload(value):
    _obj(value, FRESH_FIRST_PAYLOAD, "EPOCH_FRESH_PAYLOAD_FIELDS")
    if value["schema"] != "flop-scout-epoch-fresh-first-payload/v1": _fail("EPOCH_FRESH_PAYLOAD_SCHEMA", "unsupported fresh payload")
    for key in ("publication_id","content_id","source_cut"): _integer(value[key], "EPOCH_FRESH_PAYLOAD", 1)
    _id(value["source_id"], "EPOCH_FRESH_PAYLOAD"); _id(value["source_epoch"], "EPOCH_FRESH_PAYLOAD"); _hash(value["selection_policy_sha256"], "EPOCH_FRESH_PAYLOAD")
    _descriptor(value["accepted_anchor"]); _descriptor(value["bridge_predecessor"]); _hash(value["bridge_binding_sha256"]); _active_artifact(value["active_artifact"]); _active_set_plan(value["plan"]); _archive(value["archive"]); _floors(value["retained_floor"])
    validate_fresh_cut_authority(value["fresh_cut_authority"], value["bridge_predecessor"], value["bridge_binding_sha256"])
    if value["source_cut"] != value["fresh_cut_authority"]["committed_event_id"]: _fail("EPOCH_FRESH_CUT", "payload cut differs")
    expected="se2:"+fresh_first_payload_identity(value)
    if value["epoch_id"] != expected: _fail("EPOCH_FRESH_EPOCH", "payload epoch differs")
    return value


def validate_successor_payload(value, predecessor):
    _obj(value, SUCCESSOR_PAYLOAD, "EPOCH_SUCCESSOR_PAYLOAD_FIELDS")
    if value["schema"] != "flop-scout-epoch-content-successor-payload/v1": _fail("EPOCH_SUCCESSOR_PAYLOAD_SCHEMA", "unsupported successor payload")
    for key in ("publication_id","content_id","source_cut"): _integer(value[key], "EPOCH_SUCCESSOR_PAYLOAD", 1)
    if value["predecessor"] != predecessor: _fail("EPOCH_SUCCESSOR_GAP", "predecessor differs")
    if value["epoch_id"] != predecessor["epoch_id"]: _fail("EPOCH_SUCCESSOR_EPOCH", "epoch differs")
    if value["publication_id"] <= predecessor["publication_id"] or value["content_id"] <= predecessor["content_id"] or value["source_cut"] <= predecessor["source_cut"]: _fail("EPOCH_SUCCESSOR_ROLLBACK", "successor did not advance")
    for key in ("source_id", "source_epoch", "selection_policy_sha256"):
        if value[key] != predecessor[key]:
            _fail("EPOCH_SUCCESSOR_CONTINUITY", "protected identity differs")
    if (value["archive"]["archive_commitment_sha256"] !=
            predecessor["archive_commitment_sha256"]):
        _fail("EPOCH_SUCCESSOR_CONTINUITY", "archive identity differs")
    if (value["retained_floor"]["retained_floor_commitment_sha256"] !=
            predecessor["retained_floor_commitment_sha256"]):
        _fail("EPOCH_SUCCESSOR_CONTINUITY", "retained-floor identity differs")
    _active_artifact(value["active_artifact"]); _active_set_plan(value["plan"])
    return value


def validate_fresh_cut_authority(value, bridge_predecessor, bridge_binding_sha256):
    _obj(value, FRESH_AUTHORITY, "EPOCH_FRESH_AUTHORITY_FIELDS")
    if value["schema"] != "flop-scout-epoch-fresh-cut-authority/v1": _fail("EPOCH_FRESH_AUTHORITY_SCHEMA", "unsupported fresh authority")
    _id(value["source_id"], "EPOCH_FRESH_AUTHORITY"); _id(value["epoch"], "EPOCH_FRESH_AUTHORITY")
    _integer(value["committed_event_id"], "EPOCH_FRESH_AUTHORITY", 1)
    _obj(value["snapshot"], FRESH_SNAPSHOT, "EPOCH_FRESH_SNAPSHOT_FIELDS")
    snapshot=value["snapshot"]
    if snapshot["schema"] != "flop-scout-epoch-source-snapshot/v1": _fail("EPOCH_FRESH_SNAPSHOT_SCHEMA", "unsupported source snapshot")
    _locator(snapshot["locator"], "EPOCH_FRESH_SNAPSHOT"); _hash(snapshot["sha256"], "EPOCH_FRESH_SNAPSHOT")
    _integer(snapshot["size_bytes"], "EPOCH_FRESH_SNAPSHOT", 1, MAX_INPUT_BYTES)
    _hash(snapshot["sqlite_schema_sha256"], "EPOCH_FRESH_SNAPSHOT"); _hash(snapshot["semantic_checkpoint_sha256"], "EPOCH_FRESH_SNAPSHOT")
    _hash(value["snapshot_checkpoint_sha256"], "EPOCH_FRESH_AUTHORITY"); _hash(value["bridge_binding_sha256"], "EPOCH_FRESH_AUTHORITY"); _hash(value["authority_sha256"], "EPOCH_FRESH_AUTHORITY")
    if value["snapshot_checkpoint_sha256"] != snapshot["semantic_checkpoint_sha256"]: _fail("EPOCH_FRESH_CHECKPOINT", "snapshot checkpoint differs")
    if value["bridge_binding_sha256"] != bridge_binding_sha256: _fail("EPOCH_FRESH_BRIDGE", "bridge binding differs")
    if (value["source_id"],value["epoch"]) != (bridge_predecessor["source_id"],bridge_predecessor["source_kind"]): _fail("EPOCH_FRESH_SOURCE", "fresh source identity differs")
    if value["committed_event_id"] <= bridge_predecessor["source_cut"]: _fail("EPOCH_FRESH_CUT", "fresh cut must exceed bridge cut")
    if value["authority_sha256"] != fresh_cut_authority_commitment(value): _fail("EPOCH_FRESH_AUTHORITY", "fresh authority commitment differs")
    return value


def validate_fresh_first_transition(value, accepted_anchor, now=None, max_age=3600):
    _obj(value, FRESH_FIRST, "EPOCH_FRESH_FIRST_FIELDS")
    if value["schema"] != "flop-scout-epoch-fresh-first-transition/v1": _fail("EPOCH_FRESH_FIRST_SCHEMA", "unsupported fresh first transition")
    payload=validate_fresh_first_payload(value["payload"])
    if payload["accepted_anchor"] != accepted_anchor: _fail("EPOCH_FRESH_PREDECESSOR", "accepted anchor differs")
    if value["transition_sha256"] != commitment("fresh-first-transition", payload): _fail("EPOCH_FRESH_TRANSITION", "fresh transition commitment differs")
    return payload


def validate_content_successor(value, accepted_transition):
    _obj(value, SUCCESSOR, "EPOCH_SUCCESSOR_FIELDS")
    if value["schema"] != "flop-scout-epoch-content-successor/v1": _fail("EPOCH_SUCCESSOR_SCHEMA", "unsupported successor")
    predecessor=validate_successor_predecessor(accepted_transition)
    payload=validate_successor_payload(value["payload"], predecessor)
    if value["transition_sha256"] != commitment("content-successor-transition", payload): _fail("EPOCH_SUCCESSOR_TRANSITION", "successor transition commitment differs")
    return payload


def build_fresh_first_transition(*, publication_id, content_id, source_id, source_epoch, source_cut,
                                 created_at, selection_policy_sha256, snapshot, snapshot_bytes,
                                 archive, archive_bytes, plan, plan_bytes, active_artifact,
                                 active_artifact_bytes, retained_floor, accepted_anchor,
                                 bridge_predecessor):
    """Build the minimal dedicated fresh-root; all commitments are owned here."""
    _integer(publication_id,"EPOCH_FRESH_PAYLOAD",1); _integer(content_id,"EPOCH_FRESH_PAYLOAD",1); _integer(source_cut,"EPOCH_FRESH_PAYLOAD",1)
    _id(source_id,"EPOCH_FRESH_PAYLOAD"); _id(source_epoch,"EPOCH_FRESH_PAYLOAD"); _hash(selection_policy_sha256,"EPOCH_FRESH_PAYLOAD")
    validate_archive_descriptor_bytes(archive, archive_bytes); validate_plan_descriptor_bytes(plan, plan_bytes); validate_active_artifact_bytes(active_artifact, active_artifact_bytes)
    _floors(retained_floor); _descriptor(accepted_anchor); _descriptor(bridge_predecessor)
    binding=commitment("a1-bridge-binding", {"accepted_anchor":accepted_anchor,"bridge_predecessor":bridge_predecessor})
    authority={"schema":"flop-scout-epoch-fresh-cut-authority/v1","source_id":source_id,"epoch":source_epoch,"committed_event_id":source_cut,"snapshot":snapshot,"snapshot_checkpoint_sha256":snapshot["semantic_checkpoint_sha256"],"bridge_binding_sha256":binding}
    authority["authority_sha256"]=fresh_cut_authority_commitment(authority)
    validate_fresh_cut_authority(authority,bridge_predecessor,binding)
    payload={"schema":"flop-scout-epoch-fresh-first-payload/v1","publication_id":publication_id,"content_id":content_id,"source_id":source_id,"source_epoch":source_epoch,"source_cut":source_cut,"created_at":created_at,"selection_policy_sha256":selection_policy_sha256,"archive":archive,"plan":plan,"active_artifact":active_artifact,"retained_floor":retained_floor,"accepted_anchor":accepted_anchor,"bridge_predecessor":bridge_predecessor,"bridge_binding_sha256":binding,"fresh_cut_authority":authority,"epoch_id":"se2:pending"}
    payload["epoch_id"]="se2:"+fresh_first_payload_identity(payload)
    root={"schema":"flop-scout-epoch-fresh-first-transition/v1","payload":payload}
    root["transition_sha256"]=commitment("fresh-first-transition",payload)
    validate_fresh_first_transition(root,accepted_anchor)
    return root


def build_content_successor(*, predecessor, publication_id, content_id, source_cut, created_at,
                            plan, plan_bytes, active_artifact, active_artifact_bytes,
                            archive, archive_bytes, retained_floor):
    """Build a same-epoch CONTENT successor from its accepted closed identity."""
    predecessor=validate_successor_predecessor(predecessor)
    validate_archive_descriptor_bytes(archive,archive_bytes); validate_plan_descriptor_bytes(plan,plan_bytes); validate_active_artifact_bytes(active_artifact,active_artifact_bytes); _floors(retained_floor)
    payload={"schema":"flop-scout-epoch-content-successor-payload/v1","publication_id":publication_id,"content_id":content_id,"source_id":predecessor["source_id"],"source_epoch":predecessor["source_epoch"],"source_cut":source_cut,"created_at":created_at,"selection_policy_sha256":predecessor["selection_policy_sha256"],"archive":archive,"plan":plan,"active_artifact":active_artifact,"retained_floor":retained_floor,"predecessor":predecessor,"epoch_id":predecessor["epoch_id"]}
    root={"schema":"flop-scout-epoch-content-successor/v1","payload":payload}
    root["transition_sha256"]=commitment("content-successor-transition",payload)
    validate_content_successor(root,predecessor)
    return root
