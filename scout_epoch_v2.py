"""Pure, bounded V2 epoch-rollover model and validator.

No file, database, clock, environment, network, signature, or publication I/O.
"""
import hashlib
import json
import re

SCHEMA = "flop-scout-router-epoch-rollover/v2"
REVISION = "A1-EPOCH-V2"
MAX_INPUT_BYTES, MAX_DEPTH, MAX_STRING_BYTES = 65536, 16, 4096
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
FLOOR = ("room", "generation", "domain", "retained_floor", "omitted_ranges")
FLOORS = ("entries", "selection_policy_version", "mandatory_proof_closure", "mandatory_proof_closure_sha256", "durable_qualification_history", "durable_qualification_history_sha256", "coverage_witnesses", "coverage_witnesses_sha256", "permanent_pinned_evidence", "permanent_pinned_evidence_sha256", "omitted_history", "omitted_history_sha256", "retained_floor_commitment_sha256")
ACTIVE = ("target", "headroom", "reserve", "hard_max", "mandatory_closure_count")
COMMITMENTS = ("accepted_anchor_sha256", "bridge_predecessor_sha256", "bridge_binding_sha256", "archive_descriptor_sha256", "retained_floor_declaration_sha256", "mandatory_closure_sha256", "durable_qualification_history_sha256", "coverage_witnesses_sha256", "permanent_pinned_evidence_sha256", "transition_sha256")
TRANSITION = ("schema", "contract_revision", "epoch_number", "epoch_id", "created_at", "source_binding", "source_cut", "accepted_anchor", "bridge_predecessor", "bridge_binding_sha256", "archive", "retained_floor_commitment", "active_epoch", "commitments")


def _cut(value):
    _obj(value, CUT); _id(value["source_id"]); _id(value["epoch"])
    _integer(value["committed_event_id"], "EPOCH_SOURCE_CUT"); _hash(value["cut_evidence_sha256"])


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
    pairs = (("mandatory_proof_closure", "mandatory_proof_closure_sha256", "mandatory-closure"), ("durable_qualification_history", "durable_qualification_history_sha256", "durable-qualification-history"), ("coverage_witnesses", "coverage_witnesses_sha256", "coverage-witnesses"), ("permanent_pinned_evidence", "permanent_pinned_evidence_sha256", "permanent-pinned-evidence"), ("omitted_history", "omitted_history_sha256", "omitted-history"))
    for body, digest, domain in pairs:
        _hash(value[digest])
        if value[digest] != commitment(domain, value[body]): _fail("EPOCH_COMMITMENT", "nested commitment mismatch")
    _hash(value["retained_floor_commitment_sha256"])
    if value["retained_floor_commitment_sha256"] != commitment("retained-floor-declaration", _without(value, "retained_floor_commitment_sha256")):
        _fail("EPOCH_RETAINED_FLOOR", "retained-floor commitment mismatch")


def validate_transition(value, accepted_anchor, accepted_epoch_number=0, first_transition=False):
    """Pure public-wire validation; Router verifies a cumulative bridge locally."""
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
    if first_transition and epoch != 1: _fail("EPOCH_FIRST_TRANSITION", "first transition must begin epoch one")
    _archive(value["archive"])
    if value["archive"]["previous_manifest_sha256"] != bridge["manifest_sha256"] or value["archive"]["previous_bridge_binding_sha256"] != expected: _fail("EPOCH_ARCHIVE_BINDING", "archive is not bound to bridge predecessor")
    _floors(value["retained_floor_commitment"])
    active = value["active_epoch"]; _obj(active, ACTIVE)
    target = _integer(active["target"], "EPOCH_CAPACITY", 1, 50000); headroom = _integer(active["headroom"], "EPOCH_CAPACITY", 1, 50000); reserve = _integer(active["reserve"], "EPOCH_CAPACITY", 0, 50000); hard_max = _integer(active["hard_max"], "EPOCH_CAPACITY", 1, 50000); mandatory = _integer(active["mandatory_closure_count"], "EPOCH_CAPACITY", 0, 50000)
    if hard_max != 50000 or target + headroom + reserve > hard_max or mandatory > target: _fail("EPOCH_CAPACITY", "invalid target, headroom, reserve, or mandatory closure")
    checks = {"accepted_anchor_sha256": commitment("accepted-anchor", anchor), "bridge_predecessor_sha256": commitment("bridge-predecessor", bridge), "bridge_binding_sha256": expected, "archive_descriptor_sha256": commitment("archive-descriptor", _without(value["archive"], "archive_commitment_sha256")), "retained_floor_declaration_sha256": commitment("retained-floor-declaration", _without(value["retained_floor_commitment"], "retained_floor_commitment_sha256")), "mandatory_closure_sha256": value["retained_floor_commitment"]["mandatory_proof_closure_sha256"], "durable_qualification_history_sha256": value["retained_floor_commitment"]["durable_qualification_history_sha256"], "coverage_witnesses_sha256": value["retained_floor_commitment"]["coverage_witnesses_sha256"], "permanent_pinned_evidence_sha256": value["retained_floor_commitment"]["permanent_pinned_evidence_sha256"]}
    _obj(value["commitments"], COMMITMENTS)
    for key, digest in checks.items():
        _hash(value["commitments"][key])
        if value["commitments"][key] != digest: _fail("EPOCH_COMMITMENT", "top-level commitment mismatch")
    _hash(value["commitments"]["transition_sha256"])
    complete = _without(value, "commitments"); complete["commitments"] = _without(value["commitments"], "transition_sha256")
    if value["commitments"]["transition_sha256"] != commitment("complete-transition", complete): _fail("EPOCH_TRANSITION_HASH", "transition commitment mismatch")
    return {"epoch_id": value["epoch_id"], "epoch_number": epoch, "source_cut": value["source_cut"]["committed_event_id"], "active_target": target}
