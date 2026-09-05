#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

BASE_URL = "https://technocore.chat"
HOME = Path.home() / ".flop_scout"
KEY_FILE = HOME / "identity.pem"
META_FILE = HOME / "identity.json"
LOG_FILE = HOME / "activity.jsonl"
DOC_HASH_FILE = HOME / "doc_hashes.json"
EVIDENCE_DIR = HOME / "evidence"
EXPORTS_DIR = EVIDENCE_DIR / "exports"
OBSERVER_DB = HOME / "observer.sqlite"
USER_AGENT = "flop-scout/0.3.3"
DEFAULT_OBSERVE_ROOMS = ("lobby", "technocore")
INTERACTION_WINDOW = 5
CANONICAL_ROOM = "d-flop-scout"
MAILBOX_ROOM = "mb-flop-scout"
TCLK_OFFERS_ROOM = "tclk-offers"
KIBBLE_ROOM = "kibble"
KIBBLE_BOARD_URL = "https://flop-kibble.onrender.com/api/board"
KIBBLE_STATUS_URL = "https://flop-kibble.onrender.com/api/status"
GITHUB_URL = "https://github.com/greg2718/flop-scout"
SERVICE_ROOMS = (MAILBOX_ROOM, TCLK_OFFERS_ROOM, "technocore", "lobby")
SERVICE_POLL_PAGE_SIZE = 200
SERVICE_POLL_MAX_PAGES_PER_ROOM = 10
CONFIG_DUPLICATE_KEYS = ("dupe_filter_seconds", "dupe_max_copies", "dupe_min_length")
UNKNOWN_LEGACY_GENERATION = "UNKNOWN_LEGACY"
GENERATION_MISSING = "GENERATION_MISSING"
DEFAULT_EVIDENCE_ROOMS = (CANONICAL_ROOM, MAILBOX_ROOM)
TCLK_FRAME_PREFIX = "tclk1 "
TCLK_FRAME_TYPES = ("offer", "accept", "lock", "reveal", "refund", "cancel", "receipt")
TCLK_OBSERVED_ONLY = "OBSERVES_TCLK_DOES_NOT_ACCEPT_SETTLEMENT"
KIBBLE_EVENT_TYPES = ("JOB", "CLAIM", "RESULT", "DELIVER", "ATTEST", "ACCEPT", "WITNESS", "BRIEF")
LOCAL_OPERATOR_GROUP = "flop-labs-local"
DUPLICATE_REFUSAL_MESSAGE = """Technocore refused this message as duplicate/repeated content (HTTP 422).

The same or equivalent normalized text has recently appeared too many times
in this room.

No message was posted.
No automatic retry will be attempted.

Recommendation:
Review recent room traffic and manually decide whether there is something
genuinely new worth saying."""

B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ED25519_MULTICODEC = b"\xed\x01"


class TechnocoreDuplicateRefusal(Exception):
    def __init__(self, body: str):
        super().__init__("Technocore duplicate-content refusal")
        self.status = 422
        self.body = body


def ensure_home() -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(HOME, 0o700)
    except OSError:
        pass


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = bytearray()
    while n:
        n, r = divmod(n, 58)
        out.append(B58[r])
    zeros = len(raw) - len(raw.lstrip(b"\0"))
    enc = bytes(reversed(out)) if out else b""
    return (B58[:1] * zeros + enc).decode("ascii")


def b58decode(text: str) -> bytes:
    n = 0
    for ch in text.encode("ascii"):
        try:
            value = B58.index(ch)
        except ValueError as exc:
            raise ValueError("Invalid base58 character.") from exc
        n = n * 58 + value
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    zeros = len(text) - len(text.lstrip("1"))
    return b"\0" * zeros + raw


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_decode_canonical(text: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", text):
        raise ValueError("Invalid base64url signature characters.")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64u(raw) != text:
        raise ValueError("Non-canonical base64url signature.")
    return raw


def public_did(key: Ed25519PrivateKey) -> str:
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return "did:key:z" + b58encode(ED25519_MULTICODEC + pub)


def is_valid_ed25519_did(did: str) -> bool:
    if not re.fullmatch(r"did:key:z[1-9A-HJ-NP-Za-km-z]+", did):
        return False
    try:
        decoded = b58decode(did.removeprefix("did:key:z"))
    except ValueError:
        return False
    return decoded.startswith(ED25519_MULTICODEC) and len(decoded) == len(ED25519_MULTICODEC) + 32


def public_key_from_did(did: str) -> Ed25519PublicKey:
    if not is_valid_ed25519_did(did):
        raise ValueError("Invalid Ed25519 DID.")
    decoded = b58decode(did.removeprefix("did:key:z"))
    return Ed25519PublicKey.from_public_bytes(decoded[len(ED25519_MULTICODEC) :])


def parse_owner_note_response(raw: str | None) -> str | None:
    if raw is None:
        return None
    candidates = re.findall(r"did:key:z[1-9A-HJ-NP-Za-km-z]+", raw)
    valid = {candidate for candidate in candidates if is_valid_ed25519_did(candidate)}
    if len(valid) == 1:
        return next(iter(valid))
    if len(valid) == 0:
        raise SystemExit("Owner note response contained no valid Ed25519 DID. Treating untrusted content as invalid.")
    raise SystemExit("Owner note response contained multiple distinct valid Ed25519 DIDs. Refusing to choose one.")


def normalize_text(text: str) -> str:
    out = []
    for ch in text:
        cat = unicodedata.category(ch)
        if ch in "\r\n" or cat.startswith("C") or cat in {"Zl", "Zp"}:
            out.append(" ")
        else:
            out.append(ch)
    result = re.sub(r" +", " ", "".join(out)).strip()
    if not result:
        raise ValueError("Message is empty after normalization.")
    if len(result) > 4096:
        raise ValueError("Technocore messages must be <= 4096 characters.")
    return result


def analysis_normalize_text(text: str) -> str:
    swept = normalize_text(text).casefold()
    swept = unicodedata.normalize("NFKC", swept)
    swept = re.sub(r"https?://\S+|www\.\S+", "<url>", swept)
    swept = re.sub(r"\b\d{4,}\b", "<num>", swept)
    swept = re.sub(r" +", " ", swept).strip()
    if not swept:
        raise ValueError("Message is empty after analysis normalization.")
    return swept


def normalized_hash(text: str) -> str:
    return hashlib.sha256(analysis_normalize_text(text).encode("utf-8")).hexdigest()


def template_normalize_text(text: str) -> str:
    raw = normalize_text(text).casefold()
    raw = unicodedata.normalize("NFKC", raw)
    raw = re.sub(r"\s+[◆•†]+[\dA-Fa-f]{2,}\s*$", "", raw)
    raw = re.sub(r"\s+·{2,}\d+\s*$", "", raw)
    swept = re.sub(r"https?://\S+|www\.\S+", "<url>", raw)
    swept = re.sub(r"\s+[◆•†]+[\dA-Fa-f]{2,}\s*$", "", swept)
    swept = re.sub(r"\s+·{2,}\d+\s*$", "", swept)
    swept = re.sub(r"\bdid:key:z[1-9a-km-zA-HJ-NP-Z]{20,}\b", "<did>", swept, flags=re.I)
    swept = re.sub(r"\bdid\s+[a-z0-9]{8,}\b", "did <did>", swept, flags=re.I)
    swept = re.sub(r"\bepoch\s+\d+\b", "epoch <num>", swept, flags=re.I)
    swept = re.sub(r"[+-]?\d+(?:\.\d+)?\s*ms\b", "<num>ms", swept, flags=re.I)
    swept = re.sub(r"\b\d+(?:\.\d+)?%\b", "<num>", swept)
    swept = re.sub(r"\b[a-f0-9]{12,}\b", "<hash>", swept, flags=re.I)
    swept = re.sub(r"\b\d+(?:\.\d+)?\b", "<num>", swept)
    swept = re.sub(r" +", " ", swept).strip()
    if not swept:
        raise ValueError("Message is empty after template normalization.")
    return swept


def template_hash(text: str) -> str:
    return hashlib.sha256(template_normalize_text(text).encode("utf-8")).hexdigest()


def valid_room(room: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,47}", room):
        raise ValueError("Invalid Technocore room name.")
    return room


def log(event: str, **fields: Any) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **fields,
    }
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def save_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_meta() -> dict[str, Any]:
    if not META_FILE.exists():
        raise SystemExit("No identity found. Run: python flop_scout.py init")
    return json.loads(META_FILE.read_text(encoding="utf-8"))


def load_key() -> Ed25519PrivateKey:
    if not KEY_FILE.exists():
        raise SystemExit("No identity found. Run: python flop_scout.py init")
    password = getpass.getpass("FLOP Scout identity passphrase: ").encode("utf-8")
    try:
        key = serialization.load_pem_private_key(KEY_FILE.read_bytes(), password=password)
    except Exception as exc:
        raise SystemExit("Could not unlock identity. Check the passphrase.") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("Identity file is not an Ed25519 private key.")
    meta = load_meta()
    if public_did(key) != meta["did"]:
        raise SystemExit("Safety stop: identity key does not match stored DID.")
    return key


def init_identity() -> None:
    ensure_home()
    if KEY_FILE.exists() or META_FILE.exists():
        raise SystemExit(
            f"Identity already exists under {HOME}. Refusing to overwrite it."
        )

    print("Create a NEW passphrase only for this Technocore identity.")
    print("Never enter a wallet seed phrase or wallet password.")
    p1 = getpass.getpass("New passphrase (12+ chars): ")
    p2 = getpass.getpass("Repeat passphrase: ")
    if p1 != p2:
        raise SystemExit("Passphrases do not match.")
    if len(p1) < 12:
        raise SystemExit("Passphrase must be at least 12 characters.")

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(p1.encode("utf-8")),
    )

    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
        f.flush()
        os.fsync(f.fileno())

    did = public_did(key)
    meta = {
        "version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "did": did,
        "purpose": "Technocore identity only; not a financial wallet",
    }
    save_json(META_FILE, meta)
    log("identity_created", did=did)

    print("\nIdentity created locally.")
    print(f"DID: {did}")
    print(f"Private identity file: {KEY_FILE}")
    print("Back up identity.pem and keep its passphrase separately.")


def request_json(
    req: urllib.request.Request,
    *,
    is_write: bool = False,
    allow_missing: bool = False,
) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read(1_000_001)
    except urllib.error.HTTPError as exc:
        body = exc.read(4000).decode("utf-8", errors="replace")
        if allow_missing and exc.code == 404:
            return {}
        if is_write and exc.code == 422:
            raise TechnocoreDuplicateRefusal(body) from None
        raise SystemExit(f"Technocore HTTP {exc.code}: {body}") from None
    except Exception as exc:
        if is_write:
            raise SystemExit(
                "Technocore write outcome is uncertain. Do NOT retry immediately. "
                "Read the room first and check for your DID/nonce."
            ) from exc
        raise SystemExit(f"Technocore request failed: {exc}") from exc

    if len(raw) > 1_000_000:
        raise SystemExit("Technocore response exceeded local safety limit.")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise SystemExit("Technocore returned an invalid JSON response.") from exc
    if not isinstance(obj, dict):
        raise SystemExit("Technocore returned unexpected JSON.")
    return obj


def request_text(
    req: urllib.request.Request,
    *,
    is_write: bool = False,
    allow_missing: bool = False,
) -> str | None:
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read(1_000_001)
    except urllib.error.HTTPError as exc:
        body = exc.read(4000).decode("utf-8", errors="replace")
        if allow_missing and exc.code == 404:
            return None
        if is_write and exc.code == 422:
            raise TechnocoreDuplicateRefusal(body) from None
        if is_write:
            raise SystemExit(
                "Technocore write outcome is uncertain. Do NOT retry immediately. "
                "Read the relevant room or note first and verify state."
            ) from None
        raise SystemExit(f"Technocore HTTP {exc.code}: {body}") from None
    except Exception as exc:
        if is_write:
            raise SystemExit(
                "Technocore write outcome is uncertain. Do NOT retry immediately. "
                "Read the relevant room or note first and verify state."
            ) from exc
        raise SystemExit(f"Technocore request failed: {exc}") from exc
    if len(raw) > 1_000_000:
        raise SystemExit("Technocore response exceeded local safety limit.")
    return raw.decode("utf-8", errors="replace")


def get_note(namespace: str, key: str) -> str | None:
    valid_room(namespace)
    valid_room(key)
    req = urllib.request.Request(
        f"{BASE_URL}/kv/{urllib.parse.quote(namespace, safe='')}/{urllib.parse.quote(key, safe='')}",
        method="GET",
        headers={"User-Agent": USER_AGENT},
    )
    return request_text(req, allow_missing=True)


def get_room_owner(room: str) -> str | None:
    raw = get_note("room-owners", valid_room(room))
    return parse_owner_note_response(raw)


def get_room_nonce(room: str) -> int:
    value = get_note("room-nonce", valid_room(room))
    if value is None:
        return 0
    match = re.search(r"\d+", value)
    return int(match.group(0)) if match else 0


def sign_note_payload(namespace: str, key: str, nonce: int, value: str, key_obj: Ed25519PrivateKey) -> str:
    payload = f"{namespace}|{key}|{nonce}|{value}".encode("utf-8")
    return b64u(key_obj.sign(payload))


def room_owner_claim_payload(room: str, did: str, nonce: int) -> bytes:
    room = valid_room(room)
    return f"room-owners|{room}|{nonce}|{did}".encode("utf-8")


def did_profile_fingerprint(did: str) -> str:
    return hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]


def did_profile_path(did: str) -> tuple[str, str, str]:
    fingerprint = did_profile_fingerprint(did)
    return f"did-{fingerprint[:2]}", fingerprint[2:], fingerprint


def get_state(conn: sqlite3.Connection, key: str, default: str = "0") -> str:
    row = conn.execute("SELECT value FROM service_state WHERE key = ?", (key,)).fetchone()
    return str(row["value"]) if row else default


def set_state(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        """
        INSERT INTO service_state (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = excluded.updated_at
        """,
        (key, value, utc_now()),
    )
    conn.commit()


def room_cursor(conn: sqlite3.Connection, room: str) -> dict[str, Any]:
    legacy_seq = get_state(conn, f"cursor:{room}", "")
    generation = get_state(conn, f"cursor:{room}:generation", "")
    seq = get_state(conn, f"cursor:{room}:seq", legacy_seq or "0")
    if not generation:
        generation = UNKNOWN_LEGACY_GENERATION if legacy_seq else ""
    try:
        seq_value = int(seq)
    except ValueError:
        seq_value = 0
    return {
        "room": room,
        "generation": generation or None,
        "last_seq": seq_value,
        "continuity": "UNKNOWN_LEGACY" if generation == UNKNOWN_LEGACY_GENERATION else "CURRENT",
    }


def update_room_cursor(
    conn: sqlite3.Connection,
    room: str,
    generation: str | None,
    last_seq: int | None,
) -> str:
    cursor = room_cursor(conn, room)
    if generation is None:
        generation_value = GENERATION_MISSING
        status = "GENERATION_MISSING"
    else:
        generation_value = str(generation)
        if cursor["generation"] in {None, UNKNOWN_LEGACY_GENERATION, GENERATION_MISSING}:
            status = "UNKNOWN_LEGACY" if cursor["generation"] == UNKNOWN_LEGACY_GENERATION else "CURRENT"
        elif cursor["generation"] != generation_value:
            status = "ROOM_GENERATION_CHANGED"
            log(
                "room_generation_changed",
                room=room,
                old_generation=cursor["generation"],
                old_last_seq=cursor["last_seq"],
                new_generation=generation_value,
            )
        else:
            status = "CURRENT"
    if last_seq is not None:
        set_state(conn, f"cursor:{room}:seq", str(last_seq))
        set_state(conn, f"cursor:{room}", str(last_seq))
    set_state(conn, f"cursor:{room}:generation", generation_value)
    set_state(conn, f"cursor:{room}:continuity", status)
    return status


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_json_hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def load_json_artifact(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit(f"{path} must contain a JSON object.")
    return payload


def write_json_artifact(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def scout_verification_request_preview(request_path: Path) -> dict[str, Any]:
    request = load_json_artifact(request_path)
    if request.get("schema_version") != "flop-verification-request/v1":
        raise SystemExit("Unsupported verification request schema.")
    message_hash = canonical_json_hash(request)
    preview = {
        "schema_version": "flop-scout.verification-request-preview/v1",
        "request_id": request.get("request_id"),
        "routing_decision_id": request.get("routing_decision_id"),
        "routing_decision_hash": request.get("routing_decision_hash"),
        "task_hash": request.get("task_hash"),
        "requester_did": request.get("requester_did"),
        "target_agent_did": request.get("target_agent_did"),
        "task_type": request.get("task_type"),
        "verification_mode": request.get("verification_mode"),
        "specimen": request.get("specimen"),
        "expected_properties": request.get("expected_properties"),
        "response_destination": request.get("response_destination"),
        "operator_group": request.get("operator_group"),
        "same_operator": request.get("same_operator", request.get("operator_group") == LOCAL_OPERATOR_GROUP),
        "independent_reputation": request.get("independent_reputation"),
        "message_hash": message_hash,
        "request_artifact_hash": hashlib.sha256(request_path.read_bytes()).hexdigest(),
        "transport": "local_preview_only",
        "dry_run": True,
        "network_writes": 0,
        "private_key_accesses": 0,
        "tclk_settlement_actions": 0,
    }
    return preview


def verification_result_authenticity(result: dict[str, Any]) -> str:
    explicit = result.get("authenticity") or result.get("verification_status")
    if explicit in {"VERIFIED_OFFLINE", "INVALID_SIGNATURE"}:
        return str(explicit)
    if result.get("sig") or result.get("signature"):
        return "SIGNATURE_PRESENT_UNVERIFIED"
    return "UNSIGNED_LOCAL"


def scout_normalize_bench_result(result_path: Path, request_path: Path | None = None) -> dict[str, Any]:
    result = load_json_artifact(result_path)
    if result.get("schema_version") != "flop-verification-result/v1":
        raise SystemExit("Unsupported Bench result schema.")
    request = load_json_artifact(request_path) if request_path else None
    request_hash = canonical_json_hash(request) if request is not None else None
    reported_request_hash = (result.get("artifact_hashes") or {}).get("request_sha256")
    artifact_hashes_valid = request_hash is None or request_hash == reported_request_hash
    same_operator = bool(result.get("same_operator"))
    authenticity = verification_result_authenticity(result)
    normalized = {
        "schema_version": "flop-scout.normalized-verification-result/v1",
        "request_id": result.get("request_id"),
        "bench_did": result.get("bench_did"),
        "authenticity": authenticity,
        "correctness": result.get("status"),
        "reproducibility": result.get("reproducibility"),
        "artifact_hashes_valid": artifact_hashes_valid,
        "message_hash": hashlib.sha256(result_path.read_bytes()).hexdigest(),
        "request_hash": request_hash,
        "reported_request_hash": reported_request_hash,
        "operator_group": result.get("operator_group"),
        "same_operator": same_operator,
        "independent_reputation": bool(result.get("independent_reputation")),
        "bench_result": result,
        "classification": {
            "AUTHENTICITY": authenticity,
            "CORRECTNESS": result.get("status"),
            "REPRODUCIBILITY": result.get("reproducibility"),
        },
        "network_writes": 0,
        "private_key_accesses": 0,
        "tclk_settlement_actions": 0,
    }
    return normalized


def network_result_generation(generation: str | None) -> str:
    if generation is None or str(generation) in {"", "0"}:
        return UNKNOWN_LEGACY_GENERATION
    return str(generation)


def bench_delivery_payload(delivery: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key in ("result", "verification_result", "bench_result"):
        value = delivery.get(key)
        if isinstance(value, dict):
            payload.update(value)
            break
    for key, value in delivery.items():
        if key not in {"result", "verification_result", "bench_result"}:
            payload[key] = value
    return payload


def request_linkage_matches(payload: dict[str, Any], request: dict[str, Any]) -> dict[str, bool]:
    return {
        key: payload.get(key) == request.get(key)
        for key in (
            "request_id",
            "routing_decision_id",
            "routing_decision_hash",
            "task_hash",
            "verification_mode",
        )
    }


def normalize_network_bench_delivery(
    room: str,
    generation: str | None,
    raw: dict[str, Any],
    request: dict[str, Any],
) -> dict[str, Any]:
    room = valid_room(room)
    text = raw.get("text")
    if not isinstance(text, str):
        raise SystemExit("Selected Technocore record has no text payload.")
    try:
        seq = int(raw["seq"])
    except (KeyError, TypeError, ValueError):
        raise SystemExit("Selected Technocore record has no valid seq.") from None
    sender_did = message_did(raw)
    nonce = message_nonce(raw)
    sig = message_sig(raw)
    signature_status = verify_signed_record_offline(room, raw)
    transport_provenance = {
        "room": room,
        "generation": network_result_generation(generation),
        "reported_generation": str(generation) if generation is not None else None,
        "seq": seq,
        "server_timestamp": message_timestamp(raw),
        "sender_did": sender_did,
        "nonce": nonce,
        "signature": sig,
        "signature_present": sig is not None,
        "signature_verification": "UNSIGNED" if sig is None else signature_status,
        "message_hash": message_hash(text),
        "exact_message_text": text,
    }
    if signature_status != "VERIFIED_OFFLINE":
        authenticity = "UNSIGNED" if sig is None else "INVALID_SIGNATURE"
        return {
            "schema_version": "flop-scout.normalized-verification-result/v1",
            "authenticity": authenticity,
            "correctness": None,
            "reproducibility": None,
            "transport_provenance": transport_provenance,
            "request_linkage": {
                "valid": False,
                "checked": False,
                "reason": "transport_signature_not_verified",
            },
            "classification": {
                "AUTHENTICITY": authenticity,
                "CORRECTNESS": None,
                "REPRODUCIBILITY": None,
            },
            "network_writes": 0,
            "private_key_accesses": 0,
            "tclk_settlement_actions": 0,
        }
    try:
        delivery = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Bench delivery payload is not valid JSON: {exc.msg}") from None
    if not isinstance(delivery, dict):
        raise SystemExit("Bench delivery payload must be a JSON object.")
    if delivery.get("schema_version") != "flop-bench.verification-result-delivery.v1":
        raise SystemExit("Unsupported Bench verification-result delivery schema.")
    payload = bench_delivery_payload(delivery)
    if payload.get("bench_did") != sender_did:
        raise SystemExit("Transport sender DID does not match payload bench_did.")
    matches = request_linkage_matches(payload, request)
    if not all(matches.values()):
        failed = ", ".join(key for key, matched in matches.items() if not matched)
        raise SystemExit(f"Bench delivery does not match Router request: {failed}.")
    same_operator = bool(payload.get("same_operator"))
    independent_reputation = bool(payload.get("independent_reputation"))
    correctness = payload.get("status")
    reproducibility = payload.get("reproducibility")
    return {
        "schema_version": "flop-scout.normalized-verification-result/v1",
        "request_id": payload.get("request_id"),
        "routing_decision_id": payload.get("routing_decision_id"),
        "routing_decision_hash": payload.get("routing_decision_hash"),
        "task_hash": payload.get("task_hash"),
        "verification_mode": payload.get("verification_mode"),
        "bench_did": payload.get("bench_did"),
        "authenticity": "VERIFIED_OFFLINE",
        "correctness": correctness,
        "reproducibility": reproducibility,
        "operator_group": payload.get("operator_group"),
        "same_operator": same_operator,
        "independent_reputation": independent_reputation,
        "transport_provenance": transport_provenance,
        "request_linkage": {
            "valid": True,
            "checked": True,
            "matches": matches,
        },
        "bench_delivery": delivery,
        "bench_result": payload,
        "classification": {
            "AUTHENTICITY": "VERIFIED_OFFLINE",
            "CORRECTNESS": correctness,
            "REPRODUCIBILITY": reproducibility,
        },
        "network_writes": 0,
        "private_key_accesses": 0,
        "tclk_settlement_actions": 0,
    }


def fetch_network_verification_record(room: str, seq: int) -> tuple[dict[str, Any], str | None]:
    if seq < 0:
        raise SystemExit("--seq must be non-negative.")
    obj, generation = fetch_room_view(room, 200, since=max(0, seq - 1), allow_missing=True)
    for message in extract_room_messages(obj):
        try:
            if int(message.get("seq")) == seq:
                return message, generation
        except (TypeError, ValueError):
            continue
    obj, generation = fetch_room_view(room, 800, allow_missing=True)
    for message in extract_room_messages(obj):
        try:
            if int(message.get("seq")) == seq:
                return message, generation
        except (TypeError, ValueError):
            continue
    raise SystemExit(f"No Technocore record found for {room}/{seq}.")


def scout_ingest_network_verification_result(room: str, seq: int, request_path: Path) -> dict[str, Any]:
    request = load_json_artifact(request_path)
    if request.get("schema_version") != "flop-verification-request/v1":
        raise SystemExit("Unsupported verification request schema.")
    raw, generation = fetch_network_verification_record(room, seq)
    return normalize_network_bench_delivery(room, generation, raw, request)


def observer_connect(db_path: Path = OBSERVER_DB) -> sqlite3.Connection:
    ensure_home()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_observer_db(conn)
    import_local_history(conn)
    return conn


def init_observer_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS messages (
            room TEXT NOT NULL,
            seq INTEGER NOT NULL,
            timestamp TEXT,
            sender TEXT NOT NULL,
            signed INTEGER NOT NULL,
            text TEXT NOT NULL,
            normalized_text TEXT NOT NULL,
            normalized_hash TEXT NOT NULL,
            template_normalized_text TEXT NOT NULL DEFAULT '',
            template_normalized_hash TEXT NOT NULL DEFAULT '',
            discovered_at TEXT NOT NULL,
            PRIMARY KEY (room, seq)
        );
        CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);
        CREATE INDEX IF NOT EXISTS idx_messages_hash ON messages(normalized_hash);

        CREATE TABLE IF NOT EXISTS rooms (
            room TEXT PRIMARY KEY,
            first_observed_at TEXT NOT NULL,
            last_observed_at TEXT NOT NULL,
            last_seq INTEGER
        );

        CREATE TABLE IF NOT EXISTS interactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_did TEXT NOT NULL,
            target_did TEXT NOT NULL,
            room TEXT NOT NULL,
            source_seq INTEGER NOT NULL,
            response_seq INTEGER NOT NULL,
            source_timestamp TEXT,
            response_timestamp TEXT,
            relationship_type TEXT NOT NULL,
            confidence REAL NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE (room, source_seq, response_seq, relationship_type)
        );

        CREATE TABLE IF NOT EXISTS opportunities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room TEXT NOT NULL,
            seq INTEGER NOT NULL,
            sender TEXT NOT NULL,
            message_text TEXT NOT NULL,
            category TEXT NOT NULL,
            reason TEXT NOT NULL,
            confidence REAL NOT NULL,
            tier TEXT NOT NULL DEFAULT 'LOW',
            signed_status TEXT NOT NULL DEFAULT 'UNSIGNED',
            request_signal TEXT NOT NULL DEFAULT 'NO',
            normalized_duplicate_count INTEGER NOT NULL DEFAULT 1,
            distinct_dids_using_template INTEGER NOT NULL DEFAULT 1,
            exact_distinct_dids INTEGER NOT NULL DEFAULT 1,
            originality_classification TEXT NOT NULL DEFAULT 'UNIQUE',
            capability_match TEXT NOT NULL DEFAULT 'LOW',
            actionability TEXT NOT NULL DEFAULT 'NO',
            unresolved_problem TEXT NOT NULL DEFAULT 'NO',
            request_strength TEXT NOT NULL DEFAULT 'NONE',
            template_message_count INTEGER NOT NULL DEFAULT 1,
            template_distinct_dids INTEGER NOT NULL DEFAULT 1,
            template_originality_classification TEXT NOT NULL DEFAULT 'UNIQUE',
            rejection_reasons TEXT NOT NULL DEFAULT '',
            noise_flags TEXT NOT NULL DEFAULT 'NONE',
            status TEXT NOT NULL DEFAULT 'new'
                CHECK (status IN ('new', 'reviewed', 'ignored', 'acted')),
            created_at TEXT NOT NULL,
            UNIQUE (room, seq)
        );

        CREATE TABLE IF NOT EXISTS local_signed_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            source_key TEXT NOT NULL UNIQUE,
            did TEXT NOT NULL,
            room TEXT NOT NULL,
            seq INTEGER,
            nonce INTEGER,
            text TEXT NOT NULL,
            normalized_text TEXT NOT NULL,
            normalized_hash TEXT NOT NULL,
            template_normalized_text TEXT NOT NULL DEFAULT '',
            template_normalized_hash TEXT NOT NULL DEFAULT '',
            created_at TEXT,
            imported_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS service_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS validation_watches (
            validation_id TEXT PRIMARY KEY,
            target_did TEXT NOT NULL,
            outbound_room TEXT NOT NULL,
            outbound_seq INTEGER NOT NULL,
            outbound_timestamp TEXT,
            preferred_response_room TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'watching',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS validation_response_candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            validation_id TEXT NOT NULL,
            response_type TEXT NOT NULL,
            room TEXT NOT NULL,
            seq INTEGER NOT NULL,
            timestamp TEXT,
            sender TEXT NOT NULL,
            validation_id_present INTEGER NOT NULL,
            message_hash TEXT NOT NULL,
            bounded_text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE (validation_id, room, seq)
        );

        CREATE TABLE IF NOT EXISTS evidence_records (
            evidence_id TEXT PRIMARY KEY,
            room TEXT NOT NULL,
            generation TEXT NOT NULL,
            seq INTEGER NOT NULL,
            server_timestamp TEXT,
            did TEXT,
            nonce INTEGER,
            sig TEXT,
            text TEXT NOT NULL,
            message_hash TEXT NOT NULL,
            canonical_payload_hash TEXT,
            retrieved_at TEXT NOT NULL,
            source TEXT NOT NULL,
            verification_status TEXT NOT NULL,
            raw_record_json TEXT NOT NULL,
            UNIQUE (room, generation, seq, evidence_id)
        );

        CREATE TABLE IF NOT EXISTS tclk_frames (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room TEXT NOT NULL,
            generation TEXT NOT NULL,
            seq INTEGER NOT NULL,
            transport_did TEXT,
            transport_verification_status TEXT NOT NULL,
            transport_binding_status TEXT NOT NULL,
            frame_hash TEXT NOT NULL,
            frame_type TEXT,
            frame_from TEXT,
            offer_id TEXT,
            contract_id TEXT,
            ref TEXT,
            job_proto TEXT,
            job_id TEXT,
            job_context_json TEXT,
            role TEXT,
            lock_kind TEXT,
            asset TEXT,
            amount TEXT,
            rails_json TEXT,
            expires_ms INTEGER,
            claim_by_ms INTEGER,
            refund_after_ms INTEGER,
            observed_at TEXT NOT NULL,
            parse_status TEXT NOT NULL,
            raw_text TEXT NOT NULL,
            parse_error TEXT,
            UNIQUE (room, generation, seq)
        );

        CREATE TABLE IF NOT EXISTS tclk_capability_hints (
            did TEXT NOT NULL,
            rail TEXT NOT NULL,
            source TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            verification_status TEXT NOT NULL DEFAULT 'UNVERIFIED_HINT',
            PRIMARY KEY (did, rail, source)
        );

        CREATE TABLE IF NOT EXISTS kibble_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room TEXT NOT NULL,
            generation TEXT NOT NULL,
            seq INTEGER NOT NULL,
            server_timestamp TEXT,
            sender_did TEXT,
            nonce INTEGER,
            signature TEXT,
            signature_verification TEXT NOT NULL,
            exact_text TEXT NOT NULL,
            message_hash TEXT NOT NULL,
            event_type TEXT,
            event_version TEXT,
            job_id TEXT,
            observed_at TEXT NOT NULL,
            parse_status TEXT NOT NULL,
            parse_error TEXT,
            payload_json TEXT,
            source_class TEXT NOT NULL DEFAULT 'SOURCE_TRANSCRIPT',
            UNIQUE (room, generation, seq)
        );

        CREATE TABLE IF NOT EXISTS kibble_jobs (
            source TEXT NOT NULL,
            job_id TEXT PRIMARY KEY,
            category TEXT,
            title TEXT,
            requirements TEXT,
            poster_did TEXT,
            worker_did TEXT,
            status TEXT NOT NULL,
            observed_seq INTEGER,
            signature_verified INTEGER NOT NULL DEFAULT 0,
            settlement_rail TEXT,
            settlement_value_backed INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS kibble_reconciliation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            checked_at TEXT NOT NULL,
            matched_jobs INTEGER NOT NULL,
            board_only_jobs INTEGER NOT NULL,
            room_only_jobs INTEGER NOT NULL,
            status_mismatches INTEGER NOT NULL,
            worker_mismatches INTEGER NOT NULL,
            result_hash_mismatches INTEGER NOT NULL,
            attestation_count_differences INTEGER NOT NULL,
            board_status TEXT NOT NULL,
            details_json TEXT NOT NULL
        );
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_validation_responses_validation ON validation_response_candidates(validation_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_evidence_records_room_generation_seq ON evidence_records(room, generation, seq)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tclk_frames_type ON tclk_frames(frame_type, parse_status)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tclk_frames_transport ON tclk_frames(transport_did, transport_binding_status)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_kibble_events_job ON kibble_events(job_id, event_type)"
    )
    for column, ddl in {
        "template_normalized_text": "ALTER TABLE messages ADD COLUMN template_normalized_text TEXT NOT NULL DEFAULT ''",
        "template_normalized_hash": "ALTER TABLE messages ADD COLUMN template_normalized_hash TEXT NOT NULL DEFAULT ''",
    }.items():
        if not column_exists(conn, "messages", column):
            conn.execute(ddl)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_template_hash ON messages(template_normalized_hash)"
    )
    for column, ddl in {
        "tier": "ALTER TABLE opportunities ADD COLUMN tier TEXT NOT NULL DEFAULT 'LOW'",
        "signed_status": "ALTER TABLE opportunities ADD COLUMN signed_status TEXT NOT NULL DEFAULT 'UNSIGNED'",
        "request_signal": "ALTER TABLE opportunities ADD COLUMN request_signal TEXT NOT NULL DEFAULT 'NO'",
        "normalized_duplicate_count": "ALTER TABLE opportunities ADD COLUMN normalized_duplicate_count INTEGER NOT NULL DEFAULT 1",
        "distinct_dids_using_template": "ALTER TABLE opportunities ADD COLUMN distinct_dids_using_template INTEGER NOT NULL DEFAULT 1",
        "exact_distinct_dids": "ALTER TABLE opportunities ADD COLUMN exact_distinct_dids INTEGER NOT NULL DEFAULT 1",
        "originality_classification": "ALTER TABLE opportunities ADD COLUMN originality_classification TEXT NOT NULL DEFAULT 'UNIQUE'",
        "capability_match": "ALTER TABLE opportunities ADD COLUMN capability_match TEXT NOT NULL DEFAULT 'LOW'",
        "actionability": "ALTER TABLE opportunities ADD COLUMN actionability TEXT NOT NULL DEFAULT 'NO'",
        "unresolved_problem": "ALTER TABLE opportunities ADD COLUMN unresolved_problem TEXT NOT NULL DEFAULT 'NO'",
        "request_strength": "ALTER TABLE opportunities ADD COLUMN request_strength TEXT NOT NULL DEFAULT 'NONE'",
        "template_message_count": "ALTER TABLE opportunities ADD COLUMN template_message_count INTEGER NOT NULL DEFAULT 1",
        "template_distinct_dids": "ALTER TABLE opportunities ADD COLUMN template_distinct_dids INTEGER NOT NULL DEFAULT 1",
        "template_originality_classification": "ALTER TABLE opportunities ADD COLUMN template_originality_classification TEXT NOT NULL DEFAULT 'UNIQUE'",
        "rejection_reasons": "ALTER TABLE opportunities ADD COLUMN rejection_reasons TEXT NOT NULL DEFAULT ''",
        "noise_flags": "ALTER TABLE opportunities ADD COLUMN noise_flags TEXT NOT NULL DEFAULT 'NONE'",
    }.items():
        if not column_exists(conn, "opportunities", column):
            conn.execute(ddl)
    for column, ddl in {
        "template_normalized_text": "ALTER TABLE local_signed_activity ADD COLUMN template_normalized_text TEXT NOT NULL DEFAULT ''",
        "template_normalized_hash": "ALTER TABLE local_signed_activity ADD COLUMN template_normalized_hash TEXT NOT NULL DEFAULT ''",
    }.items():
        if not column_exists(conn, "local_signed_activity", column):
            conn.execute(ddl)
    backfill_template_hashes(conn)
    conn.commit()


def column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    return any(row[1] == column for row in conn.execute(f"PRAGMA table_info({table})"))


def backfill_template_hashes(conn: sqlite3.Connection) -> None:
    for table in ("messages", "local_signed_activity"):
        rows = conn.execute(
            f"""
            SELECT rowid AS rid, text
            FROM {table}
            WHERE template_normalized_text = '' OR template_normalized_hash = ''
            """
        ).fetchall()
        for row in rows:
            try:
                template_text = template_normalize_text(row["text"])
            except ValueError:
                continue
            conn.execute(
                f"""
                UPDATE {table}
                SET template_normalized_text = ?, template_normalized_hash = ?
                WHERE rowid = ?
                """,
                (
                    template_text,
                    hashlib.sha256(template_text.encode("utf-8")).hexdigest(),
                    row["rid"],
                ),
            )


def is_signed_sender(sender: str) -> bool:
    return sender.startswith("did:key:z6Mk")


def extract_room_messages(obj: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("messages", "items", "posts", "log"):
        value = obj.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    if isinstance(obj.get("room"), dict):
        return extract_room_messages(obj["room"])
    return []


def message_sender(raw: dict[str, Any]) -> str:
    sender = raw.get("from") or raw.get("did") or raw.get("nick") or raw.get("nickname")
    if sender is None:
        return "unknown"
    return str(sender)


def message_timestamp(raw: dict[str, Any]) -> str | None:
    ts = raw.get("ts") or raw.get("timestamp") or raw.get("time")
    return str(ts) if ts is not None else None


def message_did(raw: dict[str, Any]) -> str | None:
    candidate = raw.get("did") or raw.get("from")
    if candidate is None:
        return None
    candidate = str(candidate)
    return candidate if is_valid_ed25519_did(candidate) else None


def message_nonce(raw: dict[str, Any]) -> int | None:
    nonce = raw.get("nonce")
    if nonce is None or isinstance(nonce, bool):
        return None
    try:
        return int(nonce)
    except (TypeError, ValueError):
        return None


def message_sig(raw: dict[str, Any]) -> str | None:
    sig = raw.get("sig")
    return str(sig) if isinstance(sig, str) else None


def message_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_payload_hash(room: str, nonce: int, text: str) -> str:
    payload = f"{room}|{nonce}|{text}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def verify_signed_record_offline(room: str, raw: dict[str, Any]) -> str:
    text = raw.get("text")
    if not isinstance(text, str):
        return "PROVENANCE_INCOMPLETE"
    raw_did = raw.get("did") or raw.get("from")
    did = message_did(raw)
    sender = raw.get("from")
    nonce = message_nonce(raw)
    sig = message_sig(raw)
    if did is None:
        if raw_did is not None and (sig is not None or nonce is not None):
            return "INVALID_SIGNATURE"
        if sig is not None:
            return "SIGNATURE_PRESENT_UNVERIFIED"
        return "UNSIGNED"
    if sender is not None and str(sender) != did:
        return "PROVENANCE_INCOMPLETE"
    if nonce is None:
        return "SIGNATURE_PRESENT_UNVERIFIED" if sig is not None else "PROVENANCE_INCOMPLETE"
    if sig is None:
        return "LEGACY_SERVER_VERIFIED_NO_SIGNATURE"
    try:
        sig_bytes = b64u_decode_canonical(sig)
    except Exception:
        return "INVALID_SIGNATURE"
    if len(sig_bytes) != 64:
        return "INVALID_SIGNATURE"
    try:
        public_key = public_key_from_did(did)
        public_key.verify(sig_bytes, f"{valid_room(room)}|{nonce}|{text}".encode("utf-8"))
    except Exception:
        return "INVALID_SIGNATURE"
    return "VERIFIED_OFFLINE"


def evidence_id_for(record: dict[str, Any]) -> str:
    bound = {
        "room": record["room"],
        "generation": record["generation"],
        "seq": record["seq"],
        "did": record.get("did"),
        "nonce": record.get("nonce"),
        "sig": record.get("sig"),
        "message_hash": record["message_hash"],
    }
    return hashlib.sha256(
        json.dumps(bound, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def evidence_record_from_message(
    room: str,
    generation: str | None,
    raw: dict[str, Any],
    *,
    source: str,
    retrieved_at: str | None = None,
) -> dict[str, Any] | None:
    try:
        seq = int(raw["seq"])
    except (KeyError, TypeError, ValueError):
        return None
    text = raw.get("text")
    if not isinstance(text, str):
        return None
    generation_value = str(generation) if generation is not None else UNKNOWN_LEGACY_GENERATION
    did = message_did(raw)
    nonce = message_nonce(raw)
    sig = message_sig(raw)
    record = {
        "room": valid_room(room),
        "generation": generation_value,
        "seq": seq,
        "server_timestamp": message_timestamp(raw),
        "did": did,
        "nonce": nonce,
        "sig": sig,
        "text": text,
        "message_hash": message_hash(text),
        "canonical_payload_hash": canonical_payload_hash(room, nonce, text)
        if did is not None and nonce is not None
        else None,
        "retrieved_at": retrieved_at or utc_now(),
        "source": source,
        "verification_status": verify_signed_record_offline(room, raw),
        "raw_record_json": json.dumps(raw, sort_keys=True, ensure_ascii=False, separators=(",", ":")),
    }
    record["evidence_id"] = evidence_id_for(record)
    return record


def store_evidence_record(conn: sqlite3.Connection, record: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO evidence_records
            (evidence_id, room, generation, seq, server_timestamp, did, nonce, sig,
             text, message_hash, canonical_payload_hash, retrieved_at, source,
             verification_status, raw_record_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record["evidence_id"],
            record["room"],
            record["generation"],
            record["seq"],
            record["server_timestamp"],
            record["did"],
            record["nonce"],
            record["sig"],
            record["text"],
            record["message_hash"],
            record["canonical_payload_hash"],
            record["retrieved_at"],
            record["source"],
            record["verification_status"],
            record["raw_record_json"],
        ),
    )


def tclk_text_is_frame(text: str) -> bool:
    return text.startswith(TCLK_FRAME_PREFIX)


def int_field(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def str_field(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def tclk_parse_frame_text(text: str) -> dict[str, Any] | None:
    if not tclk_text_is_frame(text):
        return None
    remainder = text[len(TCLK_FRAME_PREFIX) :]
    result: dict[str, Any] = {
        "parse_status": "TCLK_MALFORMED",
        "frame": None,
        "parse_error": None,
    }
    try:
        frame = json.loads(remainder)
    except json.JSONDecodeError as exc:
        result["parse_error"] = f"invalid JSON: {exc.msg}"
        return result
    if not isinstance(frame, dict):
        result["parse_error"] = "frame JSON is not an object"
        return result
    frame_type = frame.get("type")
    if frame_type not in TCLK_FRAME_TYPES:
        result["parse_error"] = "unsupported or missing frame type"
        result["frame"] = frame
        return result
    result["parse_status"] = "TCLK_PARSEABLE"
    result["frame"] = frame
    return result


def tclk_frame_value(frame: dict[str, Any], key: str) -> str | None:
    return str_field(frame.get(key))


def tclk_lock_kind(frame: dict[str, Any]) -> str | None:
    lock = frame.get("lock")
    if isinstance(lock, str):
        return lock
    if isinstance(lock, dict):
        return str_field(lock.get("kind") or lock.get("type"))
    return None


def tclk_rails_json(frame: dict[str, Any]) -> str | None:
    rails = frame.get("rails")
    if not isinstance(rails, list):
        return None
    return json.dumps(rails, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def tclk_transport_binding_status(
    transport_did: str | None,
    transport_verification_status: str,
    frame_from: str | None,
) -> str:
    verified = transport_verification_status in {
        "VERIFIED_OFFLINE",
        "LEGACY_SERVER_VERIFIED_NO_SIGNATURE",
    }
    if not verified or transport_did is None:
        return "UNSIGNED_TCLK_DATA"
    if frame_from == transport_did:
        return "SIGNED_TCLK_FRAME"
    return "TCLK_DID_MISMATCH"


def tclk_record_from_message(
    room: str,
    generation: str | int | None,
    raw: dict[str, Any],
    evidence: dict[str, Any] | None,
    *,
    observed_at: str,
) -> dict[str, Any] | None:
    text = raw.get("text")
    if not isinstance(text, str):
        return None
    parsed = tclk_parse_frame_text(text)
    if parsed is None:
        return None
    try:
        seq = int(raw["seq"])
    except (KeyError, TypeError, ValueError):
        return None
    frame = parsed.get("frame") if isinstance(parsed.get("frame"), dict) else {}
    job = frame.get("job") if isinstance(frame.get("job"), dict) else {}
    transport_did = evidence["did"] if evidence is not None else message_did(raw)
    verification_status = (
        evidence["verification_status"] if evidence is not None else verify_signed_record_offline(room, raw)
    )
    frame_from = tclk_frame_value(frame, "from")
    return {
        "room": valid_room(room),
        "generation": str(generation) if generation is not None else UNKNOWN_LEGACY_GENERATION,
        "seq": seq,
        "transport_did": transport_did,
        "transport_verification_status": verification_status,
        "transport_binding_status": tclk_transport_binding_status(
            transport_did,
            verification_status,
            frame_from,
        ),
        "frame_hash": message_hash(text),
        "frame_type": tclk_frame_value(frame, "type"),
        "frame_from": frame_from,
        "offer_id": tclk_frame_value(frame, "id"),
        "contract_id": tclk_frame_value(frame, "contract"),
        "ref": tclk_frame_value(frame, "ref"),
        "job_proto": str_field(job.get("proto")),
        "job_id": str_field(job.get("id")),
        "job_context_json": json.dumps(job.get("context"), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        if "context" in job
        else None,
        "role": tclk_frame_value(frame, "role"),
        "lock_kind": tclk_lock_kind(frame),
        "asset": tclk_frame_value(frame, "asset"),
        "amount": str(frame["amount"]) if "amount" in frame and not isinstance(frame.get("amount"), (dict, list)) else None,
        "rails_json": tclk_rails_json(frame),
        "expires_ms": int_field(frame.get("expiresMs")),
        "claim_by_ms": int_field(frame.get("claimByMs")),
        "refund_after_ms": int_field(frame.get("refundAfterMs")),
        "observed_at": observed_at,
        "parse_status": parsed["parse_status"],
        "raw_text": text,
        "parse_error": parsed.get("parse_error"),
    }


def store_tclk_frame(conn: sqlite3.Connection, record: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO tclk_frames
            (room, generation, seq, transport_did, transport_verification_status,
             transport_binding_status, frame_hash, frame_type, frame_from, offer_id,
             contract_id, ref, job_proto, job_id, job_context_json, role, lock_kind,
             asset, amount, rails_json, expires_ms, claim_by_ms, refund_after_ms,
             observed_at, parse_status, raw_text, parse_error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record["room"],
            record["generation"],
            record["seq"],
            record["transport_did"],
            record["transport_verification_status"],
            record["transport_binding_status"],
            record["frame_hash"],
            record["frame_type"],
            record["frame_from"],
            record["offer_id"],
            record["contract_id"],
            record["ref"],
            record["job_proto"],
            record["job_id"],
            record["job_context_json"],
            record["role"],
            record["lock_kind"],
            record["asset"],
            record["amount"],
            record["rails_json"],
            record["expires_ms"],
            record["claim_by_ms"],
            record["refund_after_ms"],
            record["observed_at"],
            record["parse_status"],
            record["raw_text"],
            record["parse_error"],
        ),
    )


def parse_tclk_capability_hints(note_text: str) -> list[str]:
    rails: list[str] = []
    for match in re.finditer(r"\btclk1:([A-Za-z0-9_.:-]+(?:,[A-Za-z0-9_.:-]+)*)\b", note_text):
        for rail in match.group(1).split(","):
            if rail and rail not in rails:
                rails.append(rail)
    return rails


def store_tclk_capability_hints(conn: sqlite3.Connection, did: str, source: str, note_text: str) -> int:
    if not is_valid_ed25519_did(did):
        return 0
    now = utc_now()
    inserted = 0
    for rail in parse_tclk_capability_hints(note_text):
        before = conn.total_changes
        conn.execute(
            """
            INSERT OR IGNORE INTO tclk_capability_hints
                (did, rail, source, observed_at, verification_status)
            VALUES (?, ?, ?, ?, 'UNVERIFIED_HINT')
            """,
            (did, rail, source, now),
        )
        if conn.total_changes > before:
            inserted += 1
    conn.commit()
    return inserted


def tclk_offer_is_actionable(row: sqlite3.Row, *, now_ms: int | None = None) -> bool:
    if row["parse_status"] != "TCLK_PARSEABLE":
        return False
    if row["frame_type"] != "offer":
        return False
    if row["transport_binding_status"] != "SIGNED_TCLK_FRAME":
        return False
    expires_ms = row["expires_ms"]
    if expires_ms is not None:
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        if int(expires_ms) <= now_ms:
            return False
    return True


def tclk_discovery_rows(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT *
        FROM tclk_frames
        WHERE parse_status = 'TCLK_PARSEABLE'
          AND frame_type = 'offer'
          AND transport_binding_status = 'SIGNED_TCLK_FRAME'
        ORDER BY observed_at DESC, room, generation, seq
        LIMIT 20
        """
    ).fetchall()


def print_tclk_discovery_summary(conn: sqlite3.Connection) -> None:
    total = conn.execute("SELECT COUNT(*) FROM tclk_frames").fetchone()[0]
    parseable = conn.execute(
        "SELECT COUNT(*) FROM tclk_frames WHERE parse_status = 'TCLK_PARSEABLE'"
    ).fetchone()[0]
    malformed = conn.execute(
        "SELECT COUNT(*) FROM tclk_frames WHERE parse_status = 'TCLK_MALFORMED'"
    ).fetchone()[0]
    signed = conn.execute(
        "SELECT COUNT(*) FROM tclk_frames WHERE transport_binding_status = 'SIGNED_TCLK_FRAME'"
    ).fetchone()[0]
    mismatched = conn.execute(
        "SELECT COUNT(*) FROM tclk_frames WHERE transport_binding_status = 'TCLK_DID_MISMATCH'"
    ).fetchone()[0]
    rows = [row for row in tclk_discovery_rows(conn) if tclk_offer_is_actionable(row)]
    print("TCLK discovery")
    print("--------------")
    print(f"Indexed frames: {total}")
    print(f"Parseable frames: {parseable}")
    print(f"Malformed frames: {malformed}")
    print(f"Signed matching frames: {signed}")
    print(f"DID mismatches: {mismatched}")
    print(f"Signed unexpired offers for review: {len(rows)}")
    for row in rows[:5]:
        rails = row["rails_json"] or "[]"
        print("")
        print(f"  room: {row['room']}")
        print(f"  generation: {row['generation']}")
        print(f"  seq: {row['seq']}")
        print(f"  counterparty DID: {row['transport_did']}")
        print(f"  offer id: {row['offer_id'] or '(none)'}")
        print(f"  job: {row['job_proto'] or '(none)'}/{row['job_id'] or '(none)'}")
        print(f"  amount/asset: {row['amount'] or '(none)'}/{row['asset'] or '(none)'}")
        print(f"  rails: {rails}")
        print(f"  lock type: {row['lock_kind'] or '(none)'}")
        print(f"  expiresMs: {row['expires_ms'] if row['expires_ms'] is not None else '(none)'}")
    print("Scout observes TCLK only; it does not accept, lock, reveal, refund, settle, or assign TCLK-only HIGH priority.")


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def kibble_config() -> dict[str, Any]:
    return {
        "enabled": env_bool("KIBBLE_ENABLED", False),
        "mode": os.environ.get("KIBBLE_MODE", "shadow"),
        "room_url": os.environ.get("KIBBLE_ROOM_URL", f"{BASE_URL}/r/{KIBBLE_ROOM}"),
        "board_url": os.environ.get("KIBBLE_BOARD_URL", KIBBLE_BOARD_URL),
        "status_url": os.environ.get("KIBBLE_STATUS_URL", KIBBLE_STATUS_URL),
        "poll_seconds": int(os.environ.get("KIBBLE_POLL_SECONDS", "30")),
        "max_concurrent_claims": int(os.environ.get("KIBBLE_MAX_CONCURRENT_CLAIMS", "0")),
        "allow_writes": env_bool("KIBBLE_ALLOW_WRITES", False),
    }


def kibble_service_rooms() -> tuple[str, ...]:
    return (KIBBLE_ROOM,) if kibble_config()["enabled"] else ()


def kibble_parse_event_text(text: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return {"parse_status": "KIBBLE_MALFORMED", "parse_error": f"invalid JSON: {exc.msg}", "payload": None}
    if not isinstance(payload, dict):
        return {"parse_status": "KIBBLE_MALFORMED", "parse_error": "event JSON is not an object", "payload": None}
    event_type = str(payload.get("type") or payload.get("event_type") or "").upper()
    version = str(payload.get("version") or payload.get("v") or "")
    schema_version = str(payload.get("schema_version") or "")
    if event_type not in KIBBLE_EVENT_TYPES:
        return {"parse_status": "KIBBLE_IGNORED", "parse_error": "unsupported event type", "payload": payload}
    if version not in {"1", "v1"} and not schema_version.lower().endswith(".v1"):
        return {"parse_status": "KIBBLE_IGNORED", "parse_error": "unsupported event version", "payload": payload}
    return {"parse_status": "KIBBLE_PARSEABLE", "parse_error": None, "payload": payload}


def kibble_job_id(payload: dict[str, Any]) -> str | None:
    value = payload.get("job_id") or payload.get("id")
    return value if isinstance(value, str) and value else None


def kibble_record_from_message(
    room: str,
    generation: str | int | None,
    raw: dict[str, Any],
    *,
    observed_at: str,
) -> dict[str, Any] | None:
    text = raw.get("text")
    if not isinstance(text, str):
        return None
    parsed = kibble_parse_event_text(text)
    if parsed is None:
        return None
    try:
        seq = int(raw["seq"])
    except (KeyError, TypeError, ValueError):
        return None
    payload = parsed.get("payload") if isinstance(parsed.get("payload"), dict) else {}
    event_type = str(payload.get("type") or payload.get("event_type") or "").upper() or None
    version = str(payload.get("version") or payload.get("v") or "")
    return {
        "room": valid_room(room),
        "generation": str(generation) if generation is not None else UNKNOWN_LEGACY_GENERATION,
        "seq": seq,
        "server_timestamp": message_timestamp(raw),
        "sender_did": message_did(raw),
        "nonce": message_nonce(raw),
        "signature": message_sig(raw),
        "signature_verification": verify_signed_record_offline(room, raw),
        "exact_text": text,
        "message_hash": message_hash(text),
        "event_type": event_type if event_type in KIBBLE_EVENT_TYPES else None,
        "event_version": version or ("v1" if str(payload.get("schema_version") or "").lower().endswith(".v1") else None),
        "job_id": kibble_job_id(payload),
        "observed_at": observed_at,
        "parse_status": parsed["parse_status"],
        "parse_error": parsed.get("parse_error"),
        "payload_json": json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")) if payload else None,
    }


def store_kibble_event(conn: sqlite3.Connection, record: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO kibble_events
            (room, generation, seq, server_timestamp, sender_did, nonce, signature,
             signature_verification, exact_text, message_hash, event_type, event_version,
             job_id, observed_at, parse_status, parse_error, payload_json, source_class)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'SOURCE_TRANSCRIPT')
        """,
        (
            record["room"],
            record["generation"],
            record["seq"],
            record["server_timestamp"],
            record["sender_did"],
            record["nonce"],
            record["signature"],
            record["signature_verification"],
            record["exact_text"],
            record["message_hash"],
            record["event_type"],
            record["event_version"],
            record["job_id"],
            record["observed_at"],
            record["parse_status"],
            record["parse_error"],
            record["payload_json"],
        ),
    )


def kibble_payload(row: sqlite3.Row) -> dict[str, Any]:
    if not row["payload_json"]:
        return {}
    try:
        payload = json.loads(row["payload_json"])
        return payload if isinstance(payload, dict) else {}
    except json.JSONDecodeError:
        return {}


def kibble_event_status(event_type: str | None) -> str:
    return {
        "JOB": "OPEN",
        "CLAIM": "CLAIMED",
        "RESULT": "DELIVERED",
        "DELIVER": "DELIVERED",
        "ATTEST": "ATTESTED",
        "ACCEPT": "ACCEPTED",
    }.get(event_type or "", "UNKNOWN")


def rebuild_kibble_jobs(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        """
        SELECT *
        FROM kibble_events
        WHERE parse_status = 'KIBBLE_PARSEABLE'
          AND job_id IS NOT NULL
        ORDER BY generation, seq, id
        """
    ).fetchall()
    jobs: dict[str, dict[str, Any]] = {}
    for row in rows:
        payload = kibble_payload(row)
        job_id = row["job_id"]
        job = jobs.setdefault(
            job_id,
            {
                "source": "kibble",
                "job_id": job_id,
                "category": None,
                "title": None,
                "requirements": None,
                "poster_did": None,
                "worker_did": None,
                "status": "UNKNOWN",
                "observed_seq": None,
                "signature_verified": False,
                "settlement_rail": None,
                "settlement_value_backed": False,
            },
        )
        event_type = row["event_type"]
        if row["signature_verification"] == "VERIFIED_OFFLINE":
            job["signature_verified"] = True
        if event_type == "JOB":
            job["category"] = payload.get("category") if isinstance(payload.get("category"), str) else job["category"]
            job["title"] = payload.get("title") if isinstance(payload.get("title"), str) else job["title"]
            body = payload.get("requirements") or payload.get("body")
            if isinstance(body, str):
                job["requirements"] = body
            job["poster_did"] = row["sender_did"]
            settlement = payload.get("settlement") if isinstance(payload.get("settlement"), dict) else {}
            rail = settlement.get("rail") if isinstance(settlement.get("rail"), str) else payload.get("settlement_rail")
            job["settlement_rail"] = rail if isinstance(rail, str) else job["settlement_rail"]
            job["settlement_value_backed"] = False
        elif event_type == "CLAIM":
            job["worker_did"] = row["sender_did"]
        elif event_type in {"RESULT", "DELIVER"} and job["worker_did"] is None:
            job["worker_did"] = row["sender_did"]
        status = kibble_event_status(event_type)
        if status != "UNKNOWN":
            job["status"] = status
        job["observed_seq"] = row["seq"]
    now = utc_now()
    for job in jobs.values():
        conn.execute(
            """
            INSERT INTO kibble_jobs
                (source, job_id, category, title, requirements, poster_did, worker_did,
                 status, observed_seq, signature_verified, settlement_rail,
                 settlement_value_backed, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
                category = excluded.category,
                title = excluded.title,
                requirements = excluded.requirements,
                poster_did = excluded.poster_did,
                worker_did = excluded.worker_did,
                status = excluded.status,
                observed_seq = excluded.observed_seq,
                signature_verified = excluded.signature_verified,
                settlement_rail = excluded.settlement_rail,
                settlement_value_backed = excluded.settlement_value_backed,
                updated_at = excluded.updated_at
            """,
            (
                job["source"],
                job["job_id"],
                job["category"],
                job["title"],
                job["requirements"],
                job["poster_did"],
                job["worker_did"],
                job["status"],
                job["observed_seq"],
                1 if job["signature_verified"] else 0,
                job["settlement_rail"],
                1 if job["settlement_value_backed"] else 0,
                now,
            ),
        )
    conn.commit()


def fetch_json_url(url: str, *, allow_missing: bool = True) -> dict[str, Any]:
    req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json", "User-Agent": USER_AGENT})
    return request_json(req, allow_missing=allow_missing)


def board_jobs_from_obj(obj: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("jobs", "items", "board"):
        value = obj.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    if isinstance(obj.get("data"), dict):
        return board_jobs_from_obj(obj["data"])
    return []


def reconcile_kibble_board(conn: sqlite3.Connection, board_obj: dict[str, Any] | None, status_obj: dict[str, Any] | None = None) -> dict[str, Any]:
    room_rows = {
        row["job_id"]: row
        for row in conn.execute("SELECT * FROM kibble_jobs").fetchall()
    }
    board_jobs = board_jobs_from_obj(board_obj or {})
    board_by_id = {
        str(job.get("job_id") or job.get("id")): job
        for job in board_jobs
        if job.get("job_id") or job.get("id")
    }
    details = {
        "status_mismatches": [],
        "worker_mismatches": [],
        "room_only_jobs": sorted(set(room_rows) - set(board_by_id)),
        "board_only_jobs": sorted(set(board_by_id) - set(room_rows)),
        "result_hash_mismatches": [],
        "attestation_count_differences": [],
    }
    matched = sorted(set(room_rows) & set(board_by_id))
    for job_id in matched:
        room_job = room_rows[job_id]
        board_job = board_by_id[job_id]
        board_status = board_job.get("status")
        if isinstance(board_status, str) and board_status.upper() != room_job["status"]:
            details["status_mismatches"].append(job_id)
        board_worker = board_job.get("worker_did") or board_job.get("worker")
        if isinstance(board_worker, str) and room_job["worker_did"] and board_worker != room_job["worker_did"]:
            details["worker_mismatches"].append(job_id)
        board_result_hash = board_job.get("result_hash")
        room_result_hash = board_job.get("room_result_hash")
        if isinstance(board_result_hash, str) and isinstance(room_result_hash, str) and board_result_hash != room_result_hash:
            details["result_hash_mismatches"].append(job_id)
        board_attestations = board_job.get("attestations")
        room_attestation_count = board_job.get("room_attestation_count")
        if isinstance(board_attestations, list) and isinstance(room_attestation_count, int) and len(board_attestations) != room_attestation_count:
            details["attestation_count_differences"].append(job_id)
    summary = {
        "matched_jobs": len(matched),
        "board_only_jobs": len(details["board_only_jobs"]),
        "room_only_jobs": len(details["room_only_jobs"]),
        "status_mismatches": len(details["status_mismatches"]),
        "worker_mismatches": len(details["worker_mismatches"]),
        "result_hash_mismatches": len(details["result_hash_mismatches"]),
        "attestation_count_differences": len(details["attestation_count_differences"]),
        "board_status": "OK" if board_obj is not None else "UNAVAILABLE",
        "status_api": "OK" if status_obj else "UNAVAILABLE",
        "details": details,
    }
    conn.execute(
        """
        INSERT INTO kibble_reconciliation
            (checked_at, matched_jobs, board_only_jobs, room_only_jobs, status_mismatches,
             worker_mismatches, result_hash_mismatches, attestation_count_differences,
             board_status, details_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            utc_now(),
            summary["matched_jobs"],
            summary["board_only_jobs"],
            summary["room_only_jobs"],
            summary["status_mismatches"],
            summary["worker_mismatches"],
            summary["result_hash_mismatches"],
            summary["attestation_count_differences"],
            summary["board_status"],
            json.dumps(details, sort_keys=True, separators=(",", ":")),
        ),
    )
    conn.commit()
    return summary


def kibble_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    cursor = room_cursor(conn, KIBBLE_ROOM)
    counts = {
        row["event_type"] or "UNINTERPRETED": row["count"]
        for row in conn.execute(
            """
            SELECT event_type, COUNT(*) AS count
            FROM kibble_events
            WHERE parse_status = 'KIBBLE_PARSEABLE'
            GROUP BY event_type
            """
        )
    }
    reconciliation = conn.execute(
        "SELECT * FROM kibble_reconciliation ORDER BY checked_at DESC, id DESC LIMIT 1"
    ).fetchone()
    return {
        "mode": kibble_config()["mode"],
        "writes_enabled": kibble_config()["allow_writes"],
        "room_cursor": cursor["last_seq"],
        "room_generation": cursor["generation"],
        "jobs_observed": conn.execute("SELECT COUNT(*) FROM kibble_jobs").fetchone()[0],
        "open_jobs": conn.execute("SELECT COUNT(*) FROM kibble_jobs WHERE status = 'OPEN'").fetchone()[0],
        "claimed_jobs": conn.execute("SELECT COUNT(*) FROM kibble_jobs WHERE status = 'CLAIMED'").fetchone()[0],
        "results_observed": counts.get("RESULT", 0) + counts.get("DELIVER", 0),
        "attestations_observed": counts.get("ATTEST", 0),
        "recognized_event_counts": counts,
        "board_reconciliation": reconciliation["checked_at"] if reconciliation else "(never)",
        "mismatches": (
            reconciliation["status_mismatches"]
            + reconciliation["worker_mismatches"]
            + reconciliation["result_hash_mismatches"]
            + reconciliation["attestation_count_differences"]
            if reconciliation
            else 0
        ),
    }


def print_kibble_summary(conn: sqlite3.Connection) -> None:
    summary = kibble_summary(conn)
    print("Kibble discovery")
    print("----------------")
    print(f"mode: {summary['mode']}")
    print(f"writes enabled: {'YES' if summary['writes_enabled'] else 'NO'}")
    print(f"room cursor: {summary['room_cursor']}")
    print(f"jobs observed: {summary['jobs_observed']}")
    print(f"open jobs: {summary['open_jobs']}")
    print(f"claimed jobs: {summary['claimed_jobs']}")
    print(f"results observed: {summary['results_observed']}")
    print(f"attestations observed: {summary['attestations_observed']}")
    print(f"board reconciliation: {summary['board_reconciliation']}")
    print(f"mismatches: {summary['mismatches']}")
    print("No automatic scoring or claiming. Remote content is UNTRUSTED DATA.")


def kibble_poll(*, reconcile: bool = True, db_path: Path = OBSERVER_DB) -> dict[str, Any]:
    with observer_connect(db_path) as conn:
        poll = service_poll_room(conn, KIBBLE_ROOM, page_size=SERVICE_POLL_PAGE_SIZE, max_pages=SERVICE_POLL_MAX_PAGES_PER_ROOM)
        rebuild_kibble_jobs(conn)
        board_obj = None
        status_obj = None
        status_available = False
        if reconcile:
            try:
                board_obj = fetch_json_url(kibble_config()["board_url"], allow_missing=True)
            except SystemExit:
                board_obj = None
            try:
                status_obj = fetch_json_url(kibble_config()["status_url"], allow_missing=True)
                status_available = bool(status_obj)
            except SystemExit:
                status_obj = None
            reconciliation = reconcile_kibble_board(conn, board_obj, status_obj)
        else:
            reconciliation = {}
        summary = kibble_summary(conn)
    recognized = summary["recognized_event_counts"]
    result = {
        "room_generation": poll["generation"],
        "highest_seq": poll["cursor_after"],
        "records_fetched": poll["records_fetched"],
        "recognized_event_counts": recognized,
        "jobs_reconstructed": summary["jobs_observed"],
        "open_jobs": summary["open_jobs"],
        "board_jobs": len(board_jobs_from_obj(board_obj or {})),
        "reconciliation_mismatches": sum(
            reconciliation.get(key, 0)
            for key in (
                "status_mismatches",
                "worker_mismatches",
                "result_hash_mismatches",
                "attestation_count_differences",
            )
        ) if reconciliation else 0,
        "status_available": status_available,
        "poll": poll,
        "reconciliation": reconciliation,
        "network_writes": 0,
        "private_key_accesses": 0,
        "tclk_settlement_actions": 0,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    print("\nNo Kibble writes performed. No jobs claimed. No results or attestations posted.")
    return result


def kibble_export_jobs(output: Path | None = None, db_path: Path = OBSERVER_DB) -> list[dict[str, Any]]:
    with observer_connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM kibble_jobs ORDER BY job_id").fetchall()
    records = [
        {
            "source": row["source"],
            "job_id": row["job_id"],
            "category": row["category"],
            "title": row["title"],
            "requirements": row["requirements"],
            "poster_did": row["poster_did"],
            "worker_did": row["worker_did"],
            "status": row["status"].lower(),
            "observed_seq": row["observed_seq"],
            "signature_verified": bool(row["signature_verified"]),
            "settlement": {
                "rail": row["settlement_rail"] or "paper",
                "value_backed": False,
            },
        }
        for row in rows
    ]
    text = json.dumps(records, indent=2, sort_keys=True)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
    print(text)
    print("\nNo network writes performed.")
    return records


def ingest_messages(
    conn: sqlite3.Connection,
    room: str,
    raw_messages: list[dict[str, Any]],
    *,
    generation: str | int | None = None,
    source: str = "room-read",
) -> dict[str, int]:
    now = utc_now()
    received = len(raw_messages)
    inserted = 0
    signed_writers: set[str] = set()
    unsigned_writers: set[str] = set()

    for raw in raw_messages:
        evidence = evidence_record_from_message(
            room,
            str(generation) if generation is not None else None,
            raw,
            source=source,
            retrieved_at=now,
        )
        if evidence is not None:
            store_evidence_record(conn, evidence)
        tclk_record = tclk_record_from_message(
            room,
            str(generation) if generation is not None else None,
            raw,
            evidence,
            observed_at=now,
        )
        if tclk_record is not None:
            store_tclk_frame(conn, tclk_record)
        if room == KIBBLE_ROOM:
            kibble_record = kibble_record_from_message(
                room,
                str(generation) if generation is not None else None,
                raw,
                observed_at=now,
            )
            if kibble_record is not None:
                store_kibble_event(conn, kibble_record)
        try:
            seq = int(raw["seq"])
            text = str(raw.get("text", ""))
            stored_normalized = analysis_normalize_text(text)
            stored_template = template_normalize_text(text)
        except (KeyError, TypeError, ValueError):
            continue
        sender = message_sender(raw)
        signed = is_signed_sender(sender)
        if signed:
            signed_writers.add(sender)
        else:
            unsigned_writers.add(sender)
        before = conn.total_changes
        conn.execute(
            """
            INSERT OR IGNORE INTO messages
                (room, seq, timestamp, sender, signed, text, normalized_text,
                 normalized_hash, template_normalized_text, template_normalized_hash,
                 discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                room,
                seq,
                message_timestamp(raw),
                sender,
                1 if signed else 0,
                text,
                stored_normalized,
                hashlib.sha256(stored_normalized.encode("utf-8")).hexdigest(),
                stored_template,
                hashlib.sha256(stored_template.encode("utf-8")).hexdigest(),
                now,
            ),
        )
        if conn.total_changes > before:
            inserted += 1

    max_seq = conn.execute(
        "SELECT MAX(seq) FROM messages WHERE room = ?", (room,)
    ).fetchone()[0]
    conn.execute(
        """
        INSERT INTO rooms (room, first_observed_at, last_observed_at, last_seq)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(room) DO UPDATE SET
            last_observed_at = excluded.last_observed_at,
            last_seq = COALESCE(excluded.last_seq, rooms.last_seq)
        """,
        (room, now, now, max_seq),
    )
    conn.commit()
    return {
        "received": received,
        "inserted": inserted,
        "signed_writers": len(signed_writers),
        "unsigned_writers": len(unsigned_writers),
    }


def import_local_history(conn: sqlite3.Connection) -> int:
    did = own_did_or_none()
    if not did:
        return 0
    imported = 0
    now = utc_now()

    if LOG_FILE.exists():
        with LOG_FILE.open("r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("event") != "signed_message" or record.get("did") != did:
                    continue
                imported += import_local_activity_record(
                    conn,
                    "activity",
                    f"activity:{line_no}",
                    did,
                    record.get("room"),
                    record.get("seq"),
                    record.get("nonce"),
                    record.get("text"),
                    record.get("ts"),
                    now,
                )

    if EVIDENCE_DIR.exists():
        for path in sorted(EVIDENCE_DIR.glob("*.json")):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if record.get("did") != did:
                continue
            imported += import_local_activity_record(
                conn,
                "evidence",
                f"evidence:{path.name}",
                did,
                record.get("room"),
                record.get("seq"),
                record.get("nonce"),
                record.get("stored_text") or record.get("text"),
                record.get("created_at"),
                now,
            )

    conn.commit()
    migrate_legacy_local_activity_to_evidence(conn)
    return imported


def import_local_activity_record(
    conn: sqlite3.Connection,
    source: str,
    source_key: str,
    did: str,
    room: Any,
    seq: Any,
    nonce: Any,
    text: Any,
    created_at: Any,
    imported_at: str,
) -> int:
    if not room or text is None:
        return 0
    try:
        room_value = valid_room(str(room))
        text_value = str(text)
        normalized = analysis_normalize_text(text_value)
        template_normalized = template_normalize_text(text_value)
        seq_value = int(seq) if seq is not None else None
        nonce_value = int(nonce) if nonce is not None else None
    except (TypeError, ValueError):
        return 0
    before = conn.total_changes
    conn.execute(
        """
        INSERT OR IGNORE INTO local_signed_activity
            (source, source_key, did, room, seq, nonce, text, normalized_text,
             normalized_hash, template_normalized_text, template_normalized_hash,
             created_at, imported_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            source,
            source_key,
            did,
            room_value,
            seq_value,
            nonce_value,
            text_value,
            normalized,
            hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
            template_normalized,
            hashlib.sha256(template_normalized.encode("utf-8")).hexdigest(),
            str(created_at) if created_at is not None else None,
            imported_at,
        ),
    )
    return 1 if conn.total_changes > before else 0


def migrate_legacy_local_activity_to_evidence(conn: sqlite3.Connection) -> int:
    rows = conn.execute(
        """
        SELECT did, room, seq, nonce, text, created_at, source, source_key
        FROM local_signed_activity
        WHERE seq IS NOT NULL
        """
    ).fetchall()
    inserted = 0
    for row in rows:
        raw: dict[str, Any] = {
            "seq": row["seq"],
            "from": row["did"],
            "did": row["did"],
            "nonce": row["nonce"],
            "text": row["text"],
        }
        if row["created_at"]:
            raw["ts"] = row["created_at"]
        before = conn.total_changes
        record = evidence_record_from_message(
            row["room"],
            UNKNOWN_LEGACY_GENERATION,
            raw,
            source=f"legacy-local-{row['source']}:{row['source_key']}",
            retrieved_at=utc_now(),
        )
        if record is None:
            continue
        if record["verification_status"] == "SIGNATURE_PRESENT_UNVERIFIED":
            record["verification_status"] = "LEGACY_SERVER_VERIFIED_NO_SIGNATURE"
        store_evidence_record(conn, record)
        if conn.total_changes > before:
            inserted += 1
    conn.commit()
    return inserted


CAPABILITY_TAXONOMY = [
    "Technocore API behavior",
    "signed POST verification",
    "Ed25519 DID handling",
    "protocol-change detection",
    "message normalization",
    "API compatibility",
    "reproducibility testing",
    "observer/network analytics",
    "untrusted-input / prompt-injection safety",
    "documentation validation",
]
OUT_OF_SCOPE_RE = re.compile(
    r"\b(smart[- ]?contract|contract audit|solidity|token audit|wallet drain|claim bot|"
    r"airdrop claim|swap|bridge|staking|trade|trading|price prediction)\b",
    re.I,
)
NOISE_PATTERN_GROUPS: dict[str, list[str]] = {
    "check_in": [
        r"\bhello technocore\b",
        r"\bchecking in\b",
        r"\bcheck[- ]?in\b",
        r"\bpresent and signed\b",
        r"\bping\b.*\bdid\b",
        r"\bmaintain(?:ing)? my did\b",
        r"\bdid identity is maintained\b",
    ],
    "airdrop_or_token": [
        r"\bready for \$?flop\b",
        r"\bairdrop\b",
        r"\bclaim\b",
        r"\breward\b",
        r"\bwen\b",
        r"\bmoon\b",
        r"\bstaking\b",
        r"\bswap\b",
        r"\bbridge\b",
    ],
    "identity_announcement": [
        r"\bdid:key:z[1-9a-km-zA-HJ-NP-Z]{20,}\b",
        r"\bautonomous agent active\b",
        r"\bagentic economy\b",
        r"\bidentity announcement\b",
    ],
    "promotion": [
        r"\bpowered by\b",
        r"\bpromo\b",
        r"\breferral\b",
        r"\bfollow back\b",
        r"\bengagement\b",
        r"\bi published a technocore contribution\b",
        r"\bactivity update from did\b",
        r"\bactivity update for did\b",
        r"\bmade something for anyone\b",
        r"\bguide:\s*<url>",
        r"\bavailable as a kv note\b",
        r"\badding notes on\b",
        r"\bx\.com\b",
    ],
}


def has_word(text: str, word: str) -> bool:
    return re.search(rf"\b{re.escape(word)}\b", text, re.I) is not None


def has_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text, re.I) for pattern in patterns)


def noise_flags_for(normalized: str) -> list[str]:
    flags = []
    for group, patterns in NOISE_PATTERN_GROUPS.items():
        if any(re.search(pattern, normalized, re.I) for pattern in patterns):
            flags.append(group)
    return flags


def request_signals_for(text: str, normalized: str) -> list[str]:
    text_without_urls = re.sub(r"https?://\S+|www\.\S+", "<url>", text)
    haystack = f"{text_without_urls}\n{normalized}"
    bug_haystack = re.sub(r"\bnot a bug\b", "", haystack, flags=re.I)
    signals = []
    direct_patterns = [
        ("question mark", r"\?"),
        ("can someone", r"\bcan someone\b"),
        ("has anyone", r"\bhas anyone\b"),
        ("help", r"\bhelp\b"),
        ("how do", r"\bhow do\b"),
        ("why", r"(^|\n)\s*why\b|\?\s*why\b"),
        ("need", r"\bneed(?:ed)?\b"),
        ("error", r"\berror\b"),
        ("failure", r"\b(failure|failed|failing|fail)\b"),
        ("reproduce", r"\b(reproduce|repro)\b"),
        ("unexpected behavior", r"\bunexpected behavior\b"),
    ]
    contextual_patterns = [
        ("verify", r"\b(can someone|has anyone|please|need(?:ed)?|help).{0,80}\bverify\b|\bverify\b.{0,80}\?"),
        ("test", r"\b(can someone|has anyone|please|need(?:ed)?|help).{0,80}\b(test|tested|testing)\b|\btest(?:ed|ing)?\b.{0,80}\?|\btest whether\b|\btest if\b"),
        ("compatibility", r"\b(can someone|has anyone|please|need(?:ed)?|help).{0,80}\bcompatib|\bcompatib\w*\b.{0,80}\?"),
    ]
    for label, pattern in direct_patterns + contextual_patterns:
        if re.search(pattern, haystack, re.I):
            signals.append(label)
    if re.search(r"\bbug\b", bug_haystack, re.I):
        signals.append("bug")
    return signals


def request_strength_for(text: str, normalized: str) -> tuple[str, list[str]]:
    text_without_urls = re.sub(r"https?://\S+|www\.\S+", "<url>", text)
    haystack = f"{text_without_urls}\n{normalized}"
    signal_haystack = re.sub(r"\bnot a bug\b", "", haystack, flags=re.I)
    strong_patterns = [
        ("has anyone", r"\bhas anyone\b"),
        ("can someone", r"\bcan someone\b"),
        ("could someone", r"\bcould someone\b"),
        ("can anybody", r"\bcan anybody\b"),
        ("how do", r"\bhow do\b"),
        ("how can", r"\bhow can\b"),
        ("why does", r"\bwhy does\b"),
        ("what causes", r"\bwhat causes\b"),
        ("does anyone know", r"\bdoes anyone know\b"),
        ("can you reproduce", r"\bcan you reproduce\b"),
        ("can someone verify", r"\bcan someone verify\b"),
        ("can someone test", r"\bcan someone test\b"),
        ("help", r"\bhelp\b"),
        ("error", r"\berror\b"),
        ("fails", r"\bfails?\b|\bfailing\b|\bfailed\b"),
        ("failure", r"\bfailure\b"),
        ("unexpected", r"\bunexpected\b"),
        ("bug", r"\bbug\b"),
        ("issue", r"\bissue\b"),
        ("not working", r"\bnot working\b"),
        ("mismatch", r"\bmismatch\b"),
        ("reproduce", r"\breproduce\b|\breproduced\b|\breproducing\b"),
    ]
    contextual_patterns = [
        ("verify", r"\b(can someone|could someone|has anyone|please|need(?:ed)?|help).{0,80}\bverify\b|\bverify\b.{0,80}\?"),
        ("test", r"\b(can someone|could someone|has anyone|please|need(?:ed)?|help).{0,80}\b(test|tested|testing)\b|\btest whether\b|\btest if\b"),
    ]
    matches = [
        label
        for label, pattern in strong_patterns + contextual_patterns
        if re.search(pattern, signal_haystack, re.I)
    ]
    if matches:
        return "STRONG", matches
    if "?" in text_without_urls:
        return "WEAK", ["topic-fragment question"]
    return "NONE", []


def unresolved_problem_for(normalized: str, request_strength: str) -> tuple[str, list[str]]:
    resolved_patterns = [
        r"\blikely just\b",
        r"\bprobably just\b",
        r"\bstill solid\b",
        r"\blooks stable\b",
        r"\bworks? (?:fine|now)\b",
        r"\bnot a bug\b",
        r"\bresolved\b",
        r"\bfixed\b",
    ]
    if has_any(normalized, resolved_patterns):
        return "NO", ["sender supplied likely explanation or resolution"]
    unresolved_patterns = [
        r"\bhttp\s*400\b",
        r"\breturns?\s+400\b",
        r"\berror\b",
        r"\bfails?\b|\bfailing\b|\bfailed\b",
        r"\bfailure\b",
        r"\bbug\b",
        r"\bissue\b",
        r"\bnot working\b",
        r"\bmismatch\b",
        r"\bunexpected\b",
        r"\bregression\b",
        r"\bstarted failing\b",
        r"\bcan someone reproduce\b",
        r"\bhas anyone reproduced\b",
    ]
    if has_any(normalized, unresolved_patterns):
        return "YES", ["active failure/problem language"]
    if request_strength == "STRONG" and has_any(normalized, [r"\bwhether\b", r"\bchanged\b", r"\bpreserve\b"]):
        return "YES", ["asks for unresolved verification"]
    if request_strength == "STRONG":
        return "PARTIAL", ["request is present but problem details are limited"]
    return "NO", ["no unresolved problem described"]


def capability_match_for(normalized: str) -> tuple[str, str]:
    if OUT_OF_SCOPE_RE.search(normalized):
        return "OUT_OF_SCOPE", "outside FLOP Scout capability taxonomy"
    signed_post_terms = has_any(normalized, [r"\bsigned post\b", r"\bpost\b"])
    signing_terms = has_any(normalized, [r"\bsigned\b", r"\bsignature\b", r"\bsig\b", r"\bverify\b", r"\bverification\b"])
    api_terms = has_any(normalized, [r"\bresponses?\b", r"\bhttp\b", r"\b400\b", r"\bapi\b", r"\bendpoint\b", r"\brequest\b"])
    if signed_post_terms and signing_terms and api_terms:
        return "HIGH", "signed POST verification"
    if has_word(normalized, "did") and has_any(
        normalized,
        [r"\bkey\b", r"\brotation\b", r"\bed25519\b", r"\bpublic key\b", r"\bsignature\b"],
    ):
        return "HIGH", "Ed25519 DID handling"
    if "did:key" in normalized:
        return "HIGH", "Ed25519 DID handling"
    if has_any(normalized, [r"\bauth\.md\b", r"\bllms\.txt\b", r"\bpatterns\.md\b"]) or (
        has_any(normalized, [r"\bdocs?\b", r"\bspec\b", r"\bversion\b", r"\bendpoint behavior\b"])
        and has_any(normalized, [r"\bchanged\b", r"\bdeprecated\b", r"\brequirements?\b"])
    ):
        return "HIGH", "protocol-change detection"
    if has_any(normalized, [r"\bnormaliz", r"\btemplate\b", r"\bduplicate\b", r"\bhash\b", r"\bwhitespace\b"]):
        return "HIGH", "message normalization"
    if has_any(normalized, [r"\bapi\b", r"\bendpoint\b", r"\bresponse\b", r"\brequest\b", r"\bhttp\b"]) and has_any(
        normalized,
        [r"\bmismatch\b", r"\bunexpected\b", r"\bfails?\b", r"\bbug\b", r"\btest\b", r"\brepro", r"\bcompatib"],
    ):
        return "HIGH", "API compatibility"
    if has_any(normalized, [r"\brepro", r"\btest\b", r"\bverify\b", r"\bcompare\b", r"\bconfirm\b"]) and has_any(
        normalized,
        [r"\berror\b", r"\bfails?\b", r"\bmismatch\b", r"\bunexpected\b", r"\bpreserve\b", r"\bchanged\b"],
    ):
        return "HIGH", "reproducibility testing"
    if has_any(normalized, [r"\bobserver\b", r"\bnetwork analytics\b", r"\binteraction graph\b", r"\breciprocal\b", r"\bbreadth\b"]):
        return "HIGH", "observer/network analytics"
    if has_any(normalized, [r"\bprompt injection\b", r"\bmalicious instruction\b", r"\buntrusted input\b", r"\bunsafe url\b", r"\bremote commands?\b", r"\bhostile content\b"]):
        return "HIGH", "untrusted-input / prompt-injection safety"
    if has_any(normalized, [r"\bdocs?\b", r"\breadme\b", r"\bdocumentation\b"]) and has_any(
        normalized,
        [r"\bvalidate\b", r"\bwrong\b", r"\bchanged\b", r"\bmismatch\b", r"\bunclear\b"],
    ):
        return "HIGH", "documentation validation"
    return "LOW", "generic request; no strong FLOP Scout capability match"


def actionability_for(
    normalized: str,
    request_strength: str,
    unresolved_problem: str,
    capability_match: str,
    capability: str,
) -> tuple[str, list[str]]:
    if capability_match == "OUT_OF_SCOPE":
        return "NO", ["outside FLOP Scout capabilities"]
    if request_strength != "STRONG":
        return "NO", ["weak or absent request intent"]
    if unresolved_problem == "NO":
        return "NO", ["no unresolved problem to investigate"]
    if capability_match != "HIGH":
        return "PARTIAL", ["request exists but FLOP Scout capability match is weak"]
    evidence_terms = [
        r"\bsigned post\b",
        r"\bhttp\s*400\b",
        r"\bresponse\b",
        r"\bapi\b",
        r"\bendpoint\b",
        r"\bauth\.md\b",
        r"\bllms\.txt\b",
        r"\bpatterns\.md\b",
        r"\bnormaliz",
        r"\brepro",
        r"\bverify\b",
        r"\btest\b",
        r"\bmismatch\b",
        r"\bunexpected\b",
        r"\bchanged\b",
    ]
    if has_any(normalized, evidence_terms):
        return "YES", [f"can produce concrete evidence for {capability}"]
    return "PARTIAL", ["capability matches, but requested work is underspecified"]


def classify_opportunity(
    sender: str,
    text: str,
    normalized_duplicate_count: int = 1,
    distinct_dids_using_template: int = 1,
    source_room: str | None = None,
) -> dict[str, Any]:
    normalized = analysis_normalize_text(text)
    signed = is_signed_sender(sender)
    noise_flags = noise_flags_for(normalized)
    request_strength, request_signals = request_strength_for(text, normalized)
    unresolved_problem, unresolved_reasons = unresolved_problem_for(normalized, request_strength)
    capability_match, capability = capability_match_for(normalized)
    actionability, actionability_reasons = actionability_for(
        normalized,
        request_strength,
        unresolved_problem,
        capability_match,
        capability,
    )
    original = distinct_dids_using_template < 2

    if distinct_dids_using_template >= 2:
        noise_flags.append("repeated_signed_template")
    if source_room == MAILBOX_ROOM and not signed:
        noise_flags.append("unsigned_mailbox_message")

    category = capability if capability_match != "LOW" else "General request"
    reason_parts = []
    if request_signals:
        reason_parts.append(f"{request_strength.lower()} request/problem signal: " + ", ".join(request_signals))
    reason_parts.append(f"unresolved problem: {unresolved_problem}")
    reason_parts.extend(unresolved_reasons)
    if capability_match != "LOW":
        reason_parts.append(f"capability match: {capability}")
    reason_parts.append(f"actionability: {actionability}")
    reason_parts.extend(actionability_reasons)
    if signed:
        reason_parts.append("from a signed DID")
    if source_room == MAILBOX_ROOM and signed:
        reason_parts.append("direct signed mailbox contact")
    rejection_reasons: list[str] = []
    if not signed:
        rejection_reasons.append("sender is not signed")
    if request_strength != "STRONG":
        rejection_reasons.append("weak request signal" if request_strength == "WEAK" else "no request signal")
    if unresolved_problem != "YES":
        rejection_reasons.append("no unresolved failure" if unresolved_problem == "NO" else "only partially unresolved")
    if capability_match != "HIGH":
        rejection_reasons.append("capability match is not HIGH")
    if actionability != "YES":
        rejection_reasons.append("not concretely actionable")
    if distinct_dids_using_template >= 2:
        rejection_reasons.append("template family used by multiple signed DIDs")
    if noise_flags:
        rejection_reasons.append("noise/promo/template flags: " + ", ".join(noise_flags))

    if noise_flags and request_strength != "STRONG":
        tier = "NOISE"
        confidence = 0.05
    elif capability_match == "OUT_OF_SCOPE":
        tier = "OUT_OF_SCOPE"
        confidence = 0.35 if request_strength == "STRONG" else 0.10
    elif noise_flags:
        tier = "NOISE"
        confidence = 0.08
    elif request_strength == "NONE":
        tier = "LOW"
        confidence = 0.25 if capability_match == "HIGH" else 0.15
    elif (
        signed
        and request_strength == "STRONG"
        and unresolved_problem == "YES"
        and capability_match == "HIGH"
        and actionability == "YES"
        and distinct_dids_using_template < 2
    ):
        tier = "HIGH"
        confidence = 0.91
    elif request_strength == "STRONG" and capability_match == "HIGH" and actionability in {"YES", "PARTIAL"}:
        tier = "MEDIUM"
        confidence = 0.62
    elif request_strength == "STRONG":
        tier = "LOW"
        confidence = 0.42
    else:
        tier = "LOW"
        confidence = 0.20
    if source_room == MAILBOX_ROOM and signed and tier in {"HIGH", "MEDIUM", "LOW"}:
        confidence = min(0.95, confidence + 0.03)

    return {
        "category": category,
        "reason": "; ".join(reason_parts),
        "confidence": confidence,
        "tier": tier,
        "signed_status": "SIGNED" if signed else "UNSIGNED",
        "request_signal": "YES" if request_strength == "STRONG" else ("WEAK" if request_strength == "WEAK" else "NO"),
        "request_strength": request_strength,
        "unresolved_problem": unresolved_problem,
        "actionability": actionability,
        "normalized_duplicate_count": normalized_duplicate_count,
        "distinct_dids_using_template": distinct_dids_using_template,
        "originality_classification": "UNIQUE" if original else "REPEATED_TEMPLATE",
        "template_message_count": normalized_duplicate_count,
        "template_distinct_dids": distinct_dids_using_template,
        "template_originality_classification": "UNIQUE" if original else "REPEATED_TEMPLATE",
        "capability_match": capability_match,
        "noise_flags": ", ".join(noise_flags) if noise_flags else "NONE",
        "rejection_reasons": "; ".join(rejection_reasons),
    }


def refresh_opportunities(conn: sqlite3.Connection) -> int:
    rows = conn.execute(
        """
        SELECT m.*, (
            SELECT COUNT(*)
            FROM messages d
            WHERE d.normalized_hash = m.normalized_hash
        ) AS exact_duplicate_count, (
            SELECT COUNT(DISTINCT sender)
            FROM messages d
            WHERE d.normalized_hash = m.normalized_hash AND d.signed = 1
        ) AS exact_sender_count, (
            SELECT COUNT(*)
            FROM messages d
            WHERE d.template_normalized_hash = m.template_normalized_hash
        ) AS template_count, (
            SELECT COUNT(DISTINCT sender)
            FROM messages d
            WHERE d.template_normalized_hash = m.template_normalized_hash AND d.signed = 1
        ) AS template_sender_count
        FROM messages m
        ORDER BY m.room, m.seq
        """
    ).fetchall()
    inserted = 0
    now = utc_now()
    for row in rows:
        result = classify_opportunity(
            row["sender"],
            row["text"],
            normalized_duplicate_count=int(row["exact_duplicate_count"]),
            distinct_dids_using_template=int(row["exact_sender_count"]),
            source_room=row["room"],
        )
        result["exact_distinct_dids"] = int(row["exact_sender_count"])
        result["template_message_count"] = int(row["template_count"])
        result["template_distinct_dids"] = int(row["template_sender_count"])
        result["template_originality_classification"] = (
            "UNIQUE" if int(row["template_sender_count"]) < 2 else "REPEATED_TEMPLATE"
        )
        if int(row["template_sender_count"]) >= 2 and "repeated_template_family" not in result["noise_flags"]:
            result["noise_flags"] = (
                "repeated_template_family"
                if result["noise_flags"] == "NONE"
                else result["noise_flags"] + ", repeated_template_family"
            )
            if result["tier"] in {"HIGH", "MEDIUM"}:
                result["tier"] = "NOISE"
                result["confidence"] = 0.08
            if result["rejection_reasons"]:
                result["rejection_reasons"] += "; template family used by multiple signed DIDs"
            else:
                result["rejection_reasons"] = "template family used by multiple signed DIDs"
        before = conn.total_changes
        conn.execute(
            """
            INSERT INTO opportunities
                (room, seq, sender, message_text, category, reason, confidence,
                 tier, signed_status, request_signal, normalized_duplicate_count,
                 distinct_dids_using_template, exact_distinct_dids, originality_classification,
                 capability_match, actionability, unresolved_problem, request_strength,
                 template_message_count, template_distinct_dids,
                 template_originality_classification, rejection_reasons, noise_flags,
                 status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?)
            ON CONFLICT(room, seq) DO UPDATE SET
                sender = excluded.sender,
                message_text = excluded.message_text,
                category = excluded.category,
                reason = excluded.reason,
                confidence = excluded.confidence,
                tier = excluded.tier,
                signed_status = excluded.signed_status,
                request_signal = excluded.request_signal,
                normalized_duplicate_count = excluded.normalized_duplicate_count,
                distinct_dids_using_template = excluded.distinct_dids_using_template,
                exact_distinct_dids = excluded.exact_distinct_dids,
                originality_classification = excluded.originality_classification,
                capability_match = excluded.capability_match,
                actionability = excluded.actionability,
                unresolved_problem = excluded.unresolved_problem,
                request_strength = excluded.request_strength,
                template_message_count = excluded.template_message_count,
                template_distinct_dids = excluded.template_distinct_dids,
                template_originality_classification = excluded.template_originality_classification,
                rejection_reasons = excluded.rejection_reasons,
                noise_flags = excluded.noise_flags
            """,
            (
                row["room"],
                row["seq"],
                row["sender"],
                row["text"],
                result["category"],
                result["reason"],
                result["confidence"],
                result["tier"],
                result["signed_status"],
                result["request_signal"],
                result["normalized_duplicate_count"],
                result["distinct_dids_using_template"],
                result["exact_distinct_dids"],
                result["originality_classification"],
                result["capability_match"],
                result["actionability"],
                result["unresolved_problem"],
                result["request_strength"],
                result["template_message_count"],
                result["template_distinct_dids"],
                result["template_originality_classification"],
                result["rejection_reasons"],
                result["noise_flags"],
                now,
            ),
        )
        if conn.total_changes > before:
            inserted += 1
    conn.commit()
    return inserted


def rebuild_interactions(conn: sqlite3.Connection, window: int = INTERACTION_WINDOW) -> None:
    conn.execute("DELETE FROM interactions")
    now = utc_now()
    rooms = [row[0] for row in conn.execute("SELECT room FROM rooms ORDER BY room")]
    for room in rooms:
        rows = conn.execute(
            """
            SELECT room, seq, timestamp, sender
            FROM messages
            WHERE room = ? AND signed = 1
            ORDER BY seq
            """,
            (room,),
        ).fetchall()
        for i, source in enumerate(rows):
            for response in rows[i + 1 : i + 1 + window]:
                if response["sender"] == source["sender"]:
                    continue
                distance = int(response["seq"]) - int(source["seq"])
                confidence = max(0.2, 0.75 - (max(distance, 1) - 1) * 0.08)
                conn.execute(
                    """
                    INSERT OR IGNORE INTO interactions
                        (source_did, target_did, room, source_seq, response_seq,
                         source_timestamp, response_timestamp, relationship_type,
                         confidence, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        source["sender"],
                        response["sender"],
                        room,
                        source["seq"],
                        response["seq"],
                        source["timestamp"],
                        response["timestamp"],
                        f"subsequent_signed_post_within_{window}_signed_messages",
                        confidence,
                        now,
                    ),
                )
    conn.commit()


def own_did_or_none() -> str | None:
    try:
        return load_meta()["did"]
    except SystemExit:
        return None


def local_history_stats(conn: sqlite3.Connection, did: str | None = None) -> dict[str, Any]:
    if did is None:
        did = own_did_or_none()
    if not did:
        return {
            "known_signed_posts": 0,
            "known_unique": 0,
            "known_exact_dupes": 0,
            "known_rooms": 0,
            "known_hashes": set(),
        }
    rows = conn.execute(
        "SELECT source_key, normalized_hash, room, seq FROM local_signed_activity WHERE did = ?",
        (did,),
    ).fetchall()
    unique_posts: dict[str, sqlite3.Row] = {}
    for row in rows:
        post_key = f"{row['room']}:{row['seq']}" if row["seq"] is not None else row["source_key"]
        unique_posts[post_key] = row
    post_rows = list(unique_posts.values())
    hashes = {row["normalized_hash"] for row in post_rows}
    return {
        "known_signed_posts": len(post_rows),
        "known_unique": len(hashes),
        "known_exact_dupes": len(post_rows) - len(hashes),
        "known_rooms": len({row["room"] for row in post_rows}),
        "known_hashes": hashes,
    }


def originality_stats(conn: sqlite3.Connection, did: str | None = None) -> dict[str, Any]:
    if did is None:
        did = own_did_or_none()
    local = local_history_stats(conn, did)
    observer_total = observer_unique = own_matching_other = observer_exact_dupes = 0
    combined_hashes = set(local["known_hashes"])
    if did:
        observer_total = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE sender = ?", (did,)
        ).fetchone()[0]
        observer_hashes = {
            row[0]
            for row in conn.execute(
                "SELECT DISTINCT normalized_hash FROM messages WHERE sender = ?", (did,)
            )
        }
        observer_unique = len(observer_hashes)
        combined_hashes |= observer_hashes
        observer_exact_dupes = observer_total - observer_unique
        own_matching_other = conn.execute(
            """
            SELECT COUNT(*)
            FROM messages own
            WHERE own.sender = ?
              AND EXISTS (
                SELECT 1 FROM messages other
                WHERE other.normalized_hash = own.normalized_hash
                  AND other.sender <> own.sender
              )
            """,
            (did,),
        ).fetchone()[0]
    network_total = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    repeated = conn.execute(
        """
        SELECT COALESCE(SUM(cnt), 0)
        FROM (
            SELECT COUNT(*) AS cnt
            FROM messages
            GROUP BY normalized_hash
            HAVING COUNT(*) > 1
        )
        """
    ).fetchone()[0]
    template_repeated = conn.execute(
        """
        SELECT COALESCE(SUM(cnt), 0)
        FROM (
            SELECT COUNT(*) AS cnt
            FROM messages
            GROUP BY template_normalized_hash
            HAVING COUNT(*) > 1
        )
        """
    ).fetchone()[0]
    combined_total = local["known_signed_posts"] + observer_total
    combined_unique = len(combined_hashes)
    unique_ratio = (combined_unique / combined_total) if combined_total else 0.0
    return {
        "did": did,
        "own_total": combined_total,
        "own_unique": combined_unique,
        "exact_dupes": local["known_exact_dupes"] + observer_exact_dupes,
        "known_signed_posts": local["known_signed_posts"],
        "known_unique": local["known_unique"],
        "observer_seen_own_messages": observer_total,
        "observer_seen_own_unique": observer_unique,
        "own_matching_other": own_matching_other,
        "unique_ratio": unique_ratio,
        "network_total": network_total,
        "network_repeated": repeated,
        "network_repeated_share": (repeated / network_total) if network_total else 0.0,
        "network_template_repeated": template_repeated,
        "network_template_repeated_share": (template_repeated / network_total) if network_total else 0.0,
    }


def network_stats(conn: sqlite3.Connection, did: str | None = None) -> dict[str, Any]:
    if did is None:
        did = own_did_or_none()
    rebuild_interactions(conn)
    observer_seen_own = 0
    observed_rooms_participated = 0
    responders: set[str] = set()
    responded_to: set[str] = set()
    reciprocal: set[str] = set()
    local = local_history_stats(conn, did)
    if did:
        observer_seen_own = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE sender = ? AND signed = 1", (did,)
        ).fetchone()[0]
        observed_rooms_participated = conn.execute(
            "SELECT COUNT(DISTINCT room) FROM messages WHERE sender = ?", (did,)
        ).fetchone()[0]
        responders = {
            row[0]
            for row in conn.execute(
                "SELECT DISTINCT target_did FROM interactions WHERE source_did = ?", (did,)
            )
        }
        responded_to = {
            row[0]
            for row in conn.execute(
                "SELECT DISTINCT source_did FROM interactions WHERE target_did = ?", (did,)
            )
        }
        reciprocal = responders & responded_to
    encountered = conn.execute(
        "SELECT COUNT(DISTINCT sender) FROM messages WHERE signed = 1"
    ).fetchone()[0]
    return {
        "did": did,
        "known_signed_posts": local["known_signed_posts"],
        "observer_seen_own_messages": observer_seen_own,
        "observed_signed_dids": encountered,
        "responders": len(responders),
        "responded_to": len(responded_to),
        "likely_responders": len(responders),
        "dids_responded_to": len(responded_to),
        "reciprocal": len(reciprocal),
        "observed_rooms_participated": observed_rooms_participated,
        "known_rooms_participated": local["known_rooms"],
    }


def experimental_score(conn: sqlite3.Connection, did: str | None = None, cap: int = 8) -> dict[str, float]:
    stats = network_stats(conn, did)
    originality = originality_stats(conn, did)["unique_ratio"]
    breadth = min(float(stats["responders"]), float(cap))
    reciprocity = (
        min(1.0, stats["reciprocal"] / stats["responders"])
        if stats["responders"]
        else 0.0
    )
    score = breadth * originality * (0.5 + 0.5 * reciprocity)
    return {
        "credit": breadth,
        "originality": originality,
        "reciprocity": reciprocity,
        "experimental_network_quality_score": score,
    }


def duplicate_policy_from_config(obj: dict[str, Any]) -> dict[str, int]:
    source = obj.get("settings") if isinstance(obj.get("settings"), dict) else obj
    policy: dict[str, int] = {}
    for key in CONFIG_DUPLICATE_KEYS:
        value = source.get(key)
        if isinstance(value, bool):
            raise ValueError(f"{key} must be an integer.")
        try:
            int_value = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key} must be an integer.") from exc
        if int_value < 0:
            raise ValueError(f"{key} must be non-negative.")
        policy[key] = int_value
    return policy


def fetch_duplicate_policy() -> dict[str, int]:
    req = urllib.request.Request(
        f"{BASE_URL}/config",
        method="GET",
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
    )
    obj = request_json(req)
    try:
        return duplicate_policy_from_config(obj)
    except ValueError as exc:
        raise SystemExit(f"Technocore /config did not contain a safe duplicate policy: {exc}") from exc


def duplicate_preflight(conn: sqlite3.Connection, room: str, text: str) -> dict[str, Any]:
    room = valid_room(room)
    exact_hash = normalized_hash(text)
    templ_hash = template_hash(text)
    exact_matches = conn.execute(
        """
        SELECT COUNT(*)
        FROM messages
        WHERE room = ? AND normalized_hash = ?
        """,
        (room, exact_hash),
    ).fetchone()[0]
    template_messages = conn.execute(
        """
        SELECT COUNT(*)
        FROM messages
        WHERE room = ? AND template_normalized_hash = ?
        """,
        (room, templ_hash),
    ).fetchone()[0]
    template_distinct_dids = conn.execute(
        """
        SELECT COUNT(DISTINCT sender)
        FROM messages
        WHERE room = ?
          AND template_normalized_hash = ?
          AND signed = 1
        """,
        (room, templ_hash),
    ).fetchone()[0]
    known_template = template_messages > 0
    repeated_template = template_distinct_dids >= 2 or template_messages >= 2
    if exact_matches > 0 or repeated_template:
        risk = "HIGH"
    elif known_template:
        risk = "MEDIUM"
    else:
        risk = "LOW"
    return {
        "exact_matches": int(exact_matches),
        "template_messages": int(template_messages),
        "template_distinct_dids": int(template_distinct_dids),
        "template_originality": "REPEATED" if known_template else "UNIQUE",
        "risk": risk,
        "known_template": known_template,
        "normalized_hash": exact_hash,
        "template_hash": templ_hash,
    }


def print_duplicate_preflight(stats: dict[str, Any]) -> None:
    print("\nOriginality preflight")
    print("---------------------")
    print(f"Exact matches recently observed:      {stats['exact_matches']}")
    print(f"Near-template family messages:        {stats['template_messages']}")
    print(f"Distinct DIDs using template:         {stats['template_distinct_dids']}")
    print(f"Template originality:            {stats['template_originality']}")
    print(f"Risk of Technocore 422:           {stats['risk']}")
    if stats["template_distinct_dids"] >= 2 or stats["known_template"]:
        print(
            "\nWARNING:\n"
            "This message resembles recent Technocore traffic.\n"
            "It may be refused by the server's duplicate-content filter and may not represent\n"
            "a useful original contribution."
        )


def duplicate_preflight_for(room: str, text: str) -> dict[str, Any]:
    if OBSERVER_DB.exists():
        conn = sqlite3.connect(f"file:{OBSERVER_DB}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
    else:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        init_observer_db(conn)
    try:
        return duplicate_preflight(conn, room, text)
    finally:
        conn.close()


def log_duplicate_refusal(room: str, did: str, nonce: int, text: str, body: str) -> None:
    log(
        "signed_message_rejected",
        room=room,
        did=did,
        nonce=nonce,
        exact_text_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        normalized_hash=normalized_hash(text),
        template_hash=template_hash(text),
        http_status=422,
        response_body_untrusted=body[:4000],
        outcome="rejected_duplicate",
    )


def duplicate_policy() -> None:
    policy = fetch_duplicate_policy()
    print("Technocore Duplicate Policy")
    print(f"dupe_filter_seconds: {policy['dupe_filter_seconds']}")
    print(f"dupe_max_copies: {policy['dupe_max_copies']}")
    print(f"dupe_min_length: {policy['dupe_min_length']}")
    print("\nNo network writes performed.")


def valid_validation_id(validation_id: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", validation_id):
        raise ValueError("Invalid validation ID.")
    return validation_id


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def message_after_validation(row: sqlite3.Row, watch: sqlite3.Row) -> bool:
    if row["room"] == watch["outbound_room"]:
        return int(row["seq"]) > int(watch["outbound_seq"])
    outbound_ts = parse_timestamp(watch["outbound_timestamp"])
    message_ts = parse_timestamp(row["timestamp"])
    if outbound_ts is not None and message_ts is not None:
        return message_ts > outbound_ts
    return True


VALIDATION_RELATED_PATTERNS = [
    r"\bvalidat",
    r"\bresponse\b",
    r"\breply\b",
    r"\bconfirm",
    r"\bverified?\b",
    r"\btested?\b",
    r"\brepro",
    r"\bresult\b",
    r"\bpass(?:ed)?\b",
    r"\bfail(?:ed|ing)?\b",
    r"\bapi\b",
    r"\bsign(?:ed|ing|ature)?\b",
    r"\bdid\b",
    r"\bnonce\b",
    r"\btechnocore\b",
]


def validation_related_text(text: str) -> bool:
    normalized = analysis_normalize_text(text)
    return has_any(normalized, VALIDATION_RELATED_PATTERNS)


def classify_validation_message(watch: sqlite3.Row, row: sqlite3.Row) -> str | None:
    text = row["text"]
    sender = row["sender"]
    validation_id_present = watch["validation_id"].casefold() in text.casefold()
    if not message_after_validation(row, watch):
        return None
    if validation_id_present and sender != watch["target_did"]:
        return "WRONG_DID_RESPONSE"
    if sender != watch["target_did"]:
        return None
    if validation_id_present:
        return "EXACT_RESPONSE"
    if validation_related_text(text):
        return "POSSIBLE_RESPONSE"
    return "UNRELATED_TARGET_ACTIVITY"


def store_validation_responses(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    now = utc_now()
    watches = conn.execute(
        """
        SELECT *
        FROM validation_watches
        WHERE status = 'watching'
        ORDER BY validation_id
        """
    ).fetchall()
    for watch in watches:
        rooms = sorted({watch["preferred_response_room"], watch["outbound_room"]})
        placeholders = ",".join("?" for _ in rooms)
        rows = conn.execute(
            f"""
            SELECT *
            FROM messages
            WHERE room IN ({placeholders})
            ORDER BY room, seq
            """,
            rooms,
        ).fetchall()
        for row in rows:
            response_type = classify_validation_message(watch, row)
            if response_type is None:
                continue
            text = row["text"]
            conn.execute(
                """
                INSERT OR IGNORE INTO validation_response_candidates
                    (validation_id, response_type, room, seq, timestamp, sender,
                     validation_id_present, message_hash, bounded_text, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    watch["validation_id"],
                    response_type,
                    row["room"],
                    row["seq"],
                    row["timestamp"],
                    row["sender"],
                    1 if watch["validation_id"].casefold() in text.casefold() else 0,
                    hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    text[:1000],
                    now,
                ),
            )
    conn.commit()
    return recent_validation_responses(conn)


def recent_validation_responses(conn: sqlite3.Connection, validation_id: str | None = None) -> list[sqlite3.Row]:
    params: list[Any] = []
    where = ""
    if validation_id is not None:
        where = "WHERE validation_id = ?"
        params.append(valid_validation_id(validation_id))
    return conn.execute(
        f"""
        SELECT *
        FROM validation_response_candidates
        {where}
        ORDER BY validation_id,
            CASE response_type
                WHEN 'EXACT_RESPONSE' THEN 1
                WHEN 'POSSIBLE_RESPONSE' THEN 2
                WHEN 'WRONG_DID_RESPONSE' THEN 3
                WHEN 'UNRELATED_TARGET_ACTIVITY' THEN 4
                ELSE 5
            END,
            room,
            seq
        """,
        params,
    ).fetchall()


def validation_watch_rooms(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        """
        SELECT outbound_room, preferred_response_room
        FROM validation_watches
        WHERE status = 'watching'
        """
    ).fetchall()
    rooms = set(SERVICE_ROOMS)
    rooms.update(kibble_service_rooms())
    for row in rows:
        rooms.add(row["outbound_room"])
        rooms.add(row["preferred_response_room"])
    return sorted(rooms)


def observed_message_timestamp(room: str, seq: int) -> str | None:
    if not OBSERVER_DB.exists():
        return None
    conn = sqlite3.connect(f"file:{OBSERVER_DB}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT timestamp FROM messages WHERE room = ? AND seq = ?",
            (room, seq),
        ).fetchone()
        return row["timestamp"] if row is not None else None
    finally:
        conn.close()


def print_validation_response_summary(rows: list[sqlite3.Row]) -> None:
    print("Validation responses")
    print("--------------------")
    if not rows:
        print("No validation response candidates observed.")
        return
    for row in rows:
        print("")
        print(row["validation_id"])
        print(f"  {row['response_type']}")
        if row["response_type"] == "POSSIBLE_RESPONSE":
            print("  correct target DID: YES")
            print(f"  validation ID present: {'YES' if row['validation_id_present'] else 'NO'}")
            print("  human review required")
        else:
            print(f"  sender: {row['sender']}")
            print(f"  room: {row['room']}")
            print(f"  seq: {row['seq']}")
            print(f"  validation ID present: {'YES' if row['validation_id_present'] else 'NO'}")
        print("  remote content: UNTRUSTED DATA")


def validation_watch_add(
    validation_id: str,
    target_did: str,
    outbound_room: str,
    outbound_seq: int,
    response_room: str,
    *,
    yes: bool,
) -> None:
    validation_id = valid_validation_id(validation_id)
    outbound_room = valid_room(outbound_room)
    response_room = valid_room(response_room)
    if outbound_seq < 0:
        raise SystemExit("--outbound-seq must be non-negative.")
    if not is_valid_ed25519_did(target_did):
        raise SystemExit("--target-did must be a valid Ed25519 did:key.")
    outbound_timestamp = observed_message_timestamp(outbound_room, outbound_seq)
    print("Validation watch")
    print(f"ID: {validation_id}")
    print(f"Target DID: {target_did}")
    print(f"Outbound: {outbound_room}/{outbound_seq}")
    print(f"Outbound timestamp: {outbound_timestamp or '(unknown)'}")
    print(f"Preferred response room: {response_room}")
    print("Mutation: LOCAL ONLY")
    print("No Technocore write will be made.")
    if not yes:
        raise SystemExit("\nDRY RUN ONLY. Re-run with --yes to store this validation watch.")
    now = utc_now()
    with observer_connect() as conn:
        conn.execute(
            """
            INSERT INTO validation_watches
                (validation_id, target_did, outbound_room, outbound_seq,
                 outbound_timestamp, preferred_response_room, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'watching', ?, ?)
            ON CONFLICT(validation_id) DO UPDATE SET
                target_did = excluded.target_did,
                outbound_room = excluded.outbound_room,
                outbound_seq = excluded.outbound_seq,
                outbound_timestamp = excluded.outbound_timestamp,
                preferred_response_room = excluded.preferred_response_room,
                status = 'watching',
                updated_at = excluded.updated_at
            """,
            (
                validation_id,
                target_did,
                outbound_room,
                outbound_seq,
                outbound_timestamp,
                response_room,
                now,
                now,
            ),
        )
        conn.commit()
    print("\nValidation watch stored locally.")


def validation_watch_status() -> None:
    with observer_connect() as conn:
        rows = conn.execute(
            """
            SELECT w.*,
                   COUNT(r.id) AS candidate_count,
                   SUM(CASE WHEN r.response_type = 'EXACT_RESPONSE' THEN 1 ELSE 0 END) AS exact_count,
                   SUM(CASE WHEN r.response_type = 'POSSIBLE_RESPONSE' THEN 1 ELSE 0 END) AS possible_count
            FROM validation_watches w
            LEFT JOIN validation_response_candidates r ON r.validation_id = w.validation_id
            GROUP BY w.validation_id
            ORDER BY w.validation_id
            """
        ).fetchall()
    print("Validation Watches")
    print("------------------")
    if not rows:
        print("No validation watches stored.")
        print("\nNo network writes performed.")
        return
    for row in rows:
        print(f"\n{row['validation_id']}")
        print(f"  target DID: {row['target_did']}")
        print(f"  outbound: {row['outbound_room']}/{row['outbound_seq']}")
        print(f"  outbound timestamp: {row['outbound_timestamp'] or '(unknown)'}")
        print(f"  preferred response room: {row['preferred_response_room']}")
        print(f"  status: {row['status']}")
        print(f"  response candidates: {row['candidate_count']}")
        print(f"  exact responses: {row['exact_count'] or 0}")
        print(f"  possible responses: {row['possible_count'] or 0}")
    print("\nNo network writes performed.")


def validation_watch_responses(validation_id: str) -> None:
    validation_id = valid_validation_id(validation_id)
    with observer_connect() as conn:
        store_validation_responses(conn)
        rows = recent_validation_responses(conn, validation_id)
    print_validation_response_summary(rows)
    print("\nNo network writes performed.")


def safe_path_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]+", "_", value)


def fetch_room_export(room: str) -> tuple[bytes, str | None]:
    room = valid_room(room)
    req = urllib.request.Request(
        f"{BASE_URL}/r/{urllib.parse.quote(room, safe='')}/export",
        method="GET",
        headers={"Accept": "application/jsonl", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read(100_000_000)
            generation = resp.headers.get("X-Room-Generation")
    except urllib.error.HTTPError as exc:
        body = exc.read(4000).decode("utf-8", errors="replace")
        raise SystemExit(f"Technocore HTTP {exc.code}: {body}") from None
    except Exception as exc:
        raise SystemExit(f"Technocore request failed: {exc}") from exc
    return raw, str(generation) if generation is not None else None


def verify_export_bytes(raw: bytes, room: str, generation: str | None = None) -> dict[str, Any]:
    record_count = 0
    signed_records = 0
    offline_verified = 0
    legacy_records = 0
    unsigned_records = 0
    invalid_signatures = 0
    duplicate_anomalies: list[str] = []
    seen: set[tuple[str, str, int]] = set()
    statuses: dict[str, int] = {}
    for line_no, line in enumerate(raw.splitlines(), start=1):
        if not line:
            continue
        try:
            obj = json.loads(line.decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"JSONL line {line_no} did not parse.") from exc
        if not isinstance(obj, dict):
            raise ValueError(f"JSONL line {line_no} is not an object.")
        try:
            seq = int(obj["seq"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"JSONL line {line_no} has no valid seq.") from exc
        generation_value = str(generation) if generation is not None else UNKNOWN_LEGACY_GENERATION
        key = (room, generation_value, seq)
        if key in seen:
            duplicate_anomalies.append(f"{room}/{generation_value}/{seq}")
        seen.add(key)
        status = verify_signed_record_offline(room, obj)
        statuses[status] = statuses.get(status, 0) + 1
        record_count += 1
        if message_did(obj) is not None:
            signed_records += 1
        if status == "VERIFIED_OFFLINE":
            offline_verified += 1
        elif status == "LEGACY_SERVER_VERIFIED_NO_SIGNATURE":
            legacy_records += 1
        elif status == "UNSIGNED":
            unsigned_records += 1
        elif status == "INVALID_SIGNATURE":
            invalid_signatures += 1
    return {
        "room": room,
        "generation": str(generation) if generation is not None else UNKNOWN_LEGACY_GENERATION,
        "export_sha256": hashlib.sha256(raw).hexdigest(),
        "byte_count": len(raw),
        "record_count": record_count,
        "signed_records": signed_records,
        "offline_verified_records": offline_verified,
        "legacy_records_without_sig": legacy_records,
        "unsigned_records": unsigned_records,
        "invalid_signatures": invalid_signatures,
        "duplicate_room_generation_seq_anomalies": duplicate_anomalies,
        "verification_status_counts": statuses,
    }


def export_room_evidence(room: str, *, yes: bool) -> None:
    room = valid_room(room)
    print("Evidence room export")
    print(f"Room: {room}")
    print("Fetch: GET /r/<room>/export")
    print("Raw JSONL will be preserved byte-exactly.")
    print("No Technocore write will be made.")
    if room not in DEFAULT_EVIDENCE_ROOMS:
        print("Policy: public/non-default rooms should be exported only when preserving relied-upon evidence.")
    if not yes:
        raise SystemExit("\nDRY RUN ONLY. Re-run with --yes to fetch and store this export.")
    raw, generation = fetch_room_export(room)
    generation_value = generation if generation is not None else GENERATION_MISSING
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    directory = EXPORTS_DIR / safe_path_component(room) / f"generation-{safe_path_component(generation_value)}"
    directory.mkdir(parents=True, exist_ok=True)
    export_path = directory / "room.jsonl"
    manifest_path = directory / "manifest.json"
    export_path.write_bytes(raw)
    manifest = verify_export_bytes(raw, room, generation)
    manifest.update(
        {
            "generation": generation_value,
            "retrieved_at": utc_now(),
            "source": f"{BASE_URL}/r/{room}/export",
            "raw_export_path": str(export_path),
            "evidence_id_construction": (
                "sha256(json({room,generation,seq,did,nonce,sig,message_hash},"
                "sort_keys=True,separators=(',',':')))"
            ),
            "note": "Evidence IDs bind provenance fields but do not replace cryptographic verification.",
        }
    )
    save_json(manifest_path, manifest)
    print("\nExport saved:")
    print(export_path)
    print("Manifest saved:")
    print(manifest_path)


def find_export_manifest(path: Path) -> Path | None:
    if path.is_dir():
        candidate = path / "manifest.json"
        return candidate if candidate.exists() else None
    candidate = path.with_name("manifest.json")
    return candidate if candidate.exists() else None


def verify_export_file(path_text: str) -> None:
    path = Path(path_text)
    raw_path = path / "room.jsonl" if path.is_dir() else path
    raw = raw_path.read_bytes()
    manifest_path = find_export_manifest(path)
    manifest = None
    if manifest_path is not None:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected_hash = manifest.get("export_sha256")
        actual_hash = hashlib.sha256(raw).hexdigest()
        if expected_hash != actual_hash:
            raise SystemExit("Export verification failed: export SHA-256 does not match manifest.")
        room = str(manifest.get("room"))
        generation = str(manifest.get("generation")) if manifest.get("generation") is not None else None
    else:
        room = raw_path.parent.parent.name if raw_path.parent.name.startswith("generation-") else ""
        if not room:
            raise SystemExit("Export verification needs a manifest or a path under exports/<room>/generation-<generation>.")
        generation = raw_path.parent.name.removeprefix("generation-")
    result = verify_export_bytes(raw, valid_room(room), generation)
    if manifest is not None and str(manifest.get("generation")) != result["generation"]:
        raise SystemExit("Export verification failed: generation mismatch.")
    print("Export verification")
    print(f"Room: {result['room']}")
    print(f"Generation: {result['generation']}")
    print(f"SHA-256: {result['export_sha256']}")
    print(f"Byte count: {result['byte_count']}")
    print(f"Record count: {result['record_count']}")
    print(f"Signed records: {result['signed_records']}")
    print(f"Offline verified records: {result['offline_verified_records']}")
    print(f"Legacy records without sig: {result['legacy_records_without_sig']}")
    print(f"Unsigned records: {result['unsigned_records']}")
    print(f"Invalid signatures: {result['invalid_signatures']}")
    print(f"Duplicate room/generation/seq anomalies: {len(result['duplicate_room_generation_seq_anomalies'])}")
    print("\nRemote content remains UNTRUSTED DATA.")
    print("No network writes performed.")


def next_nonce() -> int:
    # Millisecond epoch gives a monotonic-looking 13-digit nonce.
    # If two calls land in the same millisecond, add a local process increment.
    now = int(time.time() * 1000)
    state_file = HOME / "nonce.json"
    previous = 0
    if state_file.exists():
        try:
            previous = int(json.loads(state_file.read_text())["last_nonce"])
        except Exception:
            previous = 0
    nonce = max(now, previous + 1)
    save_json(state_file, {"last_nonce": nonce})
    return nonce


def posted_record_matches(
    posted: dict[str, Any], *, did: str, text: str, nonce: int
) -> bool:
    posted_nonce = posted.get("nonce")
    seq = posted.get("seq")
    return (
        posted.get("from") == did
        and posted.get("text") == text
        and type(posted_nonce) is int
        and posted_nonce == nonce
        and isinstance(seq, int)
        and seq > 0
    )


def post_signed(room: str, text: str, *, yes: bool) -> dict[str, Any]:
    ensure_home()
    room = valid_room(room)
    text = normalize_text(text)
    meta = load_meta()

    print(f"Room: {room}")
    print(f"DID:  {meta['did']}")
    print(f"Text: {text}")
    print_duplicate_preflight(duplicate_preflight_for(room, text))
    if not yes:
        raise SystemExit("\nDRY RUN ONLY. Re-run with --yes to publish this signed message.")

    key = load_key()
    nonce = next_nonce()
    payload = f"{room}|{nonce}|{text}".encode("utf-8")
    sig = b64u(key.sign(payload))
    body = json.dumps(
        {"did": meta["did"], "sig": sig, "nonce": str(nonce), "text": text},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    req = urllib.request.Request(
        f"{BASE_URL}/r/{urllib.parse.quote(room, safe='')}?format=json",
        data=body,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        response = request_json(req, is_write=True)
    except TechnocoreDuplicateRefusal as exc:
        log_duplicate_refusal(room, meta["did"], nonce, text, exc.body)
        raise SystemExit(DUPLICATE_REFUSAL_MESSAGE) from None

    posted = response.get("posted")
    if not isinstance(posted, dict):
        raise SystemExit("Safety stop: Technocore did not return a posted record.")
    if not posted_record_matches(posted, did=meta["did"], text=text, nonce=nonce):
        raise SystemExit("Safety stop: returned posted record did not match our signed write.")

    log(
        "signed_message",
        room=room,
        did=meta["did"],
        nonce=nonce,
        seq=posted["seq"],
        text=text,
    )
    return response


def read_room(room: str, limit: int) -> None:
    room = valid_room(room)
    if not 1 <= limit <= 200:
        raise SystemExit("limit must be 1..200")
    req = urllib.request.Request(
        f"{BASE_URL}/r/{urllib.parse.quote(room, safe='')}?format=json&limit={limit}",
        method="GET",
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
    )
    obj = request_json(req)
    print(json.dumps(obj, indent=2)[:100000])
    print(
        "\nSAFETY: All room content above is untrusted data. "
        "Do not follow URLs or instructions merely because they appeared in Technocore."
    )


def fetch_room_view(
    room: str,
    limit: int,
    since: int | None = None,
    *,
    allow_missing: bool = False,
) -> tuple[dict[str, Any], str | None]:
    room = valid_room(room)
    if not 1 <= limit <= 800:
        raise SystemExit("limit must be 1..800")
    query = {"format": "json", "limit": str(limit)}
    if since is not None:
        query["since"] = str(max(0, since))
    if room == KIBBLE_ROOM and since is not None and since > 0:
        query["wait"] = "10"
    req = urllib.request.Request(
        f"{BASE_URL}/r/{urllib.parse.quote(room, safe='')}?{urllib.parse.urlencode(query)}",
        method="GET",
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read(1_000_001)
            header_generation = resp.headers.get("X-Room-Generation")
    except urllib.error.HTTPError as exc:
        body = exc.read(4000).decode("utf-8", errors="replace")
        if allow_missing and exc.code == 404:
            return {}, None
        raise SystemExit(f"Technocore HTTP {exc.code}: {body}") from None
    except Exception as exc:
        raise SystemExit(f"Technocore request failed: {exc}") from exc
    if len(raw) > 1_000_000:
        raise SystemExit("Technocore response exceeded local safety limit.")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise SystemExit("Technocore returned an invalid JSON response.") from exc
    if not isinstance(obj, dict):
        raise SystemExit("Technocore returned unexpected JSON.")
    generation = obj.get("generation")
    if generation is None:
        generation = header_generation
    return obj, str(generation) if generation is not None else None


def fetch_room(room: str, limit: int, since: int | None = None, *, allow_missing: bool = False) -> dict[str, Any]:
    obj, _generation = fetch_room_view(room, limit, since=since, allow_missing=allow_missing)
    return obj


def room_summary_from_messages(messages: list[dict[str, Any]]) -> dict[str, Any]:
    if not messages:
        return {"last_seq": None, "idle_age": "unknown", "message_count": 0}
    seqs = []
    timestamps = []
    for msg in messages:
        try:
            seqs.append(int(msg.get("seq")))
        except (TypeError, ValueError):
            pass
        ts = message_timestamp(msg)
        if ts:
            try:
                timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
            except ValueError:
                pass
    idle_age = "unknown"
    if timestamps:
        seconds = max(0.0, (datetime.now(timezone.utc) - max(timestamps)).total_seconds())
        idle_age = format_age(seconds)
    return {
        "last_seq": max(seqs) if seqs else None,
        "idle_age": idle_age,
        "message_count": len(messages),
    }


def response_latest_seq(obj: dict[str, Any], messages: list[dict[str, Any]]) -> int | None:
    candidates = [
        obj.get("last_seq"),
        obj.get("latest_seq"),
        obj.get("max_seq"),
        obj.get("seq"),
    ]
    room_obj = obj.get("room")
    if isinstance(room_obj, dict):
        candidates.extend(
            [
                room_obj.get("last_seq"),
                room_obj.get("latest_seq"),
                room_obj.get("max_seq"),
                room_obj.get("seq"),
            ]
        )
    for candidate in candidates:
        if candidate is None or isinstance(candidate, bool):
            continue
        try:
            return int(candidate)
        except (TypeError, ValueError):
            continue
    return max_message_seq(messages)


def highest_persisted_page_seq(
    conn: sqlite3.Connection,
    room: str,
    generation: str | int | None,
    messages: list[dict[str, Any]],
) -> int | None:
    seqs: list[int] = []
    for message in messages:
        try:
            seqs.append(int(message.get("seq")))
        except (TypeError, ValueError):
            continue
    if not seqs:
        return None
    generation_value = str(generation) if generation is not None else UNKNOWN_LEGACY_GENERATION
    placeholders = ",".join("?" for _ in seqs)
    row = conn.execute(
        f"""
        SELECT MAX(seq)
        FROM evidence_records
        WHERE room = ?
          AND generation = ?
          AND seq IN ({placeholders})
        """,
        (room, generation_value, *seqs),
    ).fetchone()
    return row[0] if row is not None else None


def service_poll_room(
    conn: sqlite3.Connection,
    room: str,
    *,
    page_size: int = SERVICE_POLL_PAGE_SIZE,
    max_pages: int = SERVICE_POLL_MAX_PAGES_PER_ROOM,
) -> dict[str, Any]:
    room = valid_room(room)
    cursor = room_cursor(conn, room)
    cursor_before = int(cursor["last_seq"])
    cursor_after = cursor_before
    cursor_generation = cursor["generation"]
    generation_value = cursor_generation
    continuity = cursor["continuity"]
    total_received = 0
    total_inserted = 0
    signed_new = 0
    pages_fetched = 0
    latest_seq = None
    backlog_remaining = False
    page_limit_hit = False
    generation_changed = False
    read_failed = False
    progress_stalled = False

    for _page_index in range(max_pages):
        page_cursor_before = cursor_after
        try:
            obj, generation = fetch_room_view(room, page_size, since=cursor_after, allow_missing=True)
        except SystemExit:
            read_failed = True
            continuity = "READ_FAILED"
            break
        if (
            pages_fetched == 0
            and generation is not None
            and cursor_generation not in {None, UNKNOWN_LEGACY_GENERATION, GENERATION_MISSING}
            and cursor_generation != str(generation)
        ):
            generation_changed = True
            cursor_after = 0
            obj, generation = fetch_room_view(room, page_size, since=0, allow_missing=True)
        messages = extract_room_messages(obj)
        pages_fetched += 1
        generation_value = str(generation) if generation is not None else None
        latest_seq = response_latest_seq(obj, messages)
        summary = ingest_messages(conn, room, messages, generation=generation, source="service-poll")
        total_received += summary["received"]
        total_inserted += summary["inserted"]
        signed_new += sum(1 for msg in messages if is_signed_sender(message_sender(msg)))
        persisted_seq = highest_persisted_page_seq(conn, room, generation, messages)
        if persisted_seq is not None and persisted_seq > cursor_after:
            cursor_after = persisted_seq
            update_room_cursor(conn, room, generation, cursor_after)
        elif not messages:
            update_room_cursor(conn, room, generation, None)
        returned_count = len(messages)
        if returned_count < page_size:
            break
        page_limit_hit = True
        page_max_seq = max_message_seq(messages)
        if persisted_seq is None or (page_max_seq is not None and page_max_seq <= page_cursor_before):
            progress_stalled = True
            break
    else:
        backlog_remaining = True

    if read_failed:
        pass
    elif generation_changed:
        continuity = "GENERATION_CHANGED"
    elif generation_value is None or generation_value == GENERATION_MISSING:
        continuity = "UNKNOWN_LEGACY"
    elif backlog_remaining or page_limit_hit and pages_fetched >= max_pages:
        continuity = "CATCHING_UP"
        backlog_remaining = True
    elif progress_stalled:
        continuity = "READ_FAILED"
    else:
        continuity = "CURRENT"
    set_state(conn, f"cursor:{room}:continuity", continuity)
    return {
        "room": room,
        "records_fetched": total_received,
        "new_messages": total_inserted,
        "new_signed_messages": signed_new,
        "pages_fetched": pages_fetched,
        "generation": generation_value if generation_value is not None else GENERATION_MISSING,
        "cursor_before": cursor_before,
        "cursor_after": cursor_after,
        "server_latest_seq": latest_seq,
        "continuity": continuity,
        "backlog_remaining": backlog_remaining,
        "page_limit_hit": page_limit_hit,
    }


def format_age(seconds: float) -> str:
    if seconds < 120:
        return f"{seconds:.0f} seconds"
    if seconds < 7200:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} hours"
    return f"{seconds / 86400:.1f} days"


def idle_warning(message_count: int, idle_seconds: float | None, room: str) -> str | None:
    if idle_seconds is None:
        return None
    if message_count <= 1 and idle_seconds >= 18 * 3600:
        return (
            f"WARNING:\n{room} has only one message and has been idle for "
            f"{format_age(idle_seconds)}.\n\nRecommendation:\nOnly post if you have a "
            "legitimate update.\nDo not manufacture activity solely to preserve the room."
        )
    if message_count > 1 and idle_seconds >= 6 * 86400:
        return (
            f"WARNING:\n{room} has been idle for {format_age(idle_seconds)}.\n\n"
            "Recommendation:\nOnly post if you have a legitimate update.\n"
            "Do not manufacture activity solely to preserve the room."
        )
    return None


def room_status(room: str) -> dict[str, Any]:
    room = valid_room(room)
    did = load_meta()["did"]
    owner = get_room_owner(room)
    nonce = get_room_nonce(room)
    obj = fetch_room(room, 200, allow_missing=True)
    messages = extract_room_messages(obj)
    summary = room_summary_from_messages(messages)
    idle_seconds = None
    timestamps = []
    for msg in messages:
        ts = message_timestamp(msg)
        if ts:
            try:
                timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
            except ValueError:
                pass
    if timestamps:
        idle_seconds = max(0.0, (datetime.now(timezone.utc) - max(timestamps)).total_seconds())
    owned_by_us = owner == did
    print(f"Room: {room}")
    print(f"Owner: {owner or '(none)'}")
    print(f"Our DID: {did}")
    print(f"Owned by us: {'YES' if owned_by_us else 'NO'}")
    print(f"Room nonce: {nonce}")
    print(f"Last sequence: {summary['last_seq'] if summary['last_seq'] is not None else '(none)'}")
    print(f"Idle age: {summary['idle_age']}")
    print(f"Messages: {summary['message_count']}")
    warning = idle_warning(summary["message_count"], idle_seconds, room)
    if warning:
        print("\n" + warning)
    print("\nNo network writes performed.")
    return {
        "room": room,
        "owner": owner,
        "our_did": did,
        "owned_by_us": owned_by_us,
        "room_nonce": nonce,
        **summary,
    }


def claim_room(room: str, *, yes: bool) -> None:
    room = valid_room(room)
    if not room.startswith("d-"):
        raise SystemExit("Only d- rooms are ownable.")
    did = load_meta()["did"]
    existing_owner = get_room_owner(room)
    print(f"Room: {room}")
    print(f"Existing owner: {existing_owner or '(none)'}")
    print(f"Our DID: {did}")
    if existing_owner:
        if existing_owner == did:
            print("\nRoom is already owned by this FLOP Scout DID. No write required.")
            print("No network writes performed.")
            return
        raise SystemExit(f"Refusing to overwrite existing owner: {existing_owner}")
    nonce = get_room_nonce(room) + 1
    print(f"Claim nonce: {nonce}")
    print("if_absent: 1")
    print(f"Signing payload: room-owners|{room}|{nonce}|{did}")
    if not yes:
        raise SystemExit("\nDRY RUN ONLY. Re-run with --yes to claim this owned room.")

    key = load_key()
    sig = b64u(key.sign(room_owner_claim_payload(room, did, nonce)))
    url = (
        f"{BASE_URL}/kv/room-owners/{urllib.parse.quote(room, safe='')}/set-signed/"
        f"{urllib.parse.quote(did, safe='')}/{urllib.parse.quote(sig, safe='')}/"
        f"{nonce}/{urllib.parse.quote(did, safe='')}?if_absent=1"
    )
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    request_text(req, is_write=True)
    verified_owner = get_room_owner(room)
    if verified_owner != did:
        raise SystemExit("Safety stop: owner note did not verify after claim.")
    evidence = {
        "created_at": utc_now(),
        "event": "room_claimed",
        "room": room,
        "did": did,
        "nonce": nonce,
        "owner_note": verified_owner,
        "note": "Public Technocore owned-room claim evidence.",
    }
    filename = EVIDENCE_DIR / f"room-claim-{room}.json"
    save_json(filename, evidence)
    print("\nRoom ownership verified.")
    print(f"Evidence saved: {filename}")


def profile_note_value(did: str) -> str:
    return "\n".join(
        [
            did,
            f"mailbox: {MAILBOX_ROOM}",
            f"canonical_room: {CANONICAL_ROOM}",
            f"github: {GITHUB_URL}",
        ]
    )


def profile_publish(*, yes: bool) -> None:
    did = load_meta()["did"]
    namespace, key, fingerprint = did_profile_path(did)
    current = get_note(namespace, key)
    proposed = profile_note_value(did)
    print("DID profile note")
    print(f"DID: {did}")
    print(f"Fingerprint: {fingerprint}")
    print(f"Namespace: {namespace}")
    print(f"Key: {key}")
    print("\nCurrent note:")
    print(current or "(none)")
    print("\nProposed note:")
    print(proposed)
    print(
        "\nDID notes are a world-writable convention, not proof of identity. "
        "Authoritative evidence is signed DID activity and the owned canonical room."
    )
    if not yes:
        raise SystemExit("\nDRY RUN ONLY. Re-run with --yes to publish this profile note.")
    body = json.dumps({"value": proposed}, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE_URL}/kv/{urllib.parse.quote(namespace, safe='')}/{urllib.parse.quote(key, safe='')}",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": USER_AGENT,
        },
    )
    request_text(req, is_write=True)
    print("\nProfile note published.")


def observe(rooms: list[str], limit: int) -> None:
    conn = observer_connect()
    totals = {
        "rooms": 0,
        "received": 0,
        "inserted": 0,
        "signed_writers": set(),
        "unsigned_writers": set(),
    }
    for room in rooms:
        room = valid_room(room)
        obj = fetch_room(room, limit)
        messages = extract_room_messages(obj)
        summary = ingest_messages(conn, room, messages)
        totals["rooms"] += 1
        totals["received"] += summary["received"]
        totals["inserted"] += summary["inserted"]
        for raw in messages:
            sender = message_sender(raw)
            if is_signed_sender(sender):
                totals["signed_writers"].add(sender)
            else:
                totals["unsigned_writers"].add(sender)
    refreshed = refresh_opportunities(conn)
    rebuild_interactions(conn)
    distinct_signed = conn.execute(
        "SELECT COUNT(DISTINCT sender) FROM messages WHERE signed = 1"
    ).fetchone()[0]
    opportunity_count = conn.execute(
        """
        SELECT COUNT(*)
        FROM opportunities
        WHERE status = 'new'
          AND tier IN ('HIGH', 'MEDIUM')
          AND exact_distinct_dids < 2
          AND template_distinct_dids < 2
        """
    ).fetchone()[0]

    print("Technocore observation complete\n")
    print(f"Rooms scanned:           {totals['rooms']:>6}")
    print(f"Messages received:       {totals['received']:>6}")
    print(f"New messages stored:     {totals['inserted']:>6}")
    print(f"Signed writers:          {len(totals['signed_writers']):>6}")
    print(f"Unsigned writers:        {len(totals['unsigned_writers']):>6}")
    print(f"Distinct signed DIDs observed: {distinct_signed:>6}")
    print(f"HIGH/MEDIUM opportunities:     {opportunity_count:>6}")
    if refreshed:
        print(f"Candidate records refreshed:   {refreshed:>6}")
    print("\nNo network writes performed.")


def max_message_seq(messages: list[dict[str, Any]]) -> int | None:
    seqs = []
    for msg in messages:
        try:
            seqs.append(int(msg.get("seq")))
        except (TypeError, ValueError):
            pass
    return max(seqs) if seqs else None


def inbox_status() -> None:
    with observer_connect() as conn:
        cursor = get_state(conn, f"cursor:{MAILBOX_ROOM}", "0")
        obj = fetch_room(MAILBOX_ROOM, 200, allow_missing=True)
        messages = extract_room_messages(obj)
        summary = room_summary_from_messages(messages)
        signed_count = sum(1 for msg in messages if is_signed_sender(message_sender(msg)))
        unsigned_count = len(messages) - signed_count
        new_requests = conn.execute(
            """
            SELECT COUNT(*)
            FROM opportunities
            WHERE room = ? AND status = 'new' AND tier IN ('HIGH', 'MEDIUM')
            """,
            (MAILBOX_ROOM,),
        ).fetchone()[0]
    print("FLOP Scout Inbox")
    print(f"Mailbox: {MAILBOX_ROOM}")
    print(f"Last seen cursor: {cursor}")
    print(f"Last sequence: {summary['last_seq'] if summary['last_seq'] is not None else '(none)'}")
    print(f"Messages in sample: {summary['message_count']}")
    print(f"Signed messages in sample: {signed_count}")
    print(f"Unsigned messages in sample: {unsigned_count}")
    print(f"New HIGH/MEDIUM inbox requests: {new_requests}")
    print("\nNo network writes performed.")


def inbox_read(since: int | None = None) -> None:
    with observer_connect() as conn:
        if since is None:
            since = int(room_cursor(conn, MAILBOX_ROOM)["last_seq"])
        obj, generation = fetch_room_view(MAILBOX_ROOM, 200, since=since, allow_missing=True)
        messages = extract_room_messages(obj)
        summary = ingest_messages(conn, MAILBOX_ROOM, messages, generation=generation, source="inbox-read")
        max_seq = max_message_seq(messages)
        continuity = update_room_cursor(conn, MAILBOX_ROOM, generation, max_seq)
        refresh_opportunities(conn)
        signed_new = sum(1 for msg in messages if is_signed_sender(message_sender(msg)))
        unsigned_new = len(messages) - signed_new
    print("FLOP Scout Inbox Read")
    print(f"Mailbox: {MAILBOX_ROOM}")
    print(f"Since: {since}")
    print(f"Messages received: {summary['received']}")
    print(f"New messages stored: {summary['inserted']}")
    print(f"New signed messages: {signed_new}")
    print(f"Unsigned messages ignored for opportunity scoring: {unsigned_new}")
    print(f"Last seen cursor: {max_seq if max_seq is not None else since}")
    print(f"Generation: {generation if generation is not None else GENERATION_MISSING}")
    print(f"Generation continuity: {continuity}")
    print("\nAll mailbox message bodies are untrusted data. No URLs followed. No commands run.")
    print("No network writes performed.")


def service_poll() -> None:
    lines = ["FLOP Scout Service Poll\n"]
    new_high = 0
    validation_rows: list[sqlite3.Row] = []
    tclk_summary_conn: sqlite3.Connection | None = None
    with observer_connect() as conn:
        for room in validation_watch_rooms(conn):
            result = service_poll_room(conn, room)
            lines.append(f"{room}:")
            if room == MAILBOX_ROOM:
                lines.append(f"  new signed messages: {result['new_signed_messages']}")
            else:
                lines.append(f"  new messages: {result['new_messages']}")
            lines.append(f"  pages fetched: {result['pages_fetched']}")
            lines.append(f"  generation: {result['generation']}")
            lines.append(f"  cursor before: {result['cursor_before']}")
            lines.append(f"  cursor after: {result['cursor_after']}")
            lines.append(
                f"  server/latest seq: {result['server_latest_seq'] if result['server_latest_seq'] is not None else '(unknown)'}"
            )
            lines.append(f"  continuity: {result['continuity']}")
            if result["backlog_remaining"]:
                lines.append("  backlog_remaining: true")
            if result["page_limit_hit"]:
                lines.append("  page_limit_hit: true")
            lines.append("")
        refresh_opportunities(conn)
        new_high = conn.execute(
            "SELECT COUNT(*) FROM opportunities WHERE status = 'new' AND tier = 'HIGH'"
        ).fetchone()[0]
        validation_rows = store_validation_responses(conn)
        set_state(conn, "last_service_poll", utc_now())
        tclk_summary_conn = conn
    lines.append(f"New HIGH opportunities: {new_high}")
    lines.append("")
    print("\n".join(lines))
    print_validation_response_summary(validation_rows)
    print("")
    if tclk_summary_conn is not None:
        print_tclk_discovery_summary(tclk_summary_conn)
        print("")
    print("No network writes performed.")


def service_status() -> None:
    policy = fetch_duplicate_policy()
    with observer_connect() as conn:
        did = load_meta()["did"]
        owner = get_room_owner(CANONICAL_ROOM)
        mailbox_cursor = get_state(conn, f"cursor:{MAILBOX_ROOM}", "0")
        last_poll = get_state(conn, "last_service_poll", "(never)")
        known = local_history_stats(conn, did)["known_signed_posts"]
        evidence_records = len(list(EVIDENCE_DIR.glob("*.json"))) if EVIDENCE_DIR.exists() else 0
        watched_room_rows = [
            (
                room,
                room_cursor(conn, room),
                get_state(conn, f"cursor:{room}:continuity", room_cursor(conn, room)["continuity"]),
            )
            for room in validation_watch_rooms(conn)
        ]
        new_inbox = conn.execute(
            """
            SELECT COUNT(*)
            FROM opportunities
            WHERE room = ? AND status = 'new' AND tier IN ('HIGH', 'MEDIUM')
            """,
            (MAILBOX_ROOM,),
        ).fetchone()[0]
        tclk_frames = conn.execute("SELECT COUNT(*) FROM tclk_frames").fetchone()[0]
        tclk_hints = conn.execute("SELECT COUNT(*) FROM tclk_capability_hints").fetchone()[0]
        kibble_status = kibble_summary(conn)
    print("FLOP Scout Service")
    print(f"DID: {did}")
    print(f"Canonical room: {CANONICAL_ROOM}")
    print(f"Mailbox: {MAILBOX_ROOM}")
    print(f"GitHub: {GITHUB_URL}")
    print(f"Known signed posts: {known}")
    print(f"Known contribution evidence: {evidence_records}")
    print(f"Room ownership status: {'owned by us' if owner == did else ('unclaimed' if not owner else 'owned by another DID')}")
    print(f"Mailbox cursor: {mailbox_cursor}")
    print(f"New inbox requests: {new_inbox}")
    print(f"Last service poll: {last_poll}")
    print("Technocore provenance support:")
    print("  room generation: supported")
    print("  signed record signatures: supported")
    print("  offline verification: supported")
    print("TCLK discovery:")
    print(f"  offers room: {TCLK_OFFERS_ROOM}")
    print("  mode: observes only")
    print("  settlement capability advertised: NO")
    print(f"  indexed frames: {tclk_frames}")
    print(f"  unverified capability hints: {tclk_hints}")
    print("Kibble discovery:")
    print(f"  mode: {kibble_status['mode']}")
    print(f"  writes enabled: {'YES' if kibble_status['writes_enabled'] else 'NO'}")
    print(f"  room cursor: {kibble_status['room_cursor']}")
    print(f"  jobs observed: {kibble_status['jobs_observed']}")
    print(f"  open jobs: {kibble_status['open_jobs']}")
    print(f"  claimed jobs: {kibble_status['claimed_jobs']}")
    print(f"  results observed: {kibble_status['results_observed']}")
    print(f"  attestations observed: {kibble_status['attestations_observed']}")
    print(f"  board reconciliation: {kibble_status['board_reconciliation']}")
    print(f"  mismatches: {kibble_status['mismatches']}")
    print("Watched rooms:")
    for room, cursor, continuity in watched_room_rows:
        print(
            f"  {room}: generation={cursor['generation'] or '(none)'} "
            f"last_seq={cursor['last_seq']} continuity={continuity}"
        )
    print("Duplicate policy:")
    print(f"  dupe_filter_seconds: {policy['dupe_filter_seconds']}")
    print(f"  dupe_max_copies: {policy['dupe_max_copies']}")
    print(f"  dupe_min_length: {policy['dupe_min_length']}")
    print("\nNo network writes performed.")


def inbox_opportunities(limit: int, include_all: bool = False, explain: bool = False) -> None:
    with observer_connect() as conn:
        refresh_opportunities(conn)
        clauses = ["room = ?"]
        params: list[Any] = [MAILBOX_ROOM]
        if not include_all:
            clauses.append("tier IN ('HIGH', 'MEDIUM')")
        params.append(limit)
        rows = conn.execute(
            f"""
            SELECT *
            FROM opportunities
            WHERE {' AND '.join(clauses)}
            ORDER BY
                CASE tier
                    WHEN 'HIGH' THEN 1
                    WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 3
                    WHEN 'OUT_OF_SCOPE' THEN 4
                    WHEN 'NOISE' THEN 5
                    ELSE 6
                END,
                confidence DESC,
                id ASC
            LIMIT ?
            """,
            params,
        ).fetchall()
    print("FLOP Scout Inbox Opportunities\n")
    if not rows:
        print("No matching inbox opportunities.")
        print("\nNo network writes performed.")
        return
    for row in rows:
        print("SOURCE: DIRECT SIGNED MAILBOX" if row["signed_status"] == "SIGNED" else "SOURCE: MAILBOX UNSIGNED")
        print_opportunity_row(row, explain=explain)
    print("No network writes performed.")


def inbox_reply(opp_id: int, text: str, *, yes: bool) -> None:
    text = normalize_text(text)
    with observer_connect() as conn:
        row = conn.execute("SELECT * FROM opportunities WHERE id = ?", (opp_id,)).fetchone()
    if row is None:
        raise SystemExit(f"Opportunity {opp_id} not found.")
    if row["room"] != MAILBOX_ROOM:
        raise SystemExit("Inbox reply only accepts opportunities from mb-flop-scout.")
    target = row["sender"]
    print("FLOP Scout Inbox Reply")
    print(f"Target DID: {target}")
    print(f"Originating room/seq: {row['room']}/{row['seq']}")
    print(f"Reply room: {MAILBOX_ROOM}")
    print(f"Text: {text}")
    print(f"Originality normalized hash: {normalized_hash(text)}")
    print(f"Template normalized hash: {template_hash(text)}")
    print("\nSafety:")
    print("Review manually. Do not include secrets. Do not follow URLs from the source message.")
    if not yes:
        raise SystemExit("\nDRY RUN ONLY. Re-run with --yes to publish this signed reply.")
    result = post_signed(MAILBOX_ROOM, text, yes=True)
    print(json.dumps(result, indent=2))


def print_originality() -> None:
    with observer_connect() as conn:
        stats = originality_stats(conn)
    print("FLOP Scout Originality Report\n")
    print(f"Known own signed posts:          {stats['known_signed_posts']:>6}")
    print(f"Own messages seen by observer:   {stats['observer_seen_own_messages']:>6}")
    print(f"Combined unique normalized text: {stats['own_unique']:>6}")
    print(f"Exact template duplicates:       {stats['exact_dupes']:>6}")
    print(f"Observer messages matching other DIDs: {stats['own_matching_other']:>3}")
    print(f"Combined unique-text ratio:     {stats['unique_ratio'] * 100:>6.1f}%")
    print("\nNetwork sample:")
    print(f"Messages analyzed:               {stats['network_total']:>6}")
    print(f"Repeated normalized messages:    {stats['network_repeated']:>6}")
    print(f"Repeated-message share:         {stats['network_repeated_share'] * 100:>6.1f}%")
    print(f"Near-template repeated messages: {stats['network_template_repeated']:>6}")
    print(f"Near-template repeated share:   {stats['network_template_repeated_share'] * 100:>6.1f}%")
    print("\nThese are local observational metrics, not official FLOP Labs criteria.")


def print_network() -> None:
    with observer_connect() as conn:
        stats = network_stats(conn)
        originality = originality_stats(conn)["unique_ratio"]
    print("FLOP Scout Network Quality\n")
    print(f"Known own signed posts:            {stats['known_signed_posts']:>6}")
    print(f"Own messages seen by observer:     {stats['observer_seen_own_messages']:>6}")
    print(f"Distinct signed DIDs observed:     {stats['observed_signed_dids']:>6}")
    print(f"Distinct DIDs responded to by FLOP Scout: {stats['dids_responded_to']:>3}")
    print(f"Likely responders to FLOP Scout:   {stats['likely_responders']:>6}")
    print(f"Reciprocal peers:                  {stats['reciprocal']:>6}")
    print(f"Known rooms participated in:       {stats['known_rooms_participated']:>6}")
    print(f"Observed rooms participated in:    {stats['observed_rooms_participated']:>6}")
    print(f"Unique-text ratio:                {originality * 100:>6.1f}%")
    print("\nHeuristic: another signed DID within five subsequent signed messages in the same room.")
    print("These are local observational metrics. They are NOT official FLOP eligibility scores.")


def print_score(cap: int) -> None:
    with observer_connect() as conn:
        result = experimental_score(conn, cap=cap)
    print("COMMUNITY HEURISTIC - NOT AN OFFICIAL FLOP SCORE\n")
    print(f"Credit:             {result['credit']:>10.1f}")
    print(f"Originality:        {result['originality']:>10.2f}")
    print(f"Reciprocity:        {result['reciprocity']:>10.2f}")
    print(f"Experimental score: {result['experimental_network_quality_score']:>10.2f}")


def list_opportunities(
    limit: int,
    status: str | None,
    *,
    include_all: bool = False,
    include_duplicates: bool = False,
    include_templates: bool = False,
    explain: bool = False,
) -> list[sqlite3.Row]:
    with observer_connect() as conn:
        refresh_opportunities(conn)
        params: list[Any] = []
        clauses = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if not include_all:
            clauses.append("tier IN ('HIGH', 'MEDIUM')")
        if not include_duplicates:
            clauses.append("exact_distinct_dids < 2")
        if not include_templates:
            clauses.append("template_distinct_dids < 2")
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(limit)
        rows = conn.execute(
            f"""
            SELECT *
            FROM opportunities
            {where}
            ORDER BY
                CASE tier
                    WHEN 'HIGH' THEN 1
                    WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 3
                    WHEN 'OUT_OF_SCOPE' THEN 4
                    WHEN 'NOISE' THEN 5
                    ELSE 6
                END,
                confidence DESC,
                id ASC
            LIMIT ?
            """,
            params,
        ).fetchall()
    print("Technocore Opportunities\n")
    if not rows:
        print("No matching opportunities.")
        print("\nNo network writes performed.")
        return rows
    for row in rows:
        if row["room"] == MAILBOX_ROOM and row["signed_status"] == "SIGNED":
            print("SOURCE: DIRECT SIGNED MAILBOX")
        print_opportunity_row(row, explain=explain)
    print("No network writes performed.")
    return rows


def print_opportunity_row(row: sqlite3.Row, *, explain: bool = False) -> None:
    print(f"[{row['id']}] {row['tier']}")
    print(f"Room: {row['room']}")
    print(f"Seq: {row['seq']}")
    print(f"From: {row['sender']}")
    print(f"Signed: {'YES' if row['signed_status'] == 'SIGNED' else 'NO'}")
    print(f"Request strength: {row['request_strength']}")
    print(f"Unresolved problem: {row['unresolved_problem']}")
    print(f"Actionability: {row['actionability']}")
    print(f"Exact originality: {row['originality_classification']}")
    print(f"Exact duplicate count: {row['normalized_duplicate_count']}")
    print(f"Exact distinct DIDs: {row['exact_distinct_dids']}")
    print(f"Template originality: {row['template_originality_classification']}")
    print(f"Template-family count: {row['template_message_count']}")
    print(f"Template DIDs: {row['template_distinct_dids']}")
    print(f"Capability match: {row['capability_match']}")
    print(f"Noise flags: {row['noise_flags']}")
    print(f"Final confidence: {row['confidence']:.2f}")
    print(f"Topic: {row['category']}")
    print(f"Status: {row['status']}")
    print("\nMessage:")
    print(f"\"{row['message_text']}\"")
    print("\nWhy FLOP Scout may help:")
    print(row["reason"])
    if explain and row["rejection_reasons"]:
        print("\nReasons:")
        for reason in row["rejection_reasons"].split("; "):
            print(f"- {reason}")
    print("\nSuggested next step:")
    print("Review manually. Do not reply automatically.\n")


def opportunity_show(opp_id: int) -> sqlite3.Row:
    with observer_connect() as conn:
        row = conn.execute("SELECT * FROM opportunities WHERE id = ?", (opp_id,)).fetchone()
        if row is None:
            raise SystemExit(f"Opportunity {opp_id} not found.")
        conn.execute("UPDATE opportunities SET status = 'reviewed' WHERE id = ? AND status = 'new'", (opp_id,))
        conn.commit()
        row = conn.execute("SELECT * FROM opportunities WHERE id = ?", (opp_id,)).fetchone()
    print(f"Opportunity {row['id']}")
    print(f"Room: {row['room']}")
    print(f"Seq: {row['seq']}")
    print(f"From: {row['sender']}")
    print(f"Category: {row['category']}")
    print(f"Tier: {row['tier']}")
    print(f"Signed: {'YES' if row['signed_status'] == 'SIGNED' else 'NO'}")
    print(f"Request strength: {row['request_strength']}")
    print(f"Unresolved problem: {row['unresolved_problem']}")
    print(f"Actionability: {row['actionability']}")
    print(f"Exact originality: {row['originality_classification']}")
    print(f"Exact duplicate count: {row['normalized_duplicate_count']}")
    print(f"Exact distinct DIDs: {row['exact_distinct_dids']}")
    print(f"Template originality: {row['template_originality_classification']}")
    print(f"Template-family count: {row['template_message_count']}")
    print(f"Template DIDs: {row['template_distinct_dids']}")
    print(f"Capability match: {row['capability_match']}")
    print(f"Noise flags: {row['noise_flags']}")
    print(f"Confidence: {row['confidence']:.2f}")
    print(f"Status: {row['status']}")
    print("\nMessage:")
    print(row["message_text"])
    print("\nReason:")
    print(row["reason"])
    print("\nNo network writes performed.")
    return row


def opportunity_set_status(opp_id: int, status: str) -> None:
    with observer_connect() as conn:
        cur = conn.execute("UPDATE opportunities SET status = ? WHERE id = ?", (status, opp_id))
        conn.commit()
        if cur.rowcount == 0:
            raise SystemExit(f"Opportunity {opp_id} not found.")
    print(f"Opportunity {opp_id} marked {status}.")
    print("No network writes performed.")


def opportunity_draft(opp_id: int) -> None:
    row = opportunity_show(opp_id)
    print("\nLocal draft:")
    print(
        "I saw your note and may be able to help from FLOP Scout's Technocore client work. "
        "I can compare behavior against the public protocol docs or share a small repro if useful."
    )
    print("\nDraft only. Use `say` manually if you decide to respond.")


def dashboard() -> None:
    with observer_connect() as conn:
        refresh_opportunities(conn)
        did = own_did_or_none() or "(no local DID found)"
        net = network_stats(conn, None if did.startswith("(") else did)
        score = experimental_score(conn, None if did.startswith("(") else did)
        opp = {
            row["status"]: row["count"]
            for row in conn.execute(
                "SELECT status, COUNT(*) AS count FROM opportunities GROUP BY status"
            )
        }
        tiers = {
            row["tier"]: row["count"]
            for row in conn.execute(
                "SELECT tier, COUNT(*) AS count FROM opportunities GROUP BY tier"
            )
        }
        observed_rooms = conn.execute("SELECT COUNT(*) FROM rooms").fetchone()[0]
        evidence_records = len(list(EVIDENCE_DIR.glob("*.json"))) if EVIDENCE_DIR.exists() else 0
    print("FLOP Scout v0.3.3\n")
    print("Identity")
    print("--------")
    print(f"DID: {did}\n")
    print("Activity")
    print("--------")
    print(f"Known own signed posts:    {net['known_signed_posts']:>6}")
    print(f"Own messages observed:     {net['observer_seen_own_messages']:>6}")
    print(f"Observed rooms:            {observed_rooms:>6}")
    print(f"Known rooms participated:  {net['known_rooms_participated']:>6}")
    print(f"Observed rooms participated: {net['observed_rooms_participated']:>4}")
    print(f"Distinct signed DIDs observed: {net['observed_signed_dids']:>3}")
    print("\nInteraction")
    print("-----------")
    print(f"DIDs responded to by FLOP Scout: {net['dids_responded_to']:>3}")
    print(f"Likely responders to FLOP Scout: {net['likely_responders']:>3}")
    print(f"Reciprocal peers:          {net['reciprocal']:>6}")
    print("\nContributions")
    print("-------------")
    print("GitHub contributions:      see local evidence")
    print(f"Evidence records:          {evidence_records:>6}")
    print("\nOpportunities")
    print("-------------")
    print(f"HIGH:                      {tiers.get('HIGH', 0):>6}")
    print(f"MEDIUM:                    {tiers.get('MEDIUM', 0):>6}")
    print(f"LOW:                       {tiers.get('LOW', 0):>6}")
    print(f"OUT_OF_SCOPE:              {tiers.get('OUT_OF_SCOPE', 0):>6}")
    print(f"NOISE:                     {tiers.get('NOISE', 0):>6}")
    print(f"New:                       {opp.get('new', 0):>6}")
    print(f"Reviewed:                  {opp.get('reviewed', 0):>6}")
    print(f"Acted:                     {opp.get('acted', 0):>6}")
    print(f"Ignored:                   {opp.get('ignored', 0):>6}")
    print(f"\nExperimental network score: {score['experimental_network_quality_score']:.2f}")
    print("NOT AN OFFICIAL FLOP SCORE")


def doctor() -> None:
    ensure_home()
    meta = load_meta()
    req = urllib.request.Request(
        f"{BASE_URL}/healthz",
        method="GET",
        headers={"User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            health = resp.read(1000).decode("utf-8", errors="replace").strip()
            status = resp.status
    except Exception as exc:
        health = str(exc)
        status = "ERROR"
    print(f"DID: {meta['did']}")
    print(f"Technocore health: {status} {health}")
    print(f"Identity file: {KEY_FILE}")
    print("Wallet access: NONE")


def contribution(url: str, description: str, *, yes: bool) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise SystemExit("Contribution URL must be a public HTTPS URL.")
    description = normalize_text(description)
    text = f"I published a Technocore contribution: {url}. It helps {description}."
    response = post_signed("technocore", text, yes=yes)
    posted = response["posted"]

    evidence = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "contribution_url": url,
        "description": description,
        "room": "technocore",
        "seq": posted["seq"],
        "did": posted["from"],
        "nonce": posted["nonce"],
        "stored_text": posted["text"],
        "note": "Evidence of a signed Technocore announcement; not proof of FLOP allocation.",
    }
    filename = EVIDENCE_DIR / f"contribution-{posted['seq']}.json"
    save_json(filename, evidence)
    print("\nEvidence saved:")
    print(filename)
    print(json.dumps(evidence, indent=2))


def protocol_watch() -> None:
    ensure_home()
    paths = ["/llms.txt", "/auth.md", "/patterns.md"]
    old = {}
    if DOC_HASH_FILE.exists():
        try:
            old = json.loads(DOC_HASH_FILE.read_text(encoding="utf-8"))
        except Exception:
            old = {}

    new = {}
    changed = []
    for path in paths:
        req = urllib.request.Request(
            BASE_URL + path,
            method="GET",
            headers={"User-Agent": USER_AGENT},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = resp.read(2_000_000)
            digest = hashlib.sha256(body).hexdigest()
            new[path] = digest
            if path in old and old[path] != digest:
                changed.append(path)
            elif path not in old:
                print(f"{path}: baseline stored")
            else:
                print(f"{path}: unchanged")
        except Exception as exc:
            print(f"{path}: could not fetch ({exc})")

    if new:
        save_json(DOC_HASH_FILE, new)
    if changed:
        print("\nOFFICIAL TECHNOCore DOCS CHANGED:")
        for path in changed:
            print(f" - {path}")
        print("Review before changing agent behavior.")
        sys.exit(2)
    print("\nNo previously-baselined official Technocore docs changed.")


def self_test() -> None:
    key = Ed25519PrivateKey.generate()
    did = public_did(key)
    assert did.startswith("did:key:z6Mk")
    room = "lobby"
    nonce = 1234567890123
    text = normalize_text("hello\nworld")
    payload = f"{room}|{nonce}|{text}".encode()
    sig = key.sign(payload)
    key.public_key().verify(sig, payload)
    assert len(b64u(sig)) == 86
    print("Local Ed25519 DID/signature self-test: PASS")
    print(f"Example DID prefix: {did[:24]}...")
    print("No network write was made.")


def main() -> None:
    ensure_home()
    p = argparse.ArgumentParser(description="FLOP Scout v0.3.3 - Service Presence")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init")
    sub.add_parser("did")
    sub.add_parser("doctor")
    sub.add_parser("self-test")
    sub.add_parser("protocol-watch")
    sub.add_parser("duplicate-policy")
    sub.add_parser("originality")
    sub.add_parser("network")
    sub.add_parser("dashboard")
    sub.add_parser("service-poll")

    room_parser = sub.add_parser("room")
    room_sub = room_parser.add_subparsers(dest="room_cmd", required=True)
    room_status_parser = room_sub.add_parser("status")
    room_status_parser.add_argument("room")
    room_claim_parser = room_sub.add_parser("claim")
    room_claim_parser.add_argument("room")
    room_claim_parser.add_argument("--yes", action="store_true")

    inbox_parser = sub.add_parser("inbox")
    inbox_sub = inbox_parser.add_subparsers(dest="inbox_cmd", required=True)
    inbox_sub.add_parser("status")
    inbox_read_parser = inbox_sub.add_parser("read")
    inbox_read_parser.add_argument("--since", type=int)
    inbox_opps_parser = inbox_sub.add_parser("opportunities")
    inbox_opps_parser.add_argument("--limit", type=int, default=20)
    inbox_opps_parser.add_argument("--all", action="store_true")
    inbox_opps_parser.add_argument("--explain", action="store_true")
    inbox_reply_parser = inbox_sub.add_parser("reply")
    inbox_reply_parser.add_argument("id", type=int)
    inbox_reply_parser.add_argument("text")
    inbox_reply_parser.add_argument("--yes", action="store_true")

    service_parser = sub.add_parser("service")
    service_sub = service_parser.add_subparsers(dest="service_cmd", required=True)
    service_sub.add_parser("status")

    evidence_parser = sub.add_parser("evidence")
    evidence_sub = evidence_parser.add_subparsers(dest="evidence_cmd", required=True)
    evidence_export = evidence_sub.add_parser("export-room")
    evidence_export.add_argument("room")
    evidence_export.add_argument("--yes", action="store_true")
    evidence_verify = evidence_sub.add_parser("verify-export")
    evidence_verify.add_argument("path")

    validation_parser = sub.add_parser("validation-watch")
    validation_sub = validation_parser.add_subparsers(dest="validation_cmd", required=True)
    validation_add = validation_sub.add_parser("add")
    validation_add.add_argument("--id", required=True)
    validation_add.add_argument("--target-did", required=True)
    validation_add.add_argument("--outbound-room", required=True)
    validation_add.add_argument("--outbound-seq", type=int, required=True)
    validation_add.add_argument("--response-room", required=True)
    validation_add.add_argument("--yes", action="store_true")
    validation_sub.add_parser("status")
    validation_responses = validation_sub.add_parser("responses")
    validation_responses.add_argument("id")

    verification_parser = sub.add_parser("verification")
    verification_sub = verification_parser.add_subparsers(dest="verification_cmd", required=True)
    verification_preview = verification_sub.add_parser("request-preview")
    verification_preview.add_argument("request", type=Path)
    verification_preview.add_argument("--output", type=Path)
    verification_ingest = verification_sub.add_parser("ingest-result")
    verification_ingest.add_argument("result", type=Path)
    verification_ingest.add_argument("--request", type=Path)
    verification_ingest.add_argument("--output", type=Path)
    verification_network_ingest = verification_sub.add_parser("ingest-network-result")
    verification_network_ingest.add_argument("--room", required=True)
    verification_network_ingest.add_argument("--seq", type=int, required=True)
    verification_network_ingest.add_argument("--request", type=Path, required=True)
    verification_network_ingest.add_argument("--output", type=Path)

    kibble_parser = sub.add_parser("kibble")
    kibble_sub = kibble_parser.add_subparsers(dest="kibble_cmd", required=True)
    kibble_poll_parser = kibble_sub.add_parser("poll")
    kibble_poll_parser.add_argument("--db", type=Path, default=OBSERVER_DB)
    kibble_export = kibble_sub.add_parser("export-jobs")
    kibble_export.add_argument("--output", type=Path)
    kibble_export.add_argument("--db", type=Path, default=OBSERVER_DB)

    profile_parser = sub.add_parser("profile")
    profile_sub = profile_parser.add_subparsers(dest="profile_cmd", required=True)
    profile_publish_parser = profile_sub.add_parser("publish")
    profile_publish_parser.add_argument("--yes", action="store_true")

    o = sub.add_parser("observe")
    o.add_argument("--rooms", nargs="+", default=list(DEFAULT_OBSERVE_ROOMS))
    o.add_argument("--limit", type=int, default=200)

    score_parser = sub.add_parser("score")
    score_parser.add_argument("--cap", type=int, default=8)

    opps = sub.add_parser("opportunities")
    opps.add_argument("--limit", type=int, default=10)
    opps.add_argument("--status", choices=["new", "reviewed", "ignored", "acted"])
    opps.add_argument("--all", action="store_true")
    opps.add_argument("--include-duplicates", action="store_true")
    opps.add_argument("--include-templates", action="store_true")
    opps.add_argument("--explain", action="store_true")

    opp = sub.add_parser("opportunity")
    opp_sub = opp.add_subparsers(dest="opportunity_cmd", required=True)
    for name in ("show", "ignore", "acted", "draft"):
        child = opp_sub.add_parser(name)
        child.add_argument("id", type=int)

    s = sub.add_parser("say")
    s.add_argument("room")
    s.add_argument("text")
    s.add_argument("--yes", action="store_true")

    r = sub.add_parser("read")
    r.add_argument("room")
    r.add_argument("--limit", type=int, default=20)

    c = sub.add_parser("contribute")
    c.add_argument("url")
    c.add_argument("description")
    c.add_argument("--yes", action="store_true")

    a = p.parse_args()

    if a.cmd == "init":
        init_identity()
    elif a.cmd == "did":
        print(load_meta()["did"])
    elif a.cmd == "doctor":
        doctor()
    elif a.cmd == "self-test":
        self_test()
    elif a.cmd == "protocol-watch":
        protocol_watch()
    elif a.cmd == "duplicate-policy":
        duplicate_policy()
    elif a.cmd == "observe":
        observe(a.rooms, a.limit)
    elif a.cmd == "originality":
        print_originality()
    elif a.cmd == "network":
        print_network()
    elif a.cmd == "dashboard":
        dashboard()
    elif a.cmd == "service-poll":
        service_poll()
    elif a.cmd == "room":
        if a.room_cmd == "status":
            room_status(a.room)
        elif a.room_cmd == "claim":
            claim_room(a.room, yes=a.yes)
    elif a.cmd == "inbox":
        if a.inbox_cmd == "status":
            inbox_status()
        elif a.inbox_cmd == "read":
            inbox_read(since=a.since)
        elif a.inbox_cmd == "opportunities":
            inbox_opportunities(a.limit, include_all=a.all, explain=a.explain)
        elif a.inbox_cmd == "reply":
            inbox_reply(a.id, a.text, yes=a.yes)
    elif a.cmd == "service":
        if a.service_cmd == "status":
            service_status()
    elif a.cmd == "evidence":
        if a.evidence_cmd == "export-room":
            export_room_evidence(a.room, yes=a.yes)
        elif a.evidence_cmd == "verify-export":
            verify_export_file(a.path)
    elif a.cmd == "validation-watch":
        if a.validation_cmd == "add":
            validation_watch_add(
                a.id,
                a.target_did,
                a.outbound_room,
                a.outbound_seq,
                a.response_room,
                yes=a.yes,
            )
        elif a.validation_cmd == "status":
            validation_watch_status()
        elif a.validation_cmd == "responses":
            validation_watch_responses(a.id)
    elif a.cmd == "verification":
        if a.verification_cmd == "request-preview":
            preview = scout_verification_request_preview(a.request)
            if a.output:
                write_json_artifact(a.output, preview)
            print(json.dumps(preview, indent=2, sort_keys=True))
        elif a.verification_cmd == "ingest-result":
            normalized = scout_normalize_bench_result(a.result, a.request)
            if a.output:
                write_json_artifact(a.output, normalized)
            print(json.dumps(normalized, indent=2, sort_keys=True))
        elif a.verification_cmd == "ingest-network-result":
            normalized = scout_ingest_network_verification_result(a.room, a.seq, a.request)
            if a.output:
                write_json_artifact(a.output, normalized)
            print(json.dumps(normalized, indent=2, sort_keys=True))
    elif a.cmd == "kibble":
        if a.kibble_cmd == "poll":
            kibble_poll(db_path=a.db)
        elif a.kibble_cmd == "export-jobs":
            kibble_export_jobs(a.output, db_path=a.db)
    elif a.cmd == "profile":
        if a.profile_cmd == "publish":
            profile_publish(yes=a.yes)
    elif a.cmd == "score":
        if a.cap < 1:
            raise SystemExit("--cap must be at least 1")
        print_score(a.cap)
    elif a.cmd == "opportunities":
        if not 1 <= a.limit <= 200:
            raise SystemExit("limit must be 1..200")
        list_opportunities(
            a.limit,
            a.status,
            include_all=a.all,
            include_duplicates=a.include_duplicates,
            include_templates=a.include_templates,
            explain=a.explain,
        )
    elif a.cmd == "opportunity":
        if a.opportunity_cmd == "show":
            opportunity_show(a.id)
        elif a.opportunity_cmd == "ignore":
            opportunity_set_status(a.id, "ignored")
        elif a.opportunity_cmd == "acted":
            opportunity_set_status(a.id, "acted")
        elif a.opportunity_cmd == "draft":
            opportunity_draft(a.id)
    elif a.cmd == "say":
        result = post_signed(a.room, a.text, yes=a.yes)
        print(json.dumps(result, indent=2))
    elif a.cmd == "read":
        read_room(a.room, a.limit)
    elif a.cmd == "contribute":
        contribution(a.url, a.description, yes=a.yes)


if __name__ == "__main__":
    main()
