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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE_URL = "https://technocore.chat"
HOME = Path.home() / ".flop_scout"
KEY_FILE = HOME / "identity.pem"
META_FILE = HOME / "identity.json"
LOG_FILE = HOME / "activity.jsonl"
DOC_HASH_FILE = HOME / "doc_hashes.json"
EVIDENCE_DIR = HOME / "evidence"
OBSERVER_DB = HOME / "observer.sqlite"
USER_AGENT = "flop-scout/0.3.2"
DEFAULT_OBSERVE_ROOMS = ("lobby", "technocore")
INTERACTION_WINDOW = 5

B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ED25519_MULTICODEC = b"\xed\x01"


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


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def public_did(key: Ed25519PrivateKey) -> str:
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return "did:key:z" + b58encode(ED25519_MULTICODEC + pub)


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


def request_json(req: urllib.request.Request, *, is_write: bool = False) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read(1_000_001)
    except urllib.error.HTTPError as exc:
        body = exc.read(4000).decode("utf-8", errors="replace")
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


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
        """
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


def ingest_messages(conn: sqlite3.Connection, room: str, raw_messages: list[dict[str, Any]]) -> dict[str, int]:
    now = utc_now()
    received = len(raw_messages)
    inserted = 0
    signed_writers: set[str] = set()
    unsigned_writers: set[str] = set()

    for raw in raw_messages:
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
    response = request_json(req, is_write=True)

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


def fetch_room(room: str, limit: int) -> dict[str, Any]:
    room = valid_room(room)
    if not 1 <= limit <= 800:
        raise SystemExit("limit must be 1..800")
    req = urllib.request.Request(
        f"{BASE_URL}/r/{urllib.parse.quote(room, safe='')}?format=json&limit={limit}",
        method="GET",
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
    )
    return request_json(req)


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
    print("No network writes performed.")
    return rows


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
    print("FLOP Scout v0.3.2\n")
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
    p = argparse.ArgumentParser(description="FLOP Scout v0.3.2 - Precision Opportunity Filtering")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init")
    sub.add_parser("did")
    sub.add_parser("doctor")
    sub.add_parser("self-test")
    sub.add_parser("protocol-watch")
    sub.add_parser("originality")
    sub.add_parser("network")
    sub.add_parser("dashboard")

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
    elif a.cmd == "observe":
        observe(a.rooms, a.limit)
    elif a.cmd == "originality":
        print_originality()
    elif a.cmd == "network":
        print_network()
    elif a.cmd == "dashboard":
        dashboard()
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
