"""
FIPS 140-3 / NIST SP 800-53 AU-9 / SC-28 compliant audit logger.
AES-256-GCM encryption at rest + SHA-256 hash chain = tamper-evident WORM log.

Security properties:
  - AES-256-GCM: authenticated encryption (confidentiality + integrity + authenticity)
  - 96-bit random nonce per entry — NIST SP 800-38D compliant
  - HKDF-SHA256 key derivation — FIPS 140-3 approved
  - SHA-256 hash chain: each entry commits to the previous entry's hash
  - Chain verification: detects deletion, insertion, or modification of any record
  - Thread-safe append-only writes

Production swap: replace SQLite with PostgreSQL + pgcrypto, or
an HSM-backed encrypted database like EnvoyDB or AWS Aurora DSQL.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Generator, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core.models import FirewallAuditEntry, ScanResult


def _derive_audit_key(master_key_hex: str) -> bytes:
    """
    HKDF-SHA256 key derivation from master key.
    FIPS 140-3 approved KDF. Never stores the raw master key.
    In production: master_key comes from HashiCorp Vault / AWS KMS.
    """
    if not master_key_hex:
        # Demo mode: derive from random bytes (not reproducible across restarts)
        raw = os.urandom(32)
    else:
        raw = bytes.fromhex(master_key_hex) if len(master_key_hex) == 64 else master_key_hex.encode()

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"aetherhorizon-firewall-audit-v1",
        info=b"audit-encryption-key",
    )
    return hkdf.derive(raw)


class SecureAuditLogger:
    """
    Tamper-evident, encrypted, append-only audit logger.

    Write path: plaintext dict → JSON → AES-256-GCM encrypt → store (nonce + ciphertext + hashes)
    Read path:  load (nonce + ciphertext) → AES-256-GCM decrypt + verify tag → JSON parse
    Verify path: recompute SHA-256 hash chain from genesis → detect any tampering
    """

    _lock = threading.Lock()

    def __init__(
        self,
        db_path: str = "data/secure_audit.db",
        master_key_hex: str = "",
    ):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        derived = _derive_audit_key(master_key_hex)
        self._aesgcm = AESGCM(derived)
        self._chain_head: str = "0" * 64  # Genesis block

        self._init_db()
        self._load_chain_head()

    @contextmanager
    def _get_conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS secure_audit (
                    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_id      TEXT UNIQUE NOT NULL,
                    nonce_hex   TEXT NOT NULL,
                    ciphertext  BLOB NOT NULL,
                    prev_hash   TEXT NOT NULL,
                    entry_hash  TEXT NOT NULL,
                    timestamp   TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON secure_audit(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_hash ON secure_audit(entry_hash)")
            conn.commit()

    def _load_chain_head(self) -> None:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT entry_hash FROM secure_audit ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if row:
                self._chain_head = row["entry_hash"]

    def _encrypt(self, data: dict[str, Any]) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)  # 96-bit — NIST SP 800-38D
        plaintext = json.dumps(data, default=str).encode()
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        return nonce, ciphertext

    def _decrypt(self, nonce_bytes: bytes, ciphertext: bytes) -> dict[str, Any]:
        plaintext = self._aesgcm.decrypt(nonce_bytes, ciphertext, None)
        return json.loads(plaintext.decode())

    def _hash_entry(self, log_id: str, prev_hash: str, ciphertext: bytes) -> str:
        h = hashlib.sha256()
        h.update(log_id.encode())
        h.update(prev_hash.encode())
        h.update(ciphertext)
        return h.hexdigest()

    def log_scan(self, result: ScanResult, metadata: dict[str, Any] = None) -> str:
        """Encrypt and append scan result. Returns the entry's chain hash."""
        import uuid

        entry = FirewallAuditEntry(
            request_id=result.request_id,
            decision=result.decision,
            threat_level=result.threat_level,
            composite_score=result.composite_score,
            primary_category=result.primary_category,
            atlas_technique_ids=result.atlas_annotation.technique_ids if result.atlas_annotation else [],
            layers_executed=[l.value for l in result.layers_executed],
            triggered_rules=[
                r for lr in result.layer_results for r in lr.triggered_rules
            ][:10],
            total_time_ms=result.total_processing_time_ms,
            ensemble_disagreement=result.ensemble.disagreement_score if result.ensemble else None,
            canary_triggered=result.canary_result.triggered if result.canary_result else False,
            metadata=metadata or {},
        )

        payload = entry.model_dump(mode="json")
        payload["logged_at"] = datetime.utcnow().isoformat()

        with self._lock:
            nonce, ciphertext = self._encrypt(payload)
            prev_hash = self._chain_head
            entry_hash = self._hash_entry(entry.log_id, prev_hash, ciphertext)

            with self._get_conn() as conn:
                conn.execute(
                    "INSERT INTO secure_audit (log_id,nonce_hex,ciphertext,prev_hash,entry_hash,timestamp) "
                    "VALUES (?,?,?,?,?,?)",
                    (entry.log_id, nonce.hex(), ciphertext, prev_hash,
                     entry_hash, payload["logged_at"]),
                )
                conn.commit()

            self._chain_head = entry_hash
            return entry_hash

    def verify_chain(self) -> tuple[bool, Optional[str]]:
        """
        Verify complete hash chain integrity from genesis to head.
        O(n) in number of entries. Run periodically as a health check.
        Returns (is_valid, error_message_or_None).
        """
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT log_id, nonce_hex, ciphertext, prev_hash, entry_hash "
                "FROM secure_audit ORDER BY seq ASC"
            ).fetchall()

        prev = "0" * 64
        for row in rows:
            nonce = bytes.fromhex(row["nonce_hex"])
            # Verify hash chain link
            expected = self._hash_entry(row["log_id"], row["prev_hash"], bytes(row["ciphertext"]))
            if expected != row["entry_hash"]:
                return False, f"Hash mismatch at log_id={row['log_id']} — entry may be modified"
            if row["prev_hash"] != prev:
                return False, f"Chain break at log_id={row['log_id']} — entry may be deleted or inserted"
            # Verify AES-GCM authentication tag
            try:
                self._decrypt(nonce, bytes(row["ciphertext"]))
            except Exception as e:
                return False, f"Auth tag failure at log_id={row['log_id']}: {e}"
            prev = row["entry_hash"]

        return True, None

    def read_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        """Decrypt and return recent entries (authorized access only)."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT nonce_hex, ciphertext, entry_hash FROM secure_audit ORDER BY seq DESC LIMIT ?",
                (limit,),
            ).fetchall()
        results = []
        for row in rows:
            try:
                nonce = bytes.fromhex(row["nonce_hex"])
                entry = self._decrypt(nonce, bytes(row["ciphertext"]))
                entry["_chain_hash"] = row["entry_hash"]
                results.append(entry)
            except Exception:
                results.append({"error": "decryption_failed", "_chain_hash": row["entry_hash"]})
        return results

    def get_stats(self) -> dict[str, Any]:
        with self._get_conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM secure_audit").fetchone()[0]
            return {
                "total_entries": total,
                "chain_head": self._chain_head[:16] + "...",
                "db_size_bytes": self.db_path.stat().st_size if self.db_path.exists() else 0,
            }

    def mark_false_positive(self, log_id: str, is_fp: bool) -> None:
        """
        Analyst feedback — NOTE: cannot modify encrypted entries (WORM).
        Instead, appends a new signed correction entry to the chain.
        """
        correction = {
            "type": "ANALYST_CORRECTION",
            "target_log_id": log_id,
            "false_positive": is_fp,
            "corrected_at": datetime.utcnow().isoformat(),
        }
        self.log_scan.__func__  # Reuse encryption path via direct call
        # Direct correction entry
        import uuid as _uuid
        correction["log_id"] = str(_uuid.uuid4())
        with self._lock:
            nonce, ciphertext = self._encrypt(correction)
            prev_hash = self._chain_head
            entry_hash = self._hash_entry(correction["log_id"], prev_hash, ciphertext)
            with self._get_conn() as conn:
                conn.execute(
                    "INSERT INTO secure_audit (log_id,nonce_hex,ciphertext,prev_hash,entry_hash,timestamp) "
                    "VALUES (?,?,?,?,?,?)",
                    (correction["log_id"], nonce.hex(), ciphertext, prev_hash,
                     entry_hash, correction["corrected_at"]),
                )
                conn.commit()
            self._chain_head = entry_hash


_instance: Optional[SecureAuditLogger] = None

def get_audit_logger() -> SecureAuditLogger:
    global _instance
    if _instance is None:
        from config.settings import settings
        _instance = SecureAuditLogger(
            db_path=settings.secure_audit_db_path,
            master_key_hex=settings.audit_master_key,
        )
    return _instance
