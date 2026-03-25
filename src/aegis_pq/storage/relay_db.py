import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


class RelayDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self):
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS prekey_bundles (
                    user_id TEXT PRIMARY KEY,
                    sig_public_key BLOB NOT NULL,
                    kem_public_key BLOB NOT NULL,
                    dh_public_key BLOB NOT NULL,
                    bundle_signature BLOB NOT NULL,
                    updated_at INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS one_time_prekeys (
                    user_id TEXT NOT NULL,
                    key_id INTEGER NOT NULL,
                    kem_public_key BLOB NOT NULL,
                    dh_public_key BLOB NOT NULL,
                    signature BLOB NOT NULL,
                    consumed INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (user_id, key_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mailbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient_id TEXT NOT NULL,
                    envelope BLOB NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )

    def upsert_prekey_bundle(
        self,
        user_id: str,
        sig_public_key: bytes,
        kem_public_key: bytes,
        dh_public_key: bytes,
        bundle_signature: bytes,
        one_time_prekeys: list[tuple[int, bytes, bytes, bytes]],
    ):
        now = int(time.time())
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO prekey_bundles(user_id, sig_public_key, kem_public_key, dh_public_key, bundle_signature, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    sig_public_key=excluded.sig_public_key,
                    kem_public_key=excluded.kem_public_key,
                    dh_public_key=excluded.dh_public_key,
                    bundle_signature=excluded.bundle_signature,
                    updated_at=excluded.updated_at
                """,
                (user_id, sig_public_key, kem_public_key, dh_public_key, bundle_signature, now),
            )
            conn.execute("DELETE FROM one_time_prekeys WHERE user_id = ?", (user_id,))
            conn.executemany(
                """
                INSERT INTO one_time_prekeys(user_id, key_id, kem_public_key, dh_public_key, signature, consumed, created_at)
                VALUES (?, ?, ?, ?, ?, 0, ?)
                """,
                [(user_id, key_id, kem_pk, dh_pk, sig, now) for key_id, kem_pk, dh_pk, sig in one_time_prekeys],
            )

    def get_prekey_bundle(self, user_id: str):
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM prekey_bundles WHERE user_id = ?",
                (user_id,),
            ).fetchone()
            if not row:
                return None

            otpk = conn.execute(
                """
                SELECT key_id, kem_public_key, dh_public_key, signature
                FROM one_time_prekeys
                WHERE user_id = ? AND consumed = 0
                ORDER BY key_id ASC
                LIMIT 1
                """,
                (user_id,),
            ).fetchone()

            if otpk:
                conn.execute(
                    "UPDATE one_time_prekeys SET consumed = 1 WHERE user_id = ? AND key_id = ?",
                    (user_id, otpk["key_id"]),
                )

            data = dict(row)
            data["one_time_prekey"] = dict(otpk) if otpk else None
            return data

    def one_time_prekey_count(self, user_id: str) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(1) AS c FROM one_time_prekeys WHERE user_id = ? AND consumed = 0",
                (user_id,),
            ).fetchone()
            return int(row["c"])

    def enqueue_envelope(self, recipient_id: str, envelope: bytes):
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO mailbox(recipient_id, envelope, created_at) VALUES (?, ?, ?)",
                (recipient_id, envelope, int(time.time())),
            )

    def dequeue_envelopes(self, recipient_id: str, limit: int = 100) -> list[bytes]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, envelope FROM mailbox WHERE recipient_id = ? ORDER BY id ASC LIMIT ?",
                (recipient_id, limit),
            ).fetchall()
            ids = [row["id"] for row in rows]
            if ids:
                conn.executemany("DELETE FROM mailbox WHERE id = ?", [(mid,) for mid in ids])
            return [row["envelope"] for row in rows]
