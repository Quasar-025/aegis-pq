import ctypes
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _bytes_to_blob(data: bytes) -> DATA_BLOB:
    arr = (ctypes.c_byte * len(data)).from_buffer_copy(data)
    return DATA_BLOB(len(data), ctypes.cast(arr, ctypes.POINTER(ctypes.c_byte)))


def _blob_to_bytes(blob: DATA_BLOB) -> bytes:
    return bytes(ctypes.string_at(blob.pbData, blob.cbData))


class LocalKeyStore:
    def __init__(self, root: str = ".keystore"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.windows_dpapi = os.name == "nt"
        self._fernet_key_file = self.root / "fallback.fernet.key"

    def _encrypt(self, plaintext: bytes) -> bytes:
        if self.windows_dpapi:
            crypt32 = ctypes.windll.crypt32
            kernel32 = ctypes.windll.kernel32
            in_blob = _bytes_to_blob(plaintext)
            out_blob = DATA_BLOB()
            if crypt32.CryptProtectData(
                ctypes.byref(in_blob),
                "AegisPQ".encode("utf-16-le"),
                None,
                None,
                None,
                0,
                ctypes.byref(out_blob),
            ):
                try:
                    return _blob_to_bytes(out_blob)
                finally:
                    kernel32.LocalFree(out_blob.pbData)
        if not self._fernet_key_file.exists():
            self._fernet_key_file.write_bytes(Fernet.generate_key())
        return Fernet(self._fernet_key_file.read_bytes()).encrypt(plaintext)

    def _decrypt(self, ciphertext: bytes) -> bytes:
        if self.windows_dpapi:
            crypt32 = ctypes.windll.crypt32
            kernel32 = ctypes.windll.kernel32
            in_blob = _bytes_to_blob(ciphertext)
            out_blob = DATA_BLOB()
            if crypt32.CryptUnprotectData(
                ctypes.byref(in_blob),
                None,
                None,
                None,
                None,
                0,
                ctypes.byref(out_blob),
            ):
                try:
                    return _blob_to_bytes(out_blob)
                finally:
                    kernel32.LocalFree(out_blob.pbData)
        return Fernet(self._fernet_key_file.read_bytes()).decrypt(ciphertext)

    def save_identity(self, user_id: str, data: dict):
        payload = json.dumps(data, separators=(",", ":")).encode()
        protected = self._encrypt(payload)
        (self.root / f"{user_id}.bin").write_bytes(protected)

    def load_identity(self, user_id: str) -> dict | None:
        path = self.root / f"{user_id}.bin"
        if not path.exists():
            return None
        plaintext = self._decrypt(path.read_bytes())
        return json.loads(plaintext.decode())
