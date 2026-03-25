import hashlib
import os
from pathlib import Path

from aegis_pq.crypto.symmetric import aes_gcm_decrypt, aes_gcm_encrypt


class BlobStore:
    def __init__(self, root: str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put_encrypted(self, key: bytes, content: bytes) -> tuple[str, bytes, bytes]:
        nonce, ciphertext = aes_gcm_encrypt(key, content)
        digest = hashlib.sha3_256(ciphertext).digest()
        blob_id = digest.hex()
        (self.root / blob_id).write_bytes(ciphertext)
        return blob_id, digest, nonce

    def encrypt_detached(self, key: bytes, content: bytes) -> tuple[str, bytes, bytes, bytes]:
        nonce, ciphertext = aes_gcm_encrypt(key, content)
        digest = hashlib.sha3_256(ciphertext).digest()
        blob_id = digest.hex()
        return blob_id, digest, nonce, ciphertext

    def get_encrypted(self, blob_id: str) -> bytes:
        return (self.root / blob_id).read_bytes()

    def decrypt_blob(self, key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        return aes_gcm_decrypt(key, nonce, ciphertext)

    def exists(self, blob_id: str) -> bool:
        return (self.root / blob_id).exists()
