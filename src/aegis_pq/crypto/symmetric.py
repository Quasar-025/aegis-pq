import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def hkdf_sha3_256(ikm: bytes, salt: bytes = b"", info: bytes = b"", length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA3_256(),
        length=length,
        salt=salt if salt else None,
        info=info,
    )
    return hkdf.derive(ikm)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(data)
    return mac.finalize()


def ratchet_kdf(chain_key: bytes) -> Tuple[bytes, bytes]:
    next_chain_key = hmac_sha256(chain_key, b"chain")
    message_key = hmac_sha256(chain_key, b"message")
    return next_chain_key, message_key


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
