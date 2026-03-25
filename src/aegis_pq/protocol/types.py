from dataclasses import dataclass
from typing import Optional


@dataclass
class OneTimePreKey:
    key_id: int
    kem_public_key: bytes
    dh_public_key: bytes
    signature: bytes


@dataclass
class PreKeyBundle:
    user_id: str
    sig_public_key: bytes
    kem_public_key: bytes
    dh_public_key: bytes
    bundle_signature: bytes
    one_time_prekey: OneTimePreKey | None = None


@dataclass
class HandshakeInit:
    sender_id: str
    sender_sig_public_key: bytes
    sender_ephemeral_dh_public_key: bytes
    kem_ciphertext: bytes
    sender_signature: bytes
    one_time_prekey_id: int = 0


@dataclass
class SealedEnvelope:
    nonce: bytes
    ciphertext: bytes
    ephemeral_pub: bytes


@dataclass
class PacketHeader:
    session_id: str
    msg_index: int
    ratchet_pub: bytes
    timestamp: int


@dataclass
class RatchetPacket:
    header: PacketHeader
    nonce: bytes
    ciphertext: bytes
    signature: bytes
    sender_id: str


@dataclass
class FilePointer:
    blob_id: str
    file_hash: bytes
    encrypted_key: bytes
    nonce: bytes
    size: int
    filename: str


@dataclass
class DeliveryRecord:
    mailbox_owner: str
    envelope: bytes
    created_at: int
    delivered_at: Optional[int] = None
