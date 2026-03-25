import json
import time
from dataclasses import dataclass

from aegis_pq.crypto.pq import PQCryptoProvider
from aegis_pq.crypto.symmetric import aes_gcm_decrypt, aes_gcm_encrypt, hkdf_sha3_256, ratchet_kdf
from aegis_pq.errors import DecryptionError
from aegis_pq.protocol.padding import iso_7816_4_pad, iso_7816_4_unpad
from aegis_pq.protocol.types import PacketHeader, RatchetPacket


@dataclass
class RatchetState:
    session_id: str
    root_key: bytes
    send_chain_key: bytes
    recv_chain_key: bytes
    send_count: int = 0
    recv_count: int = 0


class PQDoubleRatchet:
    def __init__(self, crypto: PQCryptoProvider, block_size: int = 4096):
        self.crypto = crypto
        self.block_size = block_size

    def init_state(self, session_id: str, master_secret: bytes, is_initiator: bool) -> RatchetState:
        root_key = hkdf_sha3_256(master_secret, info=b"root-key")
        chain_a = hkdf_sha3_256(root_key, info=b"chain-a")
        chain_b = hkdf_sha3_256(root_key, info=b"chain-b")
        if is_initiator:
            send_ck, recv_ck = chain_a, chain_b
        else:
            send_ck, recv_ck = chain_b, chain_a
        return RatchetState(session_id=session_id, root_key=root_key, send_chain_key=send_ck, recv_chain_key=recv_ck)

    def kem_root_step_sender(self, state: RatchetState, peer_kem_public_key: bytes) -> tuple[RatchetState, bytes]:
        kem_ct, kem_ss = self.crypto.kem_encapsulate(peer_kem_public_key)
        new_root = hkdf_sha3_256(state.root_key + kem_ss, info=b"root-step")
        state.root_key = new_root
        state.send_chain_key = hkdf_sha3_256(new_root, info=b"send-chain")
        return state, kem_ct

    def kem_root_step_receiver(self, state: RatchetState, own_kem_private_key: bytes, kem_ciphertext: bytes) -> RatchetState:
        kem_ss = self.crypto.kem_decapsulate(own_kem_private_key, kem_ciphertext)
        new_root = hkdf_sha3_256(state.root_key + kem_ss, info=b"root-step")
        state.root_key = new_root
        state.recv_chain_key = hkdf_sha3_256(new_root, info=b"recv-chain")
        return state

    def encrypt(self, state: RatchetState, sender_id: str, signing_private_key: bytes, plaintext: bytes) -> RatchetPacket:
        state.send_chain_key, message_key = ratchet_kdf(state.send_chain_key)
        header = PacketHeader(
            session_id=state.session_id,
            msg_index=state.send_count,
            ratchet_pub=b"",
            timestamp=int(time.time()),
        )
        header_bytes = json.dumps(header.__dict__, sort_keys=True, default=lambda x: x.hex()).encode()
        padded = iso_7816_4_pad(plaintext, self.block_size)
        nonce, ciphertext = aes_gcm_encrypt(message_key[:32], padded, aad=header_bytes)
        signature = self.crypto.sign(signing_private_key, header_bytes + nonce + ciphertext)
        packet = RatchetPacket(
            header=header,
            nonce=nonce,
            ciphertext=ciphertext,
            signature=signature,
            sender_id=sender_id,
        )
        state.send_count += 1
        return packet

    def decrypt(self, state: RatchetState, sender_public_sig_key: bytes, packet: RatchetPacket) -> bytes:
        header_bytes = json.dumps(packet.header.__dict__, sort_keys=True, default=lambda x: x.hex()).encode()
        signed = header_bytes + packet.nonce + packet.ciphertext
        if not self.crypto.verify(sender_public_sig_key, signed, packet.signature):
            raise DecryptionError("ratchet packet signature verification failed")
        state.recv_chain_key, message_key = ratchet_kdf(state.recv_chain_key)
        try:
            padded = aes_gcm_decrypt(message_key[:32], packet.nonce, packet.ciphertext, aad=header_bytes)
            state.recv_count += 1
            return iso_7816_4_unpad(padded)
        except Exception as exc:
            raise DecryptionError("ratchet packet decrypt failed") from exc
