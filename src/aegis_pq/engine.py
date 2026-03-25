from dataclasses import dataclass
from typing import Any

from aegis_pq.config import AppConfig, DEFAULT_CONFIG
from aegis_pq.crypto.classical import generate_x25519_keypair, random_bytes
from aegis_pq.crypto.pq import PQCryptoProvider
from aegis_pq.network.relay_client import RelayClient
from aegis_pq.proto import aegis_pb2 as _aegis_pb2
from aegis_pq.protocol.packet_codec import ratchet_packet_from_bytes, ratchet_packet_to_bytes
from aegis_pq.protocol.ratchet import PQDoubleRatchet, RatchetState
from aegis_pq.protocol.sealed_sender import envelope_to_bytes, seal_for_server
from aegis_pq.protocol.types import HandshakeInit, OneTimePreKey, PreKeyBundle
from aegis_pq.protocol.x3dh import PQX3DH
from aegis_pq.storage.blob_store import BlobStore
from aegis_pq.storage.keystore import LocalKeyStore

pb: Any = _aegis_pb2


@dataclass
class UserIdentity:
    user_id: str
    sig_public_key: bytes
    sig_private_key: bytes
    kem_public_key: bytes
    kem_private_key: bytes
    dh_public_key: bytes
    dh_private_key: bytes


@dataclass
class LocalOneTimePreKey:
    key_id: int
    kem_public_key: bytes
    kem_private_key: bytes
    dh_public_key: bytes
    dh_private_key: bytes
    signature: bytes


class AegisClient:
    def __init__(
        self,
        user_id: str,
        relay: RelayClient,
        blob_store: BlobStore,
        config: AppConfig = DEFAULT_CONFIG,
        keystore: LocalKeyStore | None = None,
    ):
        self.user_id = user_id
        self.relay = relay
        self.blob_store = blob_store
        self.config = config
        self.keystore = keystore or LocalKeyStore()

        self.crypto = PQCryptoProvider(
            kem_name=config.crypto.kem_name,
            sig_name=config.crypto.sig_name,
            use_oqs=config.crypto.use_oqs,
        )

        loaded = self.keystore.load_identity(user_id)
        if loaded:
            self.identity = UserIdentity(
                user_id=user_id,
                sig_public_key=bytes.fromhex(loaded["sig_public_key"]),
                sig_private_key=bytes.fromhex(loaded["sig_private_key"]),
                kem_public_key=bytes.fromhex(loaded["kem_public_key"]),
                kem_private_key=bytes.fromhex(loaded["kem_private_key"]),
                dh_public_key=bytes.fromhex(loaded["dh_public_key"]),
                dh_private_key=bytes.fromhex(loaded["dh_private_key"]),
            )
            self.one_time_prekeys: dict[int, LocalOneTimePreKey] = {
                int(k): LocalOneTimePreKey(
                    key_id=int(k),
                    kem_public_key=bytes.fromhex(v["kem_public_key"]),
                    kem_private_key=bytes.fromhex(v["kem_private_key"]),
                    dh_public_key=bytes.fromhex(v["dh_public_key"]),
                    dh_private_key=bytes.fromhex(v["dh_private_key"]),
                    signature=bytes.fromhex(v["signature"]),
                )
                for k, v in loaded.get("one_time_prekeys", {}).items()
            }
            self._next_otpk_id = loaded.get("next_otpk_id", 1)
        else:
            sig = self.crypto.generate_signature_keypair()
            kem = self.crypto.generate_kem_keypair()
            dh = generate_x25519_keypair()
            self.identity = UserIdentity(
                user_id=user_id,
                sig_public_key=sig.public_key,
                sig_private_key=sig.private_key,
                kem_public_key=kem.public_key,
                kem_private_key=kem.private_key,
                dh_public_key=dh.public_bytes(),
                dh_private_key=dh.private_bytes(),
            )
            self.one_time_prekeys = {}
            self._next_otpk_id = 1
            self._generate_one_time_prekeys(target_count=32)
            self._persist_identity()

        self.server_public_key: bytes | None = None
        self.handshake = PQX3DH(self.crypto)
        self.ratchet = PQDoubleRatchet(self.crypto, block_size=config.crypto.block_size)
        self.sessions: dict[str, RatchetState] = {}
        self.peer_sig_keys: dict[str, bytes] = {}
        self.handshake_audit: dict[str, dict] = {}

    def crypto_profile(self) -> dict:
        return {
            "kem": self.crypto.kem_name,
            "signature": self.crypto.sig_name,
            "pq_enabled": bool(self.crypto.use_oqs),
            "kem_runtime": self.crypto.kem_name if self.crypto.use_oqs else "fallback-classical-kem",
            "signature_runtime": self.crypto.sig_name if self.crypto.use_oqs else "fallback-ed25519",
        }

    def _persist_identity(self):
        self.keystore.save_identity(
            self.user_id,
            {
                "sig_public_key": self.identity.sig_public_key.hex(),
                "sig_private_key": self.identity.sig_private_key.hex(),
                "kem_public_key": self.identity.kem_public_key.hex(),
                "kem_private_key": self.identity.kem_private_key.hex(),
                "dh_public_key": self.identity.dh_public_key.hex(),
                "dh_private_key": self.identity.dh_private_key.hex(),
                "next_otpk_id": self._next_otpk_id,
                "one_time_prekeys": {
                    str(k): {
                        "kem_public_key": v.kem_public_key.hex(),
                        "kem_private_key": v.kem_private_key.hex(),
                        "dh_public_key": v.dh_public_key.hex(),
                        "dh_private_key": v.dh_private_key.hex(),
                        "signature": v.signature.hex(),
                    }
                    for k, v in self.one_time_prekeys.items()
                },
            },
        )

    def _generate_one_time_prekeys(self, target_count: int = 32):
        while len(self.one_time_prekeys) < target_count:
            kid = self._next_otpk_id
            self._next_otpk_id += 1
            kem = self.crypto.generate_kem_keypair()
            dh = generate_x25519_keypair()
            signed = self.user_id.encode() + kid.to_bytes(4, "big") + kem.public_key + dh.public_bytes()
            sig = self.crypto.sign(self.identity.sig_private_key, signed)
            self.one_time_prekeys[kid] = LocalOneTimePreKey(
                key_id=kid,
                kem_public_key=kem.public_key,
                kem_private_key=kem.private_key,
                dh_public_key=dh.public_bytes(),
                dh_private_key=dh.private_bytes(),
                signature=sig,
            )

    async def bootstrap(self):
        self.server_public_key = await self.relay.get_relay_public_key()

    async def publish_prekey_bundle(self):
        if len(self.one_time_prekeys) < 8:
            self._generate_one_time_prekeys(32)
        signed = self.user_id.encode() + self.identity.kem_public_key + self.identity.dh_public_key
        bundle_signature = self.crypto.sign(self.identity.sig_private_key, signed)
        bundle = pb.PreKeyBundle(
            user_id=self.user_id,
            sig_public_key=self.identity.sig_public_key,
            kem_public_key=self.identity.kem_public_key,
            dh_public_key=self.identity.dh_public_key,
            bundle_signature=bundle_signature,
        )
        for otpk in self.one_time_prekeys.values():
            bundle.one_time_prekeys.append(
                pb.OneTimePreKey(
                    key_id=otpk.key_id,
                    kem_public_key=otpk.kem_public_key,
                    dh_public_key=otpk.dh_public_key,
                    signature=otpk.signature,
                )
            )
        await self.relay.put_bundle(bundle)
        self._persist_identity()

    async def _maybe_replenish_prekeys(self):
        if len(self.one_time_prekeys) < 8:
            self._generate_one_time_prekeys(32)
            await self.publish_prekey_bundle()

    async def initiate_session(self, peer_id: str):
        if self.server_public_key is None:
            await self.bootstrap()
        assert self.server_public_key is not None

        bundle_pb = await self.relay.get_bundle(peer_id)
        otpk = None
        if bundle_pb.one_time_prekeys:
            one = bundle_pb.one_time_prekeys[0]
            otpk = OneTimePreKey(
                key_id=one.key_id,
                kem_public_key=one.kem_public_key,
                dh_public_key=one.dh_public_key,
                signature=one.signature,
            )

        bundle = PreKeyBundle(
            user_id=bundle_pb.user_id,
            sig_public_key=bundle_pb.sig_public_key,
            kem_public_key=bundle_pb.kem_public_key,
            dh_public_key=bundle_pb.dh_public_key,
            bundle_signature=bundle_pb.bundle_signature,
            one_time_prekey=otpk,
        )
        self.peer_sig_keys[peer_id] = bundle.sig_public_key

        eph = generate_x25519_keypair()
        init, secrets = self.handshake.initiator_handshake(
            sender_id=self.user_id,
            sender_sig_public_key=self.identity.sig_public_key,
            sender_sig_private_key=self.identity.sig_private_key,
            sender_ephemeral_dh_private=eph.private_bytes(),
            sender_ephemeral_dh_public=eph.public_bytes(),
            receiver_bundle=bundle,
        )
        self.sessions[peer_id] = self.ratchet.init_state(
            session_id=f"{self.user_id}:{peer_id}",
            master_secret=secrets.master_secret,
            is_initiator=True,
        )
        self.handshake_audit[peer_id] = {
            "role": "initiator",
            "kem_runtime": self.crypto_profile()["kem_runtime"],
            "one_time_prekey_id": init.one_time_prekey_id,
            "pq_enabled": self.crypto.use_oqs,
        }

        app_msg = pb.AppMessage(
            handshake=pb.HandshakeInit(
                sender_id=init.sender_id,
                sender_sig_public_key=init.sender_sig_public_key,
                sender_ephemeral_dh_public_key=init.sender_ephemeral_dh_public_key,
                kem_ciphertext=init.kem_ciphertext,
                sender_signature=init.sender_signature,
                one_time_prekey_id=init.one_time_prekey_id,
            )
        )
        envelope = seal_for_server(
            self.server_public_key,
            sender_id=self.user_id,
            recipient_id=peer_id,
            payload=app_msg.SerializeToString(),
        )
        await self.relay.enqueue(envelope_to_bytes(envelope))

    async def send_text(self, peer_id: str, text: str):
        if self.server_public_key is None:
            await self.bootstrap()
        assert self.server_public_key is not None
        if peer_id not in self.sessions:
            raise RuntimeError(f"session not established with {peer_id}")

        packet = self.ratchet.encrypt(
            self.sessions[peer_id],
            sender_id=self.user_id,
            signing_private_key=self.identity.sig_private_key,
            plaintext=text.encode(),
        )
        app_msg = pb.AppMessage()
        app_msg.ratchet_packet.ParseFromString(ratchet_packet_to_bytes(packet))
        envelope = seal_for_server(
            self.server_public_key,
            sender_id=self.user_id,
            recipient_id=peer_id,
            payload=app_msg.SerializeToString(),
        )
        await self.relay.enqueue(envelope_to_bytes(envelope))

    async def send_file(self, peer_id: str, filename: str, content: bytes):
        if self.server_public_key is None:
            await self.bootstrap()
        assert self.server_public_key is not None
        if peer_id not in self.sessions:
            raise RuntimeError(f"session not established with {peer_id}")

        file_key = random_bytes(32)
        blob_id, digest, nonce, ciphertext = self.blob_store.encrypt_detached(file_key, content)
        await self.relay.upload_blob(blob_id, ciphertext)

        pointer = pb.FilePointer(
            blob_id=blob_id,
            file_hash=digest,
            encrypted_key=file_key,
            nonce=nonce,
            size=len(content),
            filename=filename,
        )
        packet = self.ratchet.encrypt(
            self.sessions[peer_id],
            sender_id=self.user_id,
            signing_private_key=self.identity.sig_private_key,
            plaintext=b"FILEPB::" + pointer.SerializeToString(),
        )
        app_msg = pb.AppMessage()
        app_msg.ratchet_packet.ParseFromString(ratchet_packet_to_bytes(packet))
        envelope = seal_for_server(
            self.server_public_key,
            sender_id=self.user_id,
            recipient_id=peer_id,
            payload=app_msg.SerializeToString(),
        )
        await self.relay.enqueue(envelope_to_bytes(envelope))

    async def poll(self) -> list[dict]:
        payloads = await self.relay.dequeue(self.user_id)
        events: list[dict] = []

        for payload in payloads:
            app_msg = pb.AppMessage()
            app_msg.ParseFromString(payload)
            kind = app_msg.WhichOneof("kind")
            if kind == "handshake":
                h = app_msg.handshake
                init = HandshakeInit(
                    sender_id=h.sender_id,
                    sender_sig_public_key=h.sender_sig_public_key,
                    sender_ephemeral_dh_public_key=h.sender_ephemeral_dh_public_key,
                    kem_ciphertext=h.kem_ciphertext,
                    sender_signature=h.sender_signature,
                    one_time_prekey_id=h.one_time_prekey_id,
                )
                one_time_priv = None
                if init.one_time_prekey_id:
                    otpk = self.one_time_prekeys.pop(init.one_time_prekey_id, None)
                    if otpk:
                        one_time_priv = otpk.dh_private_key
                        self._persist_identity()

                secrets = self.handshake.responder_handshake(
                    receiver_kem_private_key=self.identity.kem_private_key,
                    receiver_dh_private_key=self.identity.dh_private_key,
                    init=init,
                    receiver_one_time_dh_private_key=one_time_priv,
                )
                self.sessions[init.sender_id] = self.ratchet.init_state(
                    session_id=f"{init.sender_id}:{self.user_id}",
                    master_secret=secrets.master_secret,
                    is_initiator=False,
                )
                self.peer_sig_keys[init.sender_id] = init.sender_sig_public_key
                self.handshake_audit[init.sender_id] = {
                    "role": "responder",
                    "kem_runtime": self.crypto_profile()["kem_runtime"],
                    "one_time_prekey_id": init.one_time_prekey_id,
                    "pq_enabled": self.crypto.use_oqs,
                }
                events.append({"type": "handshake", "from": init.sender_id})
                continue

            if kind == "ratchet_packet":
                packet = ratchet_packet_from_bytes(app_msg.ratchet_packet.SerializeToString())
                peer = packet.sender_id
                if peer not in self.sessions or peer not in self.peer_sig_keys:
                    events.append({"type": "error", "reason": "unknown-session", "from": peer})
                    continue
                plaintext = self.ratchet.decrypt(self.sessions[peer], self.peer_sig_keys[peer], packet)
                if plaintext.startswith(b"FILEPB::"):
                    pointer = pb.FilePointer()
                    pointer.ParseFromString(plaintext[8:])
                    ciphertext = await self.relay.download_blob(pointer.blob_id)
                    content = self.blob_store.decrypt_blob(pointer.encrypted_key, pointer.nonce, ciphertext)
                    events.append(
                        {
                            "type": "file",
                            "from": peer,
                            "filename": pointer.filename,
                            "content": content,
                        }
                    )
                else:
                    events.append({"type": "text", "from": peer, "text": plaintext.decode(errors="replace")})

        await self._maybe_replenish_prekeys()
        return events
