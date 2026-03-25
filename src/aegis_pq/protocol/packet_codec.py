from typing import Any

from aegis_pq.proto import aegis_pb2 as _aegis_pb2
from aegis_pq.protocol.types import PacketHeader, RatchetPacket

pb: Any = _aegis_pb2


def ratchet_packet_to_bytes(packet: RatchetPacket) -> bytes:
    out = pb.RatchetPacket(
        header=pb.PacketHeader(
            session_id=packet.header.session_id,
            msg_index=packet.header.msg_index,
            ratchet_pub=packet.header.ratchet_pub,
            timestamp=packet.header.timestamp,
        ),
        nonce=packet.nonce,
        ciphertext=packet.ciphertext,
        signature=packet.signature,
        sender_id=packet.sender_id,
    )
    return out.SerializeToString()


def ratchet_packet_from_bytes(data: bytes) -> RatchetPacket:
    blob = pb.RatchetPacket()
    blob.ParseFromString(data)
    header = PacketHeader(
        session_id=blob.header.session_id,
        msg_index=blob.header.msg_index,
        ratchet_pub=blob.header.ratchet_pub,
        timestamp=blob.header.timestamp,
    )
    return RatchetPacket(
        header=header,
        nonce=blob.nonce,
        ciphertext=blob.ciphertext,
        signature=blob.signature,
        sender_id=blob.sender_id,
    )
