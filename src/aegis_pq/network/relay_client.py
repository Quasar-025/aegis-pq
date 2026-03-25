import asyncio
from typing import Any

from aegis_pq.proto import aegis_pb2 as _aegis_pb2

from .quic_transport import QuicRelayClient

pb: Any = _aegis_pb2


class RelayClient:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8888,
        quic_port: int = 8889,
        auth_token: str = "aegis-demo-auth-token",
        transport: str = "tcp",
    ):
        self.host = host
        self.port = port
        self.quic_port = quic_port
        self.auth_token = auth_token.encode()
        self.transport = transport
        self._quic = QuicRelayClient(host, quic_port)

    async def _call_tcp(self, req):
        reader, writer = await asyncio.open_connection(self.host, self.port)
        encoded = req.SerializeToString()
        writer.write(len(encoded).to_bytes(4, "big") + encoded)
        await writer.drain()
        length = int.from_bytes(await reader.readexactly(4), "big")
        raw = await reader.readexactly(length)
        writer.close()
        await writer.wait_closed()
        resp = pb.RelayResponse()
        resp.ParseFromString(raw)
        return resp

    async def _call(self, req):
        if self.transport == "quic":
            raw = await self._quic.request(req.SerializeToString())
            resp = pb.RelayResponse()
            resp.ParseFromString(raw)
            return resp
        return await self._call_tcp(req)

    async def get_relay_public_key(self) -> bytes:
        req = pb.RelayRequest(op=pb.RELAY_OPERATION_GET_PUBKEY, auth_token=self.auth_token)
        resp = await self._call(req)
        if not resp.ok:
            raise RuntimeError(resp.error)
        return resp.relay_public_key

    async def put_bundle(self, bundle):
        req = pb.RelayRequest(
            op=pb.RELAY_OPERATION_PUT_BUNDLE,
            auth_token=self.auth_token,
            put_bundle=pb.PublishBundleRequest(bundle=bundle),
        )
        resp = await self._call(req)
        if not resp.ok:
            raise RuntimeError(resp.error)

    async def get_bundle(self, user_id: str):
        req = pb.RelayRequest(
            op=pb.RELAY_OPERATION_GET_BUNDLE,
            auth_token=self.auth_token,
            get_bundle=pb.GetBundleRequest(user_id=user_id),
        )
        resp = await self._call(req)
        if not resp.ok:
            raise RuntimeError(resp.error)
        return resp.bundle.bundle

    async def enqueue(self, envelope: bytes):
        req = pb.RelayRequest(
            op=pb.RELAY_OPERATION_ENQUEUE,
            auth_token=self.auth_token,
            enqueue=pb.EnqueueRequest(envelope=envelope),
        )
        resp = await self._call(req)
        if not resp.ok:
            raise RuntimeError(resp.error)

    async def dequeue(self, recipient_id: str, limit: int = 100) -> list[bytes]:
        req = pb.RelayRequest(
            op=pb.RELAY_OPERATION_DEQUEUE,
            auth_token=self.auth_token,
            dequeue=pb.DequeueRequest(recipient_id=recipient_id, limit=limit),
        )
        resp = await self._call(req)
        if not resp.ok:
            raise RuntimeError(resp.error)
        return list(resp.dequeue.payloads)

    async def upload_blob(self, blob_id: str, ciphertext: bytes) -> bool:
        req = pb.RelayRequest(
            op=pb.RELAY_OPERATION_UPLOAD_BLOB,
            auth_token=self.auth_token,
            upload_blob=pb.BlobUploadRequest(blob_id=blob_id, ciphertext=ciphertext),
        )
        resp = await self._call(req)
        if not resp.ok:
            raise RuntimeError(resp.error)
        return resp.upload_blob.stored

    async def download_blob(self, blob_id: str) -> bytes:
        req = pb.RelayRequest(
            op=pb.RELAY_OPERATION_DOWNLOAD_BLOB,
            auth_token=self.auth_token,
            download_blob=pb.BlobDownloadRequest(blob_id=blob_id),
        )
        resp = await self._call(req)
        if not resp.ok:
            raise RuntimeError(resp.error)
        return resp.download_blob.ciphertext
