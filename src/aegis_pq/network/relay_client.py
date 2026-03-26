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
        request_timeout: float = 8.0,
        quic_fallback_to_tcp: bool = True,
    ):
        self.host = host
        self.port = port
        self.quic_port = quic_port
        self.auth_token = auth_token.encode()
        self.transport = transport
        self.request_timeout = request_timeout
        self.quic_fallback_to_tcp = quic_fallback_to_tcp
        self._quic = QuicRelayClient(host, quic_port)

    async def _call_tcp(self, req):
        reader, writer = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), timeout=self.request_timeout)
        encoded = req.SerializeToString()
        writer.write(len(encoded).to_bytes(4, "big") + encoded)
        await asyncio.wait_for(writer.drain(), timeout=self.request_timeout)
        length = int.from_bytes(await asyncio.wait_for(reader.readexactly(4), timeout=self.request_timeout), "big")
        raw = await asyncio.wait_for(reader.readexactly(length), timeout=self.request_timeout)
        writer.close()
        await writer.wait_closed()
        resp = pb.RelayResponse()
        resp.ParseFromString(raw)
        return resp

    async def _call(self, req):
        if self.transport == "quic":
            try:
                raw = await self._quic.request(req.SerializeToString(), timeout=self.request_timeout)
                resp = pb.RelayResponse()
                resp.ParseFromString(raw)
                return resp
            except Exception:
                if not self.quic_fallback_to_tcp:
                    raise
                return await self._call_tcp(req)
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
