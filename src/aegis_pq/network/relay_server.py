import asyncio
import argparse
import secrets
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from aegis_pq.proto import aegis_pb2 as _aegis_pb2
from aegis_pq.protocol.sealed_sender import envelope_from_bytes, unseal_at_server
from aegis_pq.network.quic_transport import QuicRelayServer
from aegis_pq.storage.relay_blob_store import RelayBlobStore
from aegis_pq.storage.relay_db import RelayDB

pb: Any = _aegis_pb2


async def _read_frame(reader: asyncio.StreamReader) -> bytes:
    length = int.from_bytes(await reader.readexactly(4), "big")
    return await reader.readexactly(length)


async def _write_frame(writer: asyncio.StreamWriter, payload: bytes):
    writer.write(len(payload).to_bytes(4, "big") + payload)
    await writer.drain()


class RelayServer:
    def __init__(self, db_path: str = "relay.sqlite3", blob_root: str = "relay-blobs", auth_token: str = "aegis-demo-auth-token"):
        self.db = RelayDB(db_path)
        self.blobs = RelayBlobStore(blob_root)
        self.auth_token = auth_token.encode()
        self.server_private_key = x25519.X25519PrivateKey.generate()
        self.server_public_key = self.server_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._quic_server: QuicRelayServer | None = None

    def _auth_ok(self, token: bytes) -> bool:
        return secrets.compare_digest(token, self.auth_token)

    async def process_request_bytes(self, raw: bytes) -> bytes:
        req = pb.RelayRequest()
        req.ParseFromString(raw)
        resp = pb.RelayResponse(ok=False)

        if not self._auth_ok(req.auth_token):
            resp.error = "unauthorized"
            return resp.SerializeToString()

        if req.op == pb.RELAY_OPERATION_GET_PUBKEY:
            resp.ok = True
            resp.relay_public_key = self.server_public_key
            return resp.SerializeToString()

        if req.op == pb.RELAY_OPERATION_PUT_BUNDLE:
            bundle = req.put_bundle.bundle
            otpk_rows: list[tuple[int, bytes, bytes, bytes]] = []
            for otpk in bundle.one_time_prekeys:
                otpk_rows.append((otpk.key_id, otpk.kem_public_key, otpk.dh_public_key, otpk.signature))
            self.db.upsert_prekey_bundle(
                user_id=bundle.user_id,
                sig_public_key=bundle.sig_public_key,
                kem_public_key=bundle.kem_public_key,
                dh_public_key=bundle.dh_public_key,
                bundle_signature=bundle.bundle_signature,
                one_time_prekeys=otpk_rows,
            )
            resp.ok = True
            return resp.SerializeToString()

        if req.op == pb.RELAY_OPERATION_GET_BUNDLE:
            row = self.db.get_prekey_bundle(req.get_bundle.user_id)
            if not row:
                resp.ok = False
                resp.error = "bundle-not-found"
                return resp.SerializeToString()

            bundle = pb.PreKeyBundle(
                user_id=row["user_id"],
                sig_public_key=row["sig_public_key"],
                kem_public_key=row["kem_public_key"],
                dh_public_key=row["dh_public_key"],
                bundle_signature=row["bundle_signature"],
            )
            if row.get("one_time_prekey"):
                otpk = row["one_time_prekey"]
                bundle.one_time_prekeys.append(
                    pb.OneTimePreKey(
                        key_id=otpk["key_id"],
                        kem_public_key=otpk["kem_public_key"],
                        dh_public_key=otpk["dh_public_key"],
                        signature=otpk["signature"],
                    )
                )
            resp.ok = True
            resp.bundle.bundle.CopyFrom(bundle)
            return resp.SerializeToString()

        if req.op == pb.RELAY_OPERATION_ENQUEUE:
            envelope = envelope_from_bytes(req.enqueue.envelope)
            unsealed = unseal_at_server(
                self.server_private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                ),
                envelope,
            )
            self.db.enqueue_envelope(unsealed["recipient_id"], unsealed["payload"])
            resp.ok = True
            return resp.SerializeToString()

        if req.op == pb.RELAY_OPERATION_DEQUEUE:
            payloads = self.db.dequeue_envelopes(req.dequeue.recipient_id, req.dequeue.limit or 100)
            resp.ok = True
            for payload in payloads:
                resp.dequeue.payloads.append(payload)
            return resp.SerializeToString()

        if req.op == pb.RELAY_OPERATION_UPLOAD_BLOB:
            stored = self.blobs.put(req.upload_blob.blob_id, req.upload_blob.ciphertext)
            resp.ok = True
            resp.upload_blob.stored = stored
            return resp.SerializeToString()

        if req.op == pb.RELAY_OPERATION_DOWNLOAD_BLOB:
            ciphertext = self.blobs.get(req.download_blob.blob_id)
            if ciphertext is None:
                resp.ok = False
                resp.error = "blob-not-found"
            else:
                resp.ok = True
                resp.download_blob.ciphertext = ciphertext
            return resp.SerializeToString()

        resp.error = "unknown-operation"
        return resp.SerializeToString()

    async def handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            raw = await _read_frame(reader)
            reply = await self.process_request_bytes(raw)
            await _write_frame(writer, reply)
        finally:
            writer.close()
            await writer.wait_closed()

    async def start_quic(self, host: str, port: int, cert_dir: str = ".quic"):
        self._quic_server = QuicRelayServer(host=host, port=port, cert_dir=cert_dir, request_handler=self.process_request_bytes)
        await self._quic_server.start()

    async def stop_quic(self):
        if self._quic_server:
            await self._quic_server.stop()


async def main(
    host: str = "0.0.0.0",
    port: int = 8888,
    quic_port: int = 8889,
    auth_token: str = "aegis-demo-auth-token",
    db_path: str = "relay.sqlite3",
    blob_root: str = "relay-blobs",
):
    relay = RelayServer(db_path=db_path, blob_root=blob_root, auth_token=auth_token)
    srv = await asyncio.start_server(relay.handle_tcp, host, port)
    await relay.start_quic(host, quic_port, cert_dir=".relay-quic")
    print(f"relay (tcp) listening on {host}:{port}")
    print(f"relay (quic) listening on {host}:{quic_port}")
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aegis-PQ Relay Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--quic-port", type=int, default=8889)
    parser.add_argument("--auth-token", default="aegis-demo-auth-token")
    parser.add_argument("--db-path", default="relay.sqlite3")
    parser.add_argument("--blob-root", default="relay-blobs")
    args = parser.parse_args()
    asyncio.run(
        main(
            host=args.host,
            port=args.port,
            quic_port=args.quic_port,
            auth_token=args.auth_token,
            db_path=args.db_path,
            blob_root=args.blob_root,
        )
    )
