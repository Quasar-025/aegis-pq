import asyncio
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived


def ensure_quic_cert(cert_dir: str) -> tuple[str, str]:
    root = Path(cert_dir)
    root.mkdir(parents=True, exist_ok=True)
    cert_path = root / "relay-cert.pem"
    key_path = root / "relay-key.pem"
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aegis-pq-relay")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(__import__("datetime").datetime.utcnow())
        .not_valid_after(__import__("datetime").datetime.utcnow() + __import__("datetime").timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(cert_path), str(key_path)


class RelayQuicServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, request_handler, **kwargs):
        super().__init__(*args, **kwargs)
        self._request_handler = request_handler
        self._buffers: dict[int, bytearray] = {}

    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, StreamDataReceived):
            buf = self._buffers.setdefault(event.stream_id, bytearray())
            buf.extend(event.data)
            if event.end_stream:
                payload = bytes(buf)
                self._buffers.pop(event.stream_id, None)
                asyncio.create_task(self._handle_request(event.stream_id, payload))

    async def _handle_request(self, stream_id: int, payload: bytes):
        response = await self._request_handler(payload)
        self._quic.send_stream_data(stream_id, response, end_stream=True)
        self.transmit()


class RelayQuicClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._buffers: dict[int, bytearray] = {}
        self._waiters: dict[int, asyncio.Future[bytes]] = {}

    async def request(self, payload: bytes) -> bytes:
        stream_id = self._quic.get_next_available_stream_id()
        fut: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
        self._waiters[stream_id] = fut
        self._quic.send_stream_data(stream_id, payload, end_stream=True)
        self.transmit()
        return await fut

    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, StreamDataReceived):
            buf = self._buffers.setdefault(event.stream_id, bytearray())
            buf.extend(event.data)
            if event.end_stream:
                data = bytes(buf)
                self._buffers.pop(event.stream_id, None)
                fut = self._waiters.pop(event.stream_id, None)
                if fut and not fut.done():
                    fut.set_result(data)


class QuicRelayServer:
    def __init__(self, host: str, port: int, cert_dir: str, request_handler):
        self.host = host
        self.port = port
        self.cert_dir = cert_dir
        self.request_handler = request_handler
        self._server = None

    async def start(self):
        cert_path, key_path = ensure_quic_cert(self.cert_dir)
        config = QuicConfiguration(is_client=False, alpn_protocols=["aegis-pq-relay"])
        config.load_cert_chain(cert_path, key_path)
        self._server = await serve(
            self.host,
            self.port,
            configuration=config,
            create_protocol=lambda *args, **kwargs: RelayQuicServerProtocol(
                *args,
                request_handler=self.request_handler,
                **kwargs,
            ),
        )

    async def stop(self):
        if self._server:
            self._server.close()


class QuicRelayClient:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._lock = asyncio.Lock()

    async def request(self, payload: bytes) -> bytes:
        async with self._lock:
            config = QuicConfiguration(is_client=True, alpn_protocols=["aegis-pq-relay"])
            config.verify_mode = ssl.CERT_NONE
            async with connect(
                self.host,
                self.port,
                configuration=config,
                create_protocol=RelayQuicClientProtocol,
            ) as client:
                return await client.request(payload)
