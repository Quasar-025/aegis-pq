from dataclasses import dataclass


@dataclass(frozen=True)
class CryptoConfig:
    kem_name: str = "Kyber1024"
    sig_name: str = "Dilithium5"
    use_oqs: bool = True
    block_size: int = 4096


@dataclass(frozen=True)
class StorageConfig:
    relay_db_path: str = "relay.sqlite3"
    blob_dir: str = "blobs"


@dataclass(frozen=True)
class RelayConfig:
    host: str = "127.0.0.1"
    port: int = 8888
    quic_port: int = 8889
    auth_token: str = "aegis-demo-auth-token"
    transport: str = "quic"


@dataclass(frozen=True)
class AppConfig:
    crypto: CryptoConfig = CryptoConfig()
    storage: StorageConfig = StorageConfig()
    relay: RelayConfig = RelayConfig()
    max_message_size: int = 1024 * 1024


DEFAULT_CONFIG = AppConfig()
