class AegisError(Exception):
    """Base exception for protocol errors."""


class SignatureVerificationError(AegisError):
    """Raised when a digital signature cannot be verified."""


class DecryptionError(AegisError):
    """Raised when authenticated decryption fails."""


class InvalidPacketError(AegisError):
    """Raised when packet schema or metadata is invalid."""
