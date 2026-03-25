from pathlib import Path


class RelayBlobStore:
    def __init__(self, root: str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, blob_id: str, ciphertext: bytes) -> bool:
        path = self.root / blob_id
        if path.exists():
            return False
        path.write_bytes(ciphertext)
        return True

    def get(self, blob_id: str) -> bytes | None:
        path = self.root / blob_id
        if not path.exists():
            return None
        return path.read_bytes()
