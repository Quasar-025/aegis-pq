import asyncio
import threading
from datetime import datetime

from aegis_pq.config import DEFAULT_CONFIG
from aegis_pq.engine import AegisClient
from aegis_pq.network.relay_client import RelayClient
from aegis_pq.network.relay_server import RelayServer
from aegis_pq.storage.blob_store import BlobStore

try:
    import customtkinter as ctk
except Exception:
    raise RuntimeError("customtkinter is required for UI. Install dependencies from requirements.txt")


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Aegis-PQ Secure Messenger")
        self.geometry("1100x720")
        ctk.set_appearance_mode("dark")

        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()

        self.server = RelayServer(
            db_path="ui-relay.sqlite3",
            blob_root="ui-relay-blobs",
            auth_token=DEFAULT_CONFIG.relay.auth_token,
        )
        self._submit(self._start_server())

        self.alice = AegisClient(
            "alice",
            RelayClient(port=9191, quic_port=9192, transport="quic", auth_token=DEFAULT_CONFIG.relay.auth_token),
            BlobStore("ui-blobs"),
            DEFAULT_CONFIG,
        )
        self.bob = AegisClient(
            "bob",
            RelayClient(port=9191, quic_port=9192, transport="quic", auth_token=DEFAULT_CONFIG.relay.auth_token),
            BlobStore("ui-blobs"),
            DEFAULT_CONFIG,
        )
        self._submit(self._bootstrap())

        self.header = ctk.CTkLabel(self, text="Aegis-PQ Demo Console", font=("Segoe UI", 24, "bold"))
        self.header.pack(padx=20, pady=(20, 8))

        self.chat = ctk.CTkTextbox(self, width=1040, height=460)
        self.chat.pack(padx=20, pady=12)

        self.row = ctk.CTkFrame(self)
        self.row.pack(fill="x", padx=20, pady=10)

        self.message_entry = ctk.CTkEntry(self.row, width=430, placeholder_text="Message from Alice -> Bob")
        self.message_entry.pack(padx=8, pady=10, side="left")

        self.reply_entry = ctk.CTkEntry(self.row, width=430, placeholder_text="Message from Bob -> Alice")
        self.reply_entry.pack(padx=8, pady=10, side="left")

        self.action_row = ctk.CTkFrame(self)
        self.action_row.pack(fill="x", padx=20, pady=8)

        self.send_button = ctk.CTkButton(self.action_row, text="Send Alice -> Bob", command=self.send_alice_to_bob)
        self.send_button.pack(padx=8, pady=10, side="left")

        self.reply_button = ctk.CTkButton(self.action_row, text="Send Bob -> Alice", command=self.send_bob_to_alice)
        self.reply_button.pack(padx=8, pady=10, side="left")

        self.file_button = ctk.CTkButton(self.action_row, text="Send Demo File", command=self.send_demo_file)
        self.file_button.pack(padx=8, pady=10, side="left")

        self.poll_button = ctk.CTkButton(self.action_row, text="Poll Both", command=self.poll_both)
        self.poll_button.pack(padx=8, pady=10, side="left")

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def _submit(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    async def _start_server(self):
        self.tcp = await asyncio.start_server(self.server.handle_tcp, "127.0.0.1", 9191)
        await self.server.start_quic("127.0.0.1", 9192, cert_dir=".ui-quic")

    async def _bootstrap(self):
        await self.alice.bootstrap()
        await self.bob.bootstrap()
        await self.alice.publish_prekey_bundle()
        await self.bob.publish_prekey_bundle()
        profile = self.alice.crypto_profile()
        self._append(
            f"[security] KEM runtime={profile['kem_runtime']} | SIG runtime={profile['signature_runtime']} | pq_enabled={profile['pq_enabled']}"
        )
        await self.alice.initiate_session("bob")
        await self.bob.poll()
        self._append("[system] Session established between alice and bob")

    def _append(self, line: str):
        stamp = datetime.now().strftime("%H:%M:%S")
        self.chat.insert("end", f"[{stamp}] {line}\n")
        self.chat.see("end")

    def send_alice_to_bob(self):
        text = self.message_entry.get().strip()
        if not text:
            return
        self._submit(self.alice.send_text("bob", text)).result(timeout=10)
        self._append(f"alice -> bob: {text}")
        self.message_entry.delete(0, "end")

    def send_bob_to_alice(self):
        text = self.reply_entry.get().strip()
        if not text:
            return
        self._submit(self.bob.send_text("alice", text)).result(timeout=10)
        self._append(f"bob -> alice: {text}")
        self.reply_entry.delete(0, "end")

    def send_demo_file(self):
        content = b"Aegis-PQ demo artifact: confidential payload over relay blob channel"
        self._submit(self.alice.send_file("bob", "demo.txt", content)).result(timeout=10)
        self._append("alice -> bob: sent demo.txt")

    def _render_events(self, owner: str, events: list[dict]):
        for ev in events:
            if ev["type"] == "text":
                self._append(f"{owner} received text from {ev['from']}: {ev['text']}")
            elif ev["type"] == "file":
                self._append(f"{owner} received file from {ev['from']}: {ev['filename']} ({len(ev['content'])} bytes)")
            else:
                self._append(f"{owner} event: {ev}")

    def poll_both(self):
        bob_events = self._submit(self.bob.poll()).result(timeout=10)
        alice_events = self._submit(self.alice.poll()).result(timeout=10)
        self._render_events("bob", bob_events)
        self._render_events("alice", alice_events)


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
