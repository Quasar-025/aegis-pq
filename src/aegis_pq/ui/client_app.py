import asyncio
import threading
from datetime import datetime
from pathlib import Path
from tkinter import filedialog

from aegis_pq.config import DEFAULT_CONFIG
from aegis_pq.engine import AegisClient
from aegis_pq.network.relay_client import RelayClient
from aegis_pq.storage.blob_store import BlobStore
from aegis_pq.storage.keystore import LocalKeyStore

try:
    import customtkinter as ctk
except Exception:
    raise RuntimeError("customtkinter is required for UI. Install dependencies from requirements.txt")


class ClientApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Aegis-PQ Client")
        self.geometry("1100x760")
        ctk.set_appearance_mode("dark")

        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()

        self.client: AegisClient | None = None
        self.peer_id: str | None = None

        self.header = ctk.CTkLabel(self, text="Aegis-PQ Real Client Mode", font=("Segoe UI", 24, "bold"))
        self.header.pack(padx=20, pady=(18, 6))

        self.cfg = ctk.CTkFrame(self)
        self.cfg.pack(fill="x", padx=20, pady=8)

        self.user_entry = ctk.CTkEntry(self.cfg, width=130, placeholder_text="user_id (alice)")
        self.user_entry.insert(0, "alice")
        self.user_entry.pack(side="left", padx=6, pady=8)

        self.peer_entry = ctk.CTkEntry(self.cfg, width=130, placeholder_text="peer_id (bob)")
        self.peer_entry.insert(0, "bob")
        self.peer_entry.pack(side="left", padx=6, pady=8)

        self.host_entry = ctk.CTkEntry(self.cfg, width=200, placeholder_text="relay_host")
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.pack(side="left", padx=6, pady=8)

        self.quic_port_entry = ctk.CTkEntry(self.cfg, width=90, placeholder_text="quic")
        self.quic_port_entry.insert(0, "8889")
        self.quic_port_entry.pack(side="left", padx=6, pady=8)

        self.tcp_port_entry = ctk.CTkEntry(self.cfg, width=90, placeholder_text="tcp")
        self.tcp_port_entry.insert(0, "8888")
        self.tcp_port_entry.pack(side="left", padx=6, pady=8)

        self.token_entry = ctk.CTkEntry(self.cfg, width=220, placeholder_text="auth_token")
        self.token_entry.insert(0, DEFAULT_CONFIG.relay.auth_token)
        self.token_entry.pack(side="left", padx=6, pady=8)

        self.transport_menu = ctk.CTkOptionMenu(self.cfg, values=["quic", "tcp"])
        self.transport_menu.set("quic")
        self.transport_menu.pack(side="left", padx=6, pady=8)

        self.connect_button = ctk.CTkButton(self.cfg, text="Connect", command=self.connect_client)
        self.connect_button.pack(side="left", padx=6, pady=8)

        self.chat = ctk.CTkTextbox(self, width=1040, height=440)
        self.chat.pack(padx=20, pady=12)

        self.row = ctk.CTkFrame(self)
        self.row.pack(fill="x", padx=20, pady=10)

        self.message_entry = ctk.CTkEntry(self.row, width=700, placeholder_text="Type secure message")
        self.message_entry.pack(side="left", padx=8, pady=8)

        self.send_button = ctk.CTkButton(self.row, text="Send", command=self.send_message)
        self.send_button.pack(side="left", padx=8, pady=8)

        self.file_button = ctk.CTkButton(self.row, text="Send File", command=self.send_file)
        self.file_button.pack(side="left", padx=8, pady=8)

        self.poll_button = ctk.CTkButton(self.row, text="Poll", command=self.poll_once)
        self.poll_button.pack(side="left", padx=8, pady=8)

        self.after(2000, self._poll_tick)

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def _submit(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def _append(self, line: str):
        stamp = datetime.now().strftime("%H:%M:%S")
        self.chat.insert("end", f"[{stamp}] {line}\n")
        self.chat.see("end")

    def connect_client(self):
        user_id = self.user_entry.get().strip()
        peer_id = self.peer_entry.get().strip()
        host = self.host_entry.get().strip()
        quic_port = int(self.quic_port_entry.get().strip())
        tcp_port = int(self.tcp_port_entry.get().strip())
        token = self.token_entry.get().strip()
        transport = self.transport_menu.get().strip()
        self.peer_id = peer_id

        relay = RelayClient(host=host, port=tcp_port, quic_port=quic_port, auth_token=token, transport=transport)
        local_root = Path("client-data") / user_id
        self.client = AegisClient(
            user_id,
            relay,
            BlobStore(str(local_root / "blobs")),
            DEFAULT_CONFIG,
            keystore=LocalKeyStore(str(local_root / "keystore")),
        )

        self._submit(self._bootstrap()).result(timeout=20)

    async def _bootstrap(self):
        assert self.client is not None
        await self.client.bootstrap()
        await self.client.publish_prekey_bundle()
        profile = self.client.crypto_profile()
        self._append(
            f"[security] KEM runtime={profile['kem_runtime']} | SIG runtime={profile['signature_runtime']} | pq_enabled={profile['pq_enabled']}"
        )
        if self.peer_id:
            try:
                await self.client.initiate_session(self.peer_id)
                self._append(f"[session] initiated with {self.peer_id}")
            except Exception as exc:
                self._append(f"[session] initiate deferred: {exc}")

    def _render_events(self, events: list[dict]):
        for ev in events:
            if ev.get("type") == "text":
                self._append(f"recv text from {ev['from']}: {ev['text']}")
            elif ev.get("type") == "file":
                out = Path("received")
                out.mkdir(parents=True, exist_ok=True)
                path = out / ev["filename"]
                path.write_bytes(ev["content"])
                self._append(f"recv file from {ev['from']}: {path}")
            elif ev.get("type") == "handshake":
                self._append(f"[session] handshake from {ev['from']}")
            else:
                self._append(f"event: {ev}")

    def send_message(self):
        if not self.client or not self.peer_id:
            return
        text = self.message_entry.get().strip()
        if not text:
            return
        self._submit(self.client.send_text(self.peer_id, text)).result(timeout=20)
        self._append(f"sent to {self.peer_id}: {text}")
        self.message_entry.delete(0, "end")

    def send_file(self):
        if not self.client or not self.peer_id:
            return
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        payload = Path(file_path).read_bytes()
        self._submit(self.client.send_file(self.peer_id, Path(file_path).name, payload)).result(timeout=30)
        self._append(f"sent file to {self.peer_id}: {file_path}")

    def poll_once(self):
        if not self.client:
            return
        events = self._submit(self.client.poll()).result(timeout=20)
        self._render_events(events)

    def _poll_tick(self):
        try:
            if self.client:
                events = self._submit(self.client.poll()).result(timeout=10)
                self._render_events(events)
        except Exception as exc:
            self._append(f"[poll] {exc}")
        finally:
            self.after(2000, self._poll_tick)


def main():
    app = ClientApp()
    app.mainloop()


if __name__ == "__main__":
    main()
