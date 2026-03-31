import asyncio
import threading
from collections.abc import Callable
from concurrent.futures import Future
from datetime import datetime
from pathlib import Path
import time
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
        self.geometry("1200x760")
        ctk.set_appearance_mode("dark")

        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()

        self.client: AegisClient | None = None
        self.peer_id: str | None = None
        self.connected = False
        self.connecting = False
        self.poll_inflight = False
        self.initiate_inflight = False
        self.last_initiate_attempt = 0.0
        self.last_poll_error: str | None = None
        self.last_initiate_error: str | None = None
        self._append_count = 0

        # Main container
        self.container = ctk.CTkFrame(self)
        self.container.pack(fill="both", expand=True, padx=10, pady=10)

        # Header
        self.header_frame = ctk.CTkFrame(self.container)
        self.header_frame.pack(fill="x", padx=5, pady=5)
        
        self.header = ctk.CTkLabel(self.header_frame, text="Aegis-PQ Real Client Mode", font=("Segoe UI", 24, "bold"))
        self.header.pack(side="left", padx=10, pady=10)

        self.theme_switch = ctk.CTkSwitch(self.header_frame, text="Light/Dark", command=self.toggle_theme)
        self.theme_switch.pack(side="right", padx=10, pady=10)

        # Config frame
        self.cfg_frame = ctk.CTkFrame(self.container)
        self.cfg_frame.pack(fill="x", padx=5, pady=5)

        self.create_config_widgets(self.cfg_frame)

        # Main content frame
        self.main_content_frame = ctk.CTkFrame(self.container)
        self.main_content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.main_content_frame.grid_columnconfigure(0, weight=1)
        self.main_content_frame.grid_columnconfigure(1, weight=1)
        self.main_content_frame.grid_rowconfigure(0, weight=1)

        # System logs
        self.logs_frame = ctk.CTkFrame(self.main_content_frame)
        self.logs_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.logs_frame.grid_columnconfigure(0, weight=1)
        self.logs_frame.grid_rowconfigure(1, weight=1)
        
        self.logs_label = ctk.CTkLabel(self.logs_frame, text="SYSTEM LOGS & STATUS", font=("Segoe UI", 14, "bold"))
        self.logs_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        self.chat = ctk.CTkTextbox(self.logs_frame, width=450)
        self.chat.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)

        # Messages
        self.messages_frame = ctk.CTkFrame(self.main_content_frame)
        self.messages_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        self.messages_frame.grid_columnconfigure(0, weight=1)
        self.messages_frame.grid_rowconfigure(1, weight=1)

        self.messages_label = ctk.CTkLabel(self.messages_frame, text="MESSAGES", font=("Segoe UI", 14, "bold"))
        self.messages_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        self.messages_display = ctk.CTkTextbox(self.messages_frame, width=450)
        self.messages_display.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)

        # Message input
        self.input_frame = ctk.CTkFrame(self.messages_frame)
        self.input_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=10)
        self.input_frame.grid_columnconfigure(0, weight=1)

        self.message_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Type a message... (Press Enter to Send)")
        self.message_entry.grid(row=0, column=0, sticky="ew", padx=(10,5), pady=10)
        self.message_entry.bind("<Return>", self.send_message)

        self.send_button = ctk.CTkButton(self.input_frame, text="Send", command=self.send_message)
        self.send_button.grid(row=0, column=1, padx=5, pady=10)

        self.file_button = ctk.CTkButton(self.input_frame, text="Send File", command=self.send_file)
        self.file_button.grid(row=0, column=2, padx=5, pady=10)

        self.poll_button = ctk.CTkButton(self.input_frame, text="Poll", command=self.poll_once)
        self.poll_button.grid(row=0, column=3, padx=(5,10), pady=10)

        self.after(2000, self._poll_tick)

    def create_config_widgets(self, parent):
        # Your ID
        self.user_id_frame = ctk.CTkFrame(parent)
        self.user_id_frame.pack(side="left", padx=5, pady=5, fill="x", expand=True)
        self.user_id_label = ctk.CTkLabel(self.user_id_frame, text="Your ID")
        self.user_id_label.pack(padx=5, pady=2, anchor="w")
        self.user_entry = ctk.CTkEntry(self.user_id_frame, placeholder_text="user_id (alice)")
        self.user_entry.insert(0, "alice")
        self.user_entry.pack(padx=5, pady=2, fill="x")

        # Peer ID
        self.peer_id_frame = ctk.CTkFrame(parent)
        self.peer_id_frame.pack(side="left", padx=5, pady=5, fill="x", expand=True)
        self.peer_id_label = ctk.CTkLabel(self.peer_id_frame, text="Peer ID")
        self.peer_id_label.pack(padx=5, pady=2, anchor="w")
        self.peer_entry = ctk.CTkEntry(self.peer_id_frame, placeholder_text="peer_id (bob)")
        self.peer_entry.insert(0, "bob")
        self.peer_entry.pack(padx=5, pady=2, fill="x")

        # Relay IP
        self.relay_ip_frame = ctk.CTkFrame(parent)
        self.relay_ip_frame.pack(side="left", padx=5, pady=5, fill="x", expand=True)
        self.relay_ip_label = ctk.CTkLabel(self.relay_ip_frame, text="Relay IP")
        self.relay_ip_label.pack(padx=5, pady=2, anchor="w")
        self.host_entry = ctk.CTkEntry(self.relay_ip_frame, placeholder_text="relay_host")
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.pack(padx=5, pady=2, fill="x")

        # QUIC Port
        self.quic_port_frame = ctk.CTkFrame(parent)
        self.quic_port_frame.pack(side="left", padx=5, pady=5, fill="x", expand=True)
        self.quic_port_label = ctk.CTkLabel(self.quic_port_frame, text="QUIC Port")
        self.quic_port_label.pack(padx=5, pady=2, anchor="w")
        self.quic_port_entry = ctk.CTkEntry(self.quic_port_frame, placeholder_text="quic")
        self.quic_port_entry.insert(0, "8889")
        self.quic_port_entry.pack(padx=5, pady=2, fill="x")

        # TCP Port
        self.tcp_port_frame = ctk.CTkFrame(parent)
        self.tcp_port_frame.pack(side="left", padx=5, pady=5, fill="x", expand=True)
        self.tcp_port_label = ctk.CTkLabel(self.tcp_port_frame, text="TCP Port")
        self.tcp_port_label.pack(padx=5, pady=2, anchor="w")
        self.tcp_port_entry = ctk.CTkEntry(self.tcp_port_frame, placeholder_text="tcp")
        self.tcp_port_entry.insert(0, "8888")
        self.tcp_port_entry.pack(padx=5, pady=2, fill="x")

        # Auth Token
        self.auth_token_frame = ctk.CTkFrame(parent)
        self.auth_token_frame.pack(side="left", padx=5, pady=5, fill="x", expand=True)
        self.auth_token_label = ctk.CTkLabel(self.auth_token_frame, text="Auth Token")
        self.auth_token_label.pack(padx=5, pady=2, anchor="w")
        self.token_entry = ctk.CTkEntry(self.auth_token_frame, placeholder_text="auth_token")
        self.token_entry.insert(0, DEFAULT_CONFIG.relay.auth_token)
        self.token_entry.pack(padx=5, pady=2, fill="x")

        # Transport
        self.transport_frame = ctk.CTkFrame(parent)
        self.transport_frame.pack(side="left", padx=5, pady=5, fill="x", expand=True)
        self.transport_label = ctk.CTkLabel(self.transport_frame, text="Transport")
        self.transport_label.pack(padx=5, pady=2, anchor="w")
        self.transport_menu = ctk.CTkOptionMenu(self.transport_frame, values=["quic", "tcp"])
        self.transport_menu.set("quic")
        self.transport_menu.pack(padx=5, pady=2, fill="x")

        # Connect Button
        self.connect_button = ctk.CTkButton(parent, text="Connect", command=self.connect_client)
        self.connect_button.pack(side="left", padx=10, pady=10, fill="x")

    def toggle_theme(self):
        if self.theme_switch.get() == 1:
            ctk.set_appearance_mode("light")
        else:
            ctk.set_appearance_mode("dark")

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def _submit(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def _append(self, line: str):
        stamp = datetime.now().strftime("%H:%M:%S")
        self.chat.insert("end", f"[{stamp}] {line}\n")
        self.chat.see("end")
        self._append_count += 1
        if self._append_count % 50 == 0:
            total_lines = int(float(self.chat.index("end-1c").split(".")[0]))
            if total_lines > 900:
                self.chat.delete("1.0", "300.0")

    def _append_threadsafe(self, line: str):
        self.after(0, lambda: self._append(line))

    def _dispatch_success(self, cb: Callable[[object], None], result: object):
        cb(result)

    def _dispatch_error(self, cb: Callable[[Exception], None], exc: Exception):
        cb(exc)

    def _run_async(
        self,
        coro,
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ):
        fut = self._submit(coro)
        success_cb = on_success
        error_cb = on_error

        def _done(done_fut: Future):
            try:
                result = done_fut.result()
                if success_cb is not None:
                    self.after(0, self._dispatch_success, success_cb, result)
            except Exception as exc:
                if error_cb is not None:
                    self.after(0, self._dispatch_error, error_cb, exc)
                else:
                    self._append_threadsafe(f"[error] {exc}")

        fut.add_done_callback(_done)

    def _on_connect_done(self, fut: Future):
        self.connecting = False
        self.after(0, lambda: self.connect_button.configure(state="normal", text="Connect"))
        try:
            fut.result()
            self.connected = True
            self._append_threadsafe("[system] connected")
        except Exception as exc:
            self.connected = False
            self._append_threadsafe(f"[connect] failed: {exc}")

    def connect_client(self):
        if self.connecting:
            return
        user_id = self.user_entry.get().strip()
        peer_id = self.peer_entry.get().strip()
        host = self.host_entry.get().strip()
        quic_port = int(self.quic_port_entry.get().strip())
        tcp_port = int(self.tcp_port_entry.get().strip())
        token = self.token_entry.get().strip()
        transport = self.transport_menu.get().strip()
        self.peer_id = peer_id
        self.connected = False
        self.connecting = True
        self.connect_button.configure(state="disabled", text="Connecting...")

        relay = RelayClient(host=host, port=tcp_port, quic_port=quic_port, auth_token=token, transport=transport)
        local_root = Path("client-data") / user_id
        self.client = AegisClient(
            user_id,
            relay,
            BlobStore(str(local_root / "blobs")),
            DEFAULT_CONFIG,
            keystore=LocalKeyStore(str(local_root / "keystore")),
        )
        self._append(f"[connect] {user_id} -> {host} quic:{quic_port} tcp:{tcp_port} transport:{transport}")
        fut = self._submit(self._bootstrap())
        fut.add_done_callback(self._on_connect_done)

        if user_id.lower() == "alice":
            self._append("[guide] This laptop is alice. On other laptop use user_id=bob and peer_id=alice.")
        elif user_id.lower() == "bob":
            self._append("[guide] This laptop is bob. On other laptop use user_id=alice and peer_id=bob.")

    async def _bootstrap(self):
        assert self.client is not None
        await asyncio.wait_for(self.client.bootstrap(), timeout=12)
        await asyncio.wait_for(self.client.publish_prekey_bundle(), timeout=12)
        profile = self.client.crypto_profile()
        self._append_threadsafe(
            f"[security] KEM runtime={profile['kem_runtime']} | SIG runtime={profile['signature_runtime']} | pq_enabled={profile['pq_enabled']}"
        )
        self._append_threadsafe(
            f"[security] oqs_reason={profile['oqs_reason']} | module={profile['oqs_module_name']}"
        )
        if profile.get("oqs_module_file"):
            self._append_threadsafe(f"[security] oqs_module_file={profile['oqs_module_file']}")
        if profile.get("identity_reset_reason"):
            self._append_threadsafe(f"[security] identity reset: {profile['identity_reset_reason']}")
        if self.peer_id:
            try:
                await asyncio.wait_for(self.client.initiate_session(self.peer_id), timeout=12)
                self._append_threadsafe(f"[session] initiated with {self.peer_id}")
            except Exception as exc:
                self._append_threadsafe(f"[session] initiate deferred: {exc}")

    def _render_events(self, events: list[dict]):
        for ev in events:
            if ev.get("type") == "text":
                self._append(f"recv text from {ev['from']}: {ev['text']}")
                self.messages_display.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {ev['from']}: {ev['text']}\n")
            elif ev.get("type") == "file":
                out = Path("received")
                out.mkdir(parents=True, exist_ok=True)
                path = out / ev["filename"]
                path.write_bytes(ev["content"])
                self._append(f"recv file from {ev['from']}: {path}")
                self.messages_display.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {ev['from']}: received file {path}\n")
            elif ev.get("type") == "handshake":
                self._append(f"[session] handshake from {ev['from']}")
            else:
                self._append(f"event: {ev}")

    def send_message(self, event=None):
        if not self.client or not self.peer_id:
            return
        text = self.message_entry.get().strip()
        if not text:
            return
        self.send_button.configure(state="disabled")

        def _ok(_):
            self._append(f"sent to {self.peer_id}: {text}")
            self.messages_display.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] you: {text}\n")
            self.message_entry.delete(0, "end")
            self.send_button.configure(state="normal")

        def _err(exc):
            self._append(f"[send] {exc}")
            self.send_button.configure(state="normal")

        self._run_async(self.client.send_text(self.peer_id, text), on_success=_ok, on_error=_err)

    def send_file(self):
        if not self.client or not self.peer_id:
            return
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        payload = Path(file_path).read_bytes()
        self.file_button.configure(state="disabled")

        def _ok(_):
            self._append(f"sent file to {self.peer_id}: {file_path}")
            self.file_button.configure(state="normal")

        def _err(exc):
            self._append(f"[send-file] {exc}")
            self.file_button.configure(state="normal")

        self._run_async(self.client.send_file(self.peer_id, Path(file_path).name, payload), on_success=_ok, on_error=_err)

    def _start_poll(self):
        if not self.client or not self.connected or self.connecting or self.poll_inflight:
            return

        # Recover automatically when initial handshake failed due stale/missing peer bundle.
        if self.peer_id and not self.client.has_session(self.peer_id):
            now = time.time()
            if (not self.initiate_inflight) and (now - self.last_initiate_attempt > 5.0):
                self.initiate_inflight = True
                self.last_initiate_attempt = now

                def _init_ok(_):
                    self.initiate_inflight = False
                    self.last_initiate_error = None
                    self._append(f"[session] initiated with {self.peer_id}")

                def _init_err(exc):
                    self.initiate_inflight = False
                    msg = str(exc)
                    if msg != self.last_initiate_error:
                        self._append(f"[session] retry pending: {msg}")
                        self.last_initiate_error = msg

                self._run_async(self.client.initiate_session(self.peer_id), on_success=_init_ok, on_error=_init_err)

        self.poll_inflight = True

        def _ok(events):
            self.poll_inflight = False
            self.last_poll_error = None
            self._render_events(events)

        def _err(exc):
            self.poll_inflight = False
            msg = str(exc)
            if msg != self.last_poll_error:
                self._append(f"[poll] {msg}")
                self.last_poll_error = msg

        self._run_async(self.client.poll(), on_success=_ok, on_error=_err)

    def poll_once(self):
        self._start_poll()

    def _poll_tick(self):
        self._start_poll()
        self.after(2000, self._poll_tick)


def main():
    app = ClientApp()
    app.mainloop()


if __name__ == "__main__":
    main()
