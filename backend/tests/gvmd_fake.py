"""A stand-in for gvmd: a Unix socket server that answers GMP commands from canned data.

It records every command it receives so tests can check exactly what the dashboard sent,
and it can split replies into tiny pieces to exercise the client's incremental reader.
"""

import socket
import threading
from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree as SafeET

from app.parsers.openvas import OpenVasParser

FULL_AND_FAST = "daba56c8-73ec-11df-a475-002264764cea"
OPENVAS_SCANNER = "08b69003-5fc2-4037-a479-93b440211c73"
ALL_IANA_TCP = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"


def ok(tag: str, body: str = "", status: str = "200", extra: str = "") -> bytes:
    return f'<{tag}_response status="{status}" status_text="OK"{extra}>{body}</{tag}_response>'.encode()


class FakeGvmd:
    def __init__(self, path, *, username="admin", password="secret", chunk=0):
        self.path = str(path)
        self.username = username
        self.password = password
        self.chunk = chunk  # reply in pieces of this many bytes (0 = all at once)
        self.commands: list = []
        self.reports: dict[str, dict] = {}
        self.tasks_xml = ""
        self.loading = False
        self.raw_reply: bytes | None = None  # send this instead of a normal reply, once
        self._ids = 0
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.path)
        self._server.listen(8)
        self._server.settimeout(0.2)
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    # ---------- test helpers ----------

    def add_report(self, path, *, status="Done", report_id=None, time="2026-11-01T10:00:00Z"):
        raw = path.read_bytes() if path is not None else b""
        if path is not None:
            parsed = OpenVasParser(min_qod=0).parse(path.open("rb"))
            report_id = report_id or parsed.external_id
            time = parsed.scan_end.strftime("%Y-%m-%dT%H:%M:%SZ")
        body = raw.split(b"?>", 1)[1] if raw.startswith(b"<?xml") else raw
        self.reports[report_id] = {"status": status, "time": time, "xml": body}
        return report_id

    def sent(self, tag: str) -> list:
        return [c for c in self.commands if c.tag == tag]

    def close(self):
        self._running = False
        self._thread.join(timeout=2)
        self._server.close()

    # ---------- server ----------

    def _serve(self):
        while self._running:
            try:
                conn, _ = self._server.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        buffer = b""
        authenticated = False
        with conn:
            while True:
                try:
                    data = conn.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                buffer += data
                try:
                    command = SafeET.fromstring(buffer)
                except ParseError:
                    continue  # not the whole command yet
                buffer = b""
                self.commands.append(command)
                if self.raw_reply is not None:
                    reply, self.raw_reply = self.raw_reply, None
                elif command.tag == "authenticate":
                    good = (
                        command.findtext("credentials/username") == self.username
                        and command.findtext("credentials/password") == self.password
                    )
                    authenticated = good
                    reply = ok("authenticate", "<role>Admin</role>") if good else (
                        b'<authenticate_response status="400" status_text="Authentication failed"/>'
                    )
                elif command.tag != "get_version" and not authenticated:
                    reply = f'<{command.tag}_response status="401" status_text="Authenticate first"/>'.encode()
                else:
                    reply = self._reply(command)
                self._send(conn, reply)

    def _send(self, conn, reply: bytes):
        try:
            if not self.chunk:
                conn.sendall(reply)
                return
            for start in range(0, len(reply), self.chunk):
                conn.sendall(reply[start : start + self.chunk])
        except OSError:
            pass  # the client hung up early, which some tests do on purpose

    def _new_id(self) -> str:
        self._ids += 1
        return f"00000000-0000-4000-8000-{self._ids:012d}"

    def _reply(self, command) -> bytes:
        tag = command.tag
        if tag == "get_version":
            return ok("get_version", "<version>22.8</version>")
        if tag == "get_feeds":
            syncing = "<currently_syncing><timestamp>now</timestamp></currently_syncing>" if self.loading else ""
            return ok("get_feeds", f"<feed><type>NVT</type><name>Community</name><version>1</version><description/>{syncing}</feed>")
        if tag == "get_configs":
            body = "" if self.loading else f'<config id="{FULL_AND_FAST}"><name>Full and fast</name></config>'
            return ok("get_configs", body)
        if tag == "get_scanners":
            return ok("get_scanners", f'<scanner id="{OPENVAS_SCANNER}"><name>OpenVAS Default</name><type>2</type></scanner>')
        if tag == "get_port_lists":
            return ok("get_port_lists", f'<port_list id="{ALL_IANA_TCP}"><name>All IANA assigned TCP</name></port_list>')
        if tag == "get_tasks":
            return ok("get_tasks", self.tasks_xml)
        if tag == "get_reports":
            report_id = command.get("report_id")
            if report_id:
                report = self.reports.get(report_id)
                if report is None:
                    return b'<get_reports_response status="404" status_text="Failed to find report"/>'
                return ok("get_reports", report["xml"].decode())
            listing = "".join(
                f'<report id="{rid}"><task id="t1"><name>Home network weekly</name></task>'
                f'<report id="{rid}"><scan_run_status>{r["status"]}</scan_run_status>'
                f'<scan_end>{r["time"]}</scan_end></report></report>'
                for rid, r in self.reports.items()
            )
            return ok("get_reports", listing)
        if tag in ("create_target", "create_schedule", "create_task"):
            return ok(tag, status="201", extra=f' id="{self._new_id()}"')
        if tag == "start_task":
            return ok("start_task", f"<report_id>{self._new_id()}</report_id>", status="202")
        return f'<{tag}_response status="400" status_text="Bogus command name"/>'.encode()
