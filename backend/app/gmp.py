"""A small client for the Greenbone Management Protocol (GMP).

GMP is the XML protocol that gvmd, the OpenVAS manager, speaks. The dashboard uses a
handful of its commands to read tasks and reports and to create and start scans. This
module only moves XML; openvas.py decides what to ask for.

Security notes:
- gvmd is reached through its Unix socket, which Docker shares between the two
  containers through a volume. It is never exposed on a network port.
- Commands are built with ElementTree, so values typed into the dashboard (a scan name,
  a host list) are escaped and cannot add elements of their own.
- Replies are read with defusedxml (no DTDs, no entities) and capped in size. The end
  of a reply is found with an incremental parser rather than by trusting its length.
- The GMP password stays in this process. It is never logged or sent to the browser.
"""

import socket
from xml.etree.ElementTree import Element, SubElement, tostring  # noqa: S405 - builds only
from xml.sax import SAXException
from xml.sax.handler import ContentHandler

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from defusedxml.expatreader import DefusedExpatParser

READ_CHUNK = 64 * 1024


class GmpError(RuntimeError):
    """gvmd could not be reached or did not do what was asked."""


class GmpConnectionError(GmpError):
    """The socket is missing, refused the connection or timed out."""


class GmpAuthError(GmpError):
    """The user name or password was rejected."""


class GmpCommandError(GmpError):
    """gvmd answered with an error status."""

    def __init__(self, command: str, status: str, text: str) -> None:
        super().__init__(f"OpenVAS refused {command}: {text or 'no reason given'} ({status}).")
        self.status = status
        self.text = text


def element(tag: str, attrs: dict[str, str] | None = None, text: str | None = None) -> Element:
    node = Element(tag, {k: v for k, v in (attrs or {}).items() if v is not None})
    if text is not None:
        node.text = text
    return node


def child(parent: Element, tag: str, attrs: dict[str, str] | None = None, text: str | None = None):
    node = SubElement(parent, tag, {k: v for k, v in (attrs or {}).items() if v is not None})
    if text is not None:
        node.text = text
    return node


class _EndOfReply(ContentHandler):
    """Counts open elements so the reader knows when the reply's root has closed."""

    def __init__(self) -> None:
        super().__init__()
        self.depth = 0
        self.done = False

    def startElement(self, name, attrs):  # noqa: N802 - SAX interface
        self.depth += 1

    def endElement(self, name):  # noqa: N802 - SAX interface
        self.depth -= 1
        if self.depth == 0:
            self.done = True


class GmpConnection:
    """One authenticated conversation with gvmd over its Unix socket."""

    def __init__(self, socket_path: str, *, timeout: float = 60.0, max_reply_bytes: int) -> None:
        self.socket_path = socket_path
        self.timeout = timeout
        self.max_reply_bytes = max_reply_bytes
        self._sock: socket.socket | None = None

    def __enter__(self) -> "GmpConnection":
        if self._sock is None:
            self.open()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def open(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
        except FileNotFoundError as exc:
            sock.close()
            raise GmpConnectionError("The OpenVAS manager socket does not exist yet.") from exc
        except OSError as exc:
            sock.close()
            raise GmpConnectionError(f"Could not connect to the OpenVAS manager: {exc}") from exc
        self._sock = sock

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def exchange(self, command: Element) -> bytes:
        """Send one command and return the raw reply."""
        if self._sock is None:
            raise GmpConnectionError("Not connected to the OpenVAS manager.")
        try:
            self._sock.sendall(tostring(command, encoding="utf-8", xml_declaration=False))
        except OSError as exc:
            raise GmpConnectionError(f"Lost the connection to OpenVAS: {exc}") from exc

        detector = _EndOfReply()
        parser = DefusedExpatParser(forbid_dtd=True, forbid_entities=True, forbid_external=True)
        parser.setContentHandler(detector)
        chunks: list[bytes] = []
        size = 0
        while not detector.done:
            try:
                chunk = self._sock.recv(READ_CHUNK)
            except TimeoutError as exc:
                raise GmpConnectionError("OpenVAS did not answer in time.") from exc
            except OSError as exc:
                raise GmpConnectionError(f"Lost the connection to OpenVAS: {exc}") from exc
            if not chunk:
                raise GmpConnectionError("OpenVAS closed the connection mid-reply.")
            size += len(chunk)
            if size > self.max_reply_bytes:
                raise GmpError("The OpenVAS reply is larger than the configured limit.")
            chunks.append(chunk)
            try:
                parser.feed(chunk)
                if not detector.done and hasattr(parser, "flush"):
                    # Expat 2.6+ may hold back the last token until more data arrives
                    # ("reparse deferral"). gvmd sends nothing after a reply, so ask
                    # for it now or the end of the reply could go unnoticed.
                    parser.flush()
            except (SAXException, DefusedXmlException) as exc:
                raise GmpError(f"OpenVAS sent a reply that is not acceptable XML: {exc}") from exc
        return b"".join(chunks)

    def request(self, command: Element) -> Element:
        """Send one command, check its status and return the parsed reply."""
        raw = self.exchange(command)
        try:
            reply = SafeET.fromstring(raw, forbid_dtd=True)
        except Exception as exc:  # defusedxml and expat raise several types
            raise GmpError("OpenVAS sent a reply that could not be read.") from exc
        check_status(command.tag, reply)
        return reply

    def authenticate(self, username: str, password: str) -> None:
        command = element("authenticate")
        credentials = child(command, "credentials")
        child(credentials, "username", text=username)
        child(credentials, "password", text=password)
        try:
            self.request(command)
        except GmpCommandError as exc:
            raise GmpAuthError(
                "OpenVAS rejected the user name or password set in OPENVAS_USERNAME and "
                "OPENVAS_PASSWORD."
            ) from exc


def check_status(command: str, reply: Element) -> None:
    status = reply.get("status", "")
    if not status.startswith("2"):
        text = (reply.get("status_text") or "")[:200]
        raise GmpCommandError(command, status or "no status", text)
