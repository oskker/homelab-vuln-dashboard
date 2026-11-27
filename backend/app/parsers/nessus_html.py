"""Parser for Nessus HTML reports built with the "Detailed Vulnerabilities By Host" template.

Nessus Essentials and Essentials Plus cannot export .nessus files, but they can generate
HTML reports. The detailed-by-host template carries what the dashboard needs: hosts,
ports, severity, CVSS, CVEs, synopsis, description, solution and scanner output. It does
not include the exploit-available flag or the plugin family, so those stay empty.

Security notes:
- The report is untrusted input. It is read with the standard library's html.parser,
  which only tokenises: no scripts run, nothing is fetched, and HTML has no
  entity-expansion feature to abuse the way XML does.
- Only text is kept. Markup, styles, scripts and embedded images are dropped.
- The file is decoded and parsed in chunks, and every text buffer is capped.
"""

import codecs
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import BinaryIO

from .base import ParsedFinding, ParsedHost, ParsedScan, ScanParseError
from .nessus import MAX_CVES_PER_FINDING, MAX_NAME, MAX_SHORT, MAX_TEXT, _clip, _parse_time

CHUNK_BYTES = 256 * 1024
MAX_BUFFER = MAX_TEXT * 2

# Nessus colours each finding's title bar by severity.
SEVERITY_BY_COLOUR = {"#91243e": 4, "#dd4b50": 3, "#f18c43": 2, "#f8c851": 1, "#67ace1": 0}
# Fallback when the colour is missing. Risk Factor follows CVSS v2, so it can differ.
SEVERITY_BY_RISK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

SECTION_ID = re.compile(r"^id\d+$")
BACKGROUND = re.compile(r"background:\s*(#[0-9a-f]{6})", re.IGNORECASE)
PLUGIN_TITLE = re.compile(r"^(?P<id>\d+)\s+-\s+(?P<name>.+)$", re.DOTALL)
PORT_LABEL = re.compile(r"^(?P<proto>[a-z0-9]+)/(?P<port>\d+)(?:/(?P<service>\S+))?$", re.I)
CVSS_TEXT = re.compile(r"^\s*(?P<score>\d+(?:\.\d+)?)\s*(?:\((?P<vector>[^)]*)\))?")
CVE_IN_TEXT = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

BY_HOST_HEADING = "vulnerabilities by host"
OUTPUT_LABEL = "Plugin Output"
HOST_LABELS = {"Scan Information", "Host Information"}

WRONG_TEMPLATE_SUMMARY = (
    "This is the 'Complete List of Vulnerabilities by Host' report, which leaves out ports "
    "and CVEs. In Nessus, choose Report, then the 'Detailed Vulnerabilities By Host' template."
)
WRONG_TEMPLATE_BY_PLUGIN = (
    "This report is grouped by plugin. In Nessus, choose Report, then the "
    "'Detailed Vulnerabilities By Host' template."
)
NOT_A_REPORT = (
    "This HTML file is not a Nessus report. In Nessus, open the scan, choose Report, "
    "then the 'Detailed Vulnerabilities By Host' template."
)


class _Capture:
    """Collects text inside one element, plus table cells when the element holds a table."""

    __slots__ = ("kind", "depth", "parts", "size", "rows", "row", "cell")

    def __init__(self, kind: str, depth: int) -> None:
        self.kind = kind
        self.depth = depth
        self.parts: list[str] = []
        self.size = 0
        self.rows: list[list[str]] = []
        self.row: list[str] | None = None
        self.cell: list[str] | None = None

    def add(self, text: str) -> None:
        room = MAX_BUFFER - self.size
        if room <= 0:
            return
        text = text[:room]
        self.size += len(text)
        self.parts.append(text)
        if self.cell is not None:
            self.cell.append(text)

    def text(self) -> str:
        lines = "".join(self.parts).split("\n")
        return "\n".join(line.rstrip() for line in lines).strip()


@dataclass
class _Plugin:
    severity_from_colour: int | None
    plugin_id: str = ""
    name: str = ""
    fields: dict[str, str] = field(default_factory=dict)
    ports: list[tuple[str, list[str]]] = field(default_factory=list)


@dataclass
class _Host:
    title: str = ""
    info: dict[str, str] = field(default_factory=dict)
    findings: list[ParsedFinding] = field(default_factory=list)


def _cvss(text: str | None) -> tuple[float | None, str]:
    match = CVSS_TEXT.match(text or "")
    if not match:
        return None, ""
    score = float(match.group("score"))
    if not 0.0 <= score <= 10.0:
        return None, ""
    return score, (match.group("vector") or "").strip()


def _port(label: str) -> tuple[int, str, str]:
    match = PORT_LABEL.match(label.strip())
    if not match:
        return 0, "", ""
    port = min(65535, int(match.group("port")))
    return port, match.group("proto").lower(), _clip(match.group("service"), 64)


def _cves(text: str) -> list[str]:
    found: list[str] = []
    for match in CVE_IN_TEXT.finditer(text):
        cve = match.group(0).upper()
        if cve not in found:
            found.append(cve)
        if len(found) >= MAX_CVES_PER_FINDING:
            break
    return found


class _ReportReader(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scan = ParsedScan(source="nessus")
        self.div_depth = 0
        self.capture: _Capture | None = None  # div-based capture
        self.heading: _Capture | None = None  # h2, h3 or h6 text
        self.heading_tag = ""
        self.label: str | None = None  # the most recent section label
        self.awaiting_content = False
        self.host: _Host | None = None
        self.plugin: _Plugin | None = None
        self.saw_by_host_heading = False
        self.saw_other_heading = False
        self.saw_summary_rows = False
        self.plugin_sections = 0

    # ----- tokens -----

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "div":
            self.div_depth += 1
            self._open_div({k: v or "" for k, v in attrs})
        elif tag == "br":
            target = self.heading or self.capture
            if target is not None:
                target.add("\n")
        elif tag in ("h2", "h3", "h6") and self.heading is None:
            self.heading = _Capture(tag, self.div_depth)
            self.heading_tag = tag
        elif tag == "tr":
            if "plugin-row" in (dict(attrs).get("class") or ""):
                self.saw_summary_rows = True
            if self.capture is not None and self.capture.kind == "content":
                self.capture.row = []
        elif tag in ("td", "th") and self.capture is not None and self.capture.row is not None:
            self.capture.cell = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "div":
            if self.capture is not None and self.div_depth == self.capture.depth:
                self._close_capture()
            self.div_depth -= 1
        elif tag == self.heading_tag and self.heading is not None:
            self._close_heading()
        elif tag in ("td", "th") and self.capture is not None and self.capture.cell is not None:
            if self.capture.row is not None:
                self.capture.row.append(" ".join("".join(self.capture.cell).split()))
            self.capture.cell = None
        elif tag == "tr" and self.capture is not None and self.capture.row is not None:
            self.capture.rows.append(self.capture.row)
            self.capture.row = None

    def handle_data(self, data: str) -> None:
        # Real line breaks arrive as <br>; newlines in the source are only formatting.
        text = data.replace("\r", " ").replace("\n", " ")
        if self.heading is not None:
            self.heading.add(text)
            return
        capture = self.capture
        if capture is None:
            return
        if capture.kind in ("host_title", "plugin_title") and self.div_depth != capture.depth:
            return  # skip the "-" toggle marker nested inside the title bar
        capture.add(text)

    # ----- structure -----

    def _open_div(self, attrs: dict[str, str]) -> None:
        if self.capture is not None:
            return  # a nested div (usually <div class="clear">) inside an active capture
        element_id = attrs.get("id", "")
        style = attrs.get("style", "")

        if attrs.get("class") == "details-header":
            self.capture = _Capture("label", self.div_depth)
            return
        if attrs.get("onclick", "").startswith("toggleSection(") and SECTION_ID.match(element_id):
            self._finish_plugin()
            self.label, self.awaiting_content = None, False
            colour = BACKGROUND.search(style)
            self.plugin = _Plugin(
                severity_from_colour=SEVERITY_BY_COLOUR.get(colour.group(1).lower())
                if colour
                else None
            )
            self.plugin_sections += 1
            self.capture = _Capture("plugin_title", self.div_depth)
            return
        if SECTION_ID.match(element_id) and "font-size: 22px" in style:
            self._finish_host()
            self.label, self.awaiting_content = None, False
            self.host = _Host()
            self.capture = _Capture("host_title", self.div_depth)
            return
        if self.awaiting_content:
            self.awaiting_content = False
            self.capture = _Capture("content", self.div_depth)
            return
        if (
            self.label == OUTPUT_LABEL
            and self.plugin is not None
            and self.plugin.ports
            and "monospace" in style
        ):
            self.capture = _Capture("output", self.div_depth)

    def _close_capture(self) -> None:
        capture, self.capture = self.capture, None
        if capture is None:
            return
        text = capture.text()
        if capture.kind == "label":
            self.label = text
            self.awaiting_content = text not in (OUTPUT_LABEL, "Vulnerabilities")
        elif capture.kind == "host_title" and self.host is not None:
            self.host.title = text
        elif capture.kind == "plugin_title" and self.plugin is not None:
            match = PLUGIN_TITLE.match(text)
            if match:
                self.plugin.plugin_id = match.group("id")
                self.plugin.name = match.group("name").strip()
        elif capture.kind == "content" and self.label:
            if self.label in HOST_LABELS and self.host is not None:
                for row in capture.rows:
                    if len(row) >= 2 and row[0]:
                        self.host.info[row[0].rstrip(":").strip()] = row[1]
            elif self.plugin is not None:
                self.plugin.fields[self.label] = text
        elif capture.kind == "output" and self.plugin is not None and self.plugin.ports:
            if text:
                self.plugin.ports[-1][1].append(text)

    def _close_heading(self) -> None:
        heading, self.heading, self.heading_tag = self.heading, None, ""
        if heading is None:
            return
        text = " ".join(heading.text().split())
        if heading.kind == "h3" and not self.scan.report_name:
            self.scan.report_name = _clip(text, MAX_SHORT)
        elif heading.kind == "h6" and text:
            if text.lower().startswith(BY_HOST_HEADING):
                self.saw_by_host_heading = True
            elif text.lower().startswith("vulnerabilities by"):
                self.saw_other_heading = True
        elif heading.kind == "h2" and self.label == OUTPUT_LABEL and self.plugin is not None:
            if PORT_LABEL.match(text):
                self.plugin.ports.append((text, []))

    def _finish_plugin(self) -> None:
        plugin, self.plugin = self.plugin, None
        if plugin is None or self.host is None or not plugin.plugin_id:
            return
        fields = plugin.fields
        severity = plugin.severity_from_colour
        if severity is None:
            severity = SEVERITY_BY_RISK.get(fields.get("Risk Factor", "").strip().lower(), 0)
        score, vector = _cvss(fields.get("CVSS v3.0 Base Score"))
        if score is None:
            score, vector = _cvss(fields.get("CVSS v2.0 Base Score"))
        cves = _cves(fields.get("References", ""))

        # One finding per port. A plugin can print several outputs for the same port.
        merged: dict[str, list[str]] = {}
        for label, outputs in plugin.ports:
            merged.setdefault(label, []).extend(outputs)
        if not merged:
            merged[""] = []

        for label, outputs in merged.items():
            port, protocol, service = _port(label)
            self.host.findings.append(
                ParsedFinding(
                    plugin_id=_clip(plugin.plugin_id, 64),
                    plugin_name=_clip(plugin.name, MAX_NAME),
                    severity=severity,
                    port=port,
                    protocol=protocol,
                    service=service,
                    cvss_base=score,
                    cvss_vector=_clip(vector, 128),
                    synopsis=_clip(fields.get("Synopsis"), MAX_TEXT),
                    description=_clip(fields.get("Description"), MAX_TEXT),
                    solution=_clip(fields.get("Solution"), MAX_TEXT),
                    plugin_output=_clip("\n\n".join(outputs), MAX_TEXT),
                    cves=list(cves),
                )
            )

    def _finish_host(self) -> None:
        self._finish_plugin()
        host, self.host = self.host, None
        if host is None:
            return
        info = host.info
        ip = _clip(info.get("IP") or host.title, 64)
        if not ip:
            return
        self.scan.hosts.append(
            ParsedHost(
                ip=ip,
                hostname=_clip(info.get("Netbios Name") or info.get("DNS Name"), MAX_SHORT),
                fqdn=_clip(info.get("DNS Name"), MAX_SHORT),
                os=_clip(info.get("OS"), MAX_SHORT),
                mac=_clip(info.get("MAC Address"), 64),
                scan_start=_parse_time(info.get("Start time")),
                scan_end=_parse_time(info.get("End time")),
                findings=host.findings,
            )
        )

    def finish(self) -> ParsedScan:
        self.close()
        self._finish_host()
        if self.saw_other_heading and not self.saw_by_host_heading:
            raise ScanParseError(WRONG_TEMPLATE_BY_PLUGIN)
        if not self.saw_by_host_heading:
            raise ScanParseError(NOT_A_REPORT)
        if self.plugin_sections == 0 and self.saw_summary_rows:
            raise ScanParseError(WRONG_TEMPLATE_SUMMARY)
        if not self.scan.hosts:
            raise ScanParseError("The report does not list any hosts.")
        return self.scan


class NessusHtmlParser:
    source = "nessus"

    @staticmethod
    def looks_like(head: bytes) -> bool:
        """True when the first bytes of a file look like HTML rather than XML."""
        lowered = head.removeprefix(codecs.BOM_UTF8).lstrip().lower()
        return lowered.startswith((b"<html", b"<!doctype html"))

    def parse(self, fileobj: BinaryIO) -> ParsedScan:
        reader = _ReportReader()
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        while chunk := fileobj.read(CHUNK_BYTES):
            reader.feed(decoder.decode(chunk))
        reader.feed(decoder.decode(b"", final=True))
        return reader.finish()
