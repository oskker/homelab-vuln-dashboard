"""Parser for OpenVAS (Greenbone Community Edition) reports in the XML report format.

Two shapes of the same data are accepted:
- A report downloaded from the Greenbone web interface with the "XML" report format.
  The root is <report>, which wraps an inner <report> holding the results.
- A <get_reports_response> fetched over the Greenbone Management Protocol (GMP), which
  is what the live sync receives.

How results become findings:
- Severity comes from the result's numeric score, using the CVSS bands (9.0 critical,
  7.0 high, 4.0 medium, above 0 low). Log entries, false positives (overridden to -1)
  and errors are not findings and are skipped.
- Results below the minimum quality of detection (QoD, default 70, the same default the
  Greenbone web interface uses) are skipped.
- A host listed without an end time was not finished by the scanner, and checks that
  errored are recorded per host. The importer uses both to avoid closing findings that
  were simply not re-checked.

Security notes (the same as the Nessus parser):
- Everything in a report is untrusted. Devices control their own banners and hostnames.
- Parsing goes through defusedxml with DTDs, entities and external references forbidden.
- The file is streamed; each result is released once read.
- Free-text fields are capped in length before they reach the database.
"""

import re
from datetime import UTC, datetime
from typing import BinaryIO
from xml.etree.ElementTree import Element, ParseError  # noqa: S405 - types only

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from .base import ParsedFinding, ParsedHost, ParsedScan, ScanParseError

SOURCE = "openvas"
ROOT_TAGS = {"report", "get_reports_response"}
FINISHED = "Done"
DEFAULT_MIN_QOD = 70
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
PORT_PATTERN = re.compile(r"^\s*(\d{1,5})/([A-Za-z0-9-]+)")
GENERAL_PORT_PATTERN = re.compile(r"^\s*general/([A-Za-z0-9-]+)")
ROOT_START = re.compile(rb"<(?:report|get_reports_response)[\s>/]")
SKIPPED_THREATS = {"log", "debug", "false positive", "error"}

MAX_SHORT = 255
MAX_NAME = 512
MAX_TEXT = 8000
MAX_CVES_PER_FINDING = 200
MAX_UNCHECKED_PER_HOST = 5000

# Labels for the parts of an NVT's description, in display order.
DESCRIPTION_PARTS = (
    ("insight", "Insight"),
    ("affected", "Affected"),
    ("impact", "Impact"),
    ("vuldetect", "How it was detected"),
)


def severity_level(score: float) -> int:
    """Map a 0-10 score to the dashboard's 1-4 scale (CVSS v3 qualitative bands)."""
    if score >= 9.0:
        return 4
    if score >= 7.0:
        return 3
    if score >= 4.0:
        return 2
    return 1


def _clip(value: str | None, limit: int) -> str:
    return (value or "").strip()[:limit]


def _to_float(value: str | None) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _to_int(value: str | None) -> int | None:
    try:
        return int(float(value))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def parse_time(text: str | None) -> datetime | None:
    """GMP times are ISO 8601 with a zone. They are stored as naive UTC."""
    if not text or not text.strip():
        return None
    try:
        moment = datetime.fromisoformat(text.strip())
    except ValueError:
        return None
    if moment.tzinfo is not None:
        moment = moment.astimezone(UTC).replace(tzinfo=None)
    return moment


def _port(text: str | None) -> tuple[int, str]:
    match = PORT_PATTERN.match(text or "")
    if match:
        return min(65535, int(match.group(1))), match.group(2).lower()[:16]
    general = GENERAL_PORT_PATTERN.match(text or "")
    if general:
        return 0, general.group(1).lower()[:16]
    return 0, ""


def tidy(text: str | None) -> str:
    """Undo the hard line wrapping in NVT texts while keeping paragraphs and list items."""
    paragraphs = []
    for block in re.split(r"\n\s*\n", (text or "").strip()):
        lines: list[str] = []
        for raw in block.split("\n"):
            line = " ".join(raw.split())
            if not line:
                continue
            if lines and not line.startswith(("- ", "* ")):
                lines[-1] = f"{lines[-1]} {line}"
            else:
                lines.append(line)
        if not lines:
            continue
        text_block = "\n".join(lines)
        if paragraphs and text_block.startswith(("- ", "* ")):
            paragraphs[-1] = f"{paragraphs[-1]}\n{text_block}"  # keep a list together
        else:
            paragraphs.append(text_block)
    return "\n\n".join(paragraphs)


def _tags(text: str | None) -> dict[str, str]:
    """NVT tags arrive as one string: key=value|key=value."""
    tags: dict[str, str] = {}
    for part in (text or "").split("|"):
        key, sep, value = part.partition("=")
        if sep and key.strip():
            tags[key.strip().lower()] = value.strip()
    return tags


def _cves(nvt: Element) -> list[str]:
    found: list[str] = []

    def add(candidate: str) -> None:
        cve = candidate.strip().upper()
        if CVE_PATTERN.match(cve) and cve not in found and len(found) < MAX_CVES_PER_FINDING:
            found.append(cve)

    refs = nvt.find("refs")
    if refs is not None:
        for ref in refs.findall("ref"):
            if (ref.get("type") or "").lower() == "cve":
                add(ref.get("id") or "")
    # Older GMP versions list CVEs as one comma-separated element.
    for part in (nvt.findtext("cve") or "").split(","):
        add(part)
    return found


def _cvss_vector(nvt: Element, tags: dict[str, str]) -> str:
    severities = nvt.find("severities")
    if severities is not None:
        for severity in severities.findall("severity"):
            value = severity.findtext("value")
            if value and value.strip():
                return _clip(value, 128)
    return _clip(tags.get("cvss_base_vector"), 128)


def _description(tags: dict[str, str]) -> str:
    parts = [
        f"{label}: {tidy(tags[key])}"
        for key, label in DESCRIPTION_PARTS
        if tags.get(key, "").strip()
    ]
    return _clip("\n\n".join(parts), MAX_TEXT)


class OpenVasParser:
    source = SOURCE

    def __init__(self, min_qod: int = DEFAULT_MIN_QOD) -> None:
        self.min_qod = min_qod

    @staticmethod
    def looks_like(head: bytes) -> bool:
        """True when the file starts like an OpenVAS XML report.

        Skips an XML declaration and any comments with plain string searches, so the
        check takes linear time whatever the file contains. (A single regular
        expression for this can backtrack exponentially on a crafted file.)
        """
        text = head.lstrip()
        if text.startswith(b"<?xml"):
            end = text.find(b"?>")
            if end == -1:
                return False
            text = text[end + 2 :].lstrip()
        while text.startswith(b"<!--"):
            end = text.find(b"-->", 4)
            if end == -1:
                return False
            text = text[end + 3 :].lstrip()
        return ROOT_START.match(text) is not None

    # ---------- One result ----------

    def _parse_result(self, result: Element) -> tuple[str, str, ParsedFinding] | None:
        """Return (ip, hostname, finding), or None for results that are not findings."""
        nvt = result.find("nvt")
        if nvt is None:
            return None
        oid = _clip(nvt.get("oid"), 64)
        threat = (result.findtext("threat") or "").strip().lower()
        score = _to_float(result.findtext("severity"))
        if score is None:
            score = _to_float(nvt.findtext("cvss_base"))
        if not oid or threat in SKIPPED_THREATS or score is None or score <= 0:
            return None
        score = min(score, 10.0)
        qod = _to_int(result.findtext("qod/value"))
        if qod is not None and qod < self.min_qod:
            return None

        host = result.find("host")
        ip = _clip(host.text if host is not None else "", 64)
        if not ip:
            return None
        hostname = _clip(host.findtext("hostname") if host is not None else "", MAX_SHORT)

        tags = _tags(nvt.findtext("tags"))
        port, protocol = _port(result.findtext("port"))
        name = nvt.findtext("name") or result.findtext("name")
        solution = nvt.findtext("solution") or tags.get("solution", "")
        finding = ParsedFinding(
            plugin_id=oid,
            plugin_name=_clip(name, MAX_NAME) or oid,
            plugin_family=_clip(nvt.findtext("family"), MAX_SHORT),
            severity=severity_level(score),
            port=port,
            protocol=protocol,
            # The score after any overrides set in Greenbone, so the ranking respects them.
            cvss_base=round(score, 1),
            cvss_vector=_cvss_vector(nvt, tags),
            qod=qod,
            synopsis=_clip(tidy(tags.get("summary")), MAX_TEXT),
            description=_description(tags),
            solution=_clip(tidy(solution), MAX_TEXT),
            plugin_output=_clip(result.findtext("description"), MAX_TEXT),
            cves=_cves(nvt),
        )
        return ip, hostname, finding

    # ---------- One host summary ----------

    @staticmethod
    def _parse_host_summary(element: Element) -> dict | None:
        ip = _clip(element.findtext("ip"), 64)
        if not ip:
            return None
        details: dict[str, str] = {}
        for detail in element.findall("detail"):
            name = (detail.findtext("name") or "").strip()
            if name and name not in details:
                details[name] = detail.findtext("value") or ""
        end_text = element.findtext("end")
        return {
            "ip": ip,
            "hostname": _clip(element.findtext("hostname") or details.get("hostname"), MAX_SHORT),
            "os": _clip(element.findtext("best_os_txt") or details.get("best_os_txt"), MAX_SHORT),
            "mac": _clip(details.get("MAC") or details.get("mac"), 64),
            "start": parse_time(element.findtext("start")),
            "end": parse_time(end_text),
            "complete": bool(end_text and end_text.strip()),
        }

    # ---------- The whole report ----------

    def parse(self, fileobj: BinaryIO) -> ParsedScan:
        scan = ParsedScan(source=self.source)
        stack: list[Element] = []
        outer: Element | None = None
        inner: Element | None = None
        status = ""
        hosts: dict[str, ParsedHost] = {}
        summaries: dict[str, dict] = {}
        unchecked: dict[str, set[str]] = {}
        saw_results = False

        def host_for(ip: str) -> ParsedHost:
            if ip not in hosts:
                hosts[ip] = ParsedHost(ip=ip)
            return hosts[ip]

        try:
            events = SafeET.iterparse(
                fileobj,
                events=("start", "end"),
                forbid_dtd=True,
                forbid_entities=True,
                forbid_external=True,
            )
            for event, element in events:
                if event == "start":
                    if not stack:
                        self._check_root(element)
                        if element.tag == "report":
                            outer = element
                    elif element.tag == "report":
                        if outer is None and stack[-1] is stack[0]:
                            outer = element  # the report inside a GMP response
                        elif inner is None and stack[-1] is outer:
                            inner = element  # the report that holds the results
                    elif element.tag == "results" and inner is None and stack[-1] is outer:
                        inner = outer  # a report without the nested wrapper
                    stack.append(element)
                    continue

                stack.pop()
                parent = stack[-1] if stack else None
                if parent is None:
                    continue

                if parent is outer and element is not inner:
                    if element.tag == "name":
                        scan.report_name = _clip(element.text, MAX_SHORT)
                    elif element.tag == "task" and not scan.task_name:
                        scan.task_name = _clip(element.findtext("name"), MAX_SHORT)

                if parent is inner and inner is not None:
                    tag = element.tag
                    if tag == "scan_run_status":
                        status = (element.text or "").strip()
                    elif tag == "scan_start":
                        scan.scan_start = parse_time(element.text)
                    elif tag == "scan_end":
                        scan.scan_end = parse_time(element.text)
                    elif tag == "timestamp" and scan.scan_start is None:
                        scan.scan_start = parse_time(element.text)
                    elif tag == "task":
                        scan.task_name = _clip(element.findtext("name"), MAX_SHORT) or (
                            scan.task_name
                        )
                    elif tag == "results":
                        saw_results = True
                    elif tag == "host":
                        summary = self._parse_host_summary(element)
                        if summary:
                            summaries[summary["ip"]] = summary
                        parent.remove(element)
                    continue

                grandparent = stack[-2] if len(stack) >= 2 else None
                if grandparent is inner and inner is not None:
                    if parent.tag == "results" and element.tag == "result":
                        parsed = self._parse_result(element)
                        if parsed:
                            ip, hostname, finding = parsed
                            host = host_for(ip)
                            host.hostname = host.hostname or hostname
                            host.findings.append(finding)
                        parent.remove(element)  # release the result once it is read
                    elif parent.tag == "errors" and element.tag == "error":
                        host_el = element.find("host")
                        nvt = element.find("nvt")
                        ip = _clip(host_el.text if host_el is not None else "", 64)
                        oid = _clip(nvt.get("oid") if nvt is not None else "", 64)
                        if ip and oid:
                            bucket = unchecked.setdefault(ip, set())
                            if len(bucket) < MAX_UNCHECKED_PER_HOST:
                                bucket.add(oid)
                        parent.remove(element)
        except DefusedXmlException as exc:
            raise ScanParseError(
                "The file contains XML features that are not allowed (DTD or entities)."
            ) from exc
        except ParseError as exc:
            raise ScanParseError(f"The file is not well-formed XML: {exc}") from exc

        if outer is None and inner is None:
            raise ScanParseError(_NOT_A_REPORT)
        if inner is None or not saw_results:
            raise ScanParseError(
                "This OpenVAS report has no results section. In Greenbone, download the "
                "report with the XML report format."
            )
        if status and status != FINISHED:
            raise ScanParseError(
                f"This report is from a scan that did not finish (status: {status[:40]}). "
                "Import finished scans only, so findings are not marked fixed by mistake."
            )

        scan.external_id = _clip((outer if outer is not None else inner).get("id"), 64) or None
        scan.hosts = self._assemble_hosts(hosts, summaries, unchecked, scan)
        return scan

    @staticmethod
    def _check_root(root: Element) -> None:
        if root.tag not in ROOT_TAGS:
            raise ScanParseError(_NOT_A_REPORT)
        if root.tag == "get_reports_response":
            status = root.get("status", "")
            if not status.startswith("2"):
                detail = _clip(root.get("status_text"), 200) or "unknown error"
                raise ScanParseError(f"OpenVAS refused the report request: {detail}")

    @staticmethod
    def _assemble_hosts(
        hosts: dict[str, ParsedHost],
        summaries: dict[str, dict],
        unchecked: dict[str, set[str]],
        scan: ParsedScan,
    ) -> list[ParsedHost]:
        # A host in the summary with no results was scanned and had nothing to report.
        for ip in summaries:
            if ip not in hosts:
                hosts[ip] = ParsedHost(ip=ip)
        for ip, host in hosts.items():
            summary = summaries.get(ip)
            if summary:
                host.hostname = host.hostname or summary["hostname"]
                host.os = summary["os"]
                host.mac = summary["mac"]
                host.scan_start = summary["start"]
                host.scan_end = summary["end"]
                host.complete = summary["complete"]
            host.scan_start = host.scan_start or scan.scan_start
            host.scan_end = host.scan_end or scan.scan_end or host.scan_start
            host.unchecked = unchecked.get(ip, set())
        return list(hosts.values())


_NOT_A_REPORT = (
    "This is not an OpenVAS XML report. In Greenbone, open the report, choose the download "
    "icon and pick the XML report format."
)
