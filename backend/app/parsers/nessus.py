"""Parser for Nessus v2 exports (.nessus).

Security notes:
- A scan file is untrusted input. Parsing goes through defusedxml, which refuses DTDs,
  entity expansion (billion laughs) and external entities (XXE).
- The file is streamed with iterparse and each host is released after it is read, so a
  large export does not have to fit in memory as one XML tree.
- Free-text fields are capped in length before they reach the database.
"""

import re
from datetime import UTC, datetime
from typing import BinaryIO
from xml.etree.ElementTree import ParseError  # noqa: S405 - exception type only

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from .base import ParsedFinding, ParsedHost, ParsedScan, ScanParseError

ROOT_TAG = "NessusClientData_v2"
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
NESSUS_TIME_FORMAT = "%a %b %d %H:%M:%S %Y"  # e.g. "Sun Nov 15 10:42:11 2026"

MAX_SHORT = 255
MAX_NAME = 512
MAX_TEXT = 8000
MAX_CVES_PER_FINDING = 200


def _clip(value: str | None, limit: int) -> str:
    return (value or "").strip()[:limit]


def _to_int(value: str | None, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _to_score(value: str | None) -> float | None:
    try:
        score = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return score if 0.0 <= score <= 10.0 else None


def _parse_time(text: str | None, epoch: str | None = None) -> datetime | None:
    """Prefer the epoch timestamp, which is UTC like every time the app stores.

    The text form is in the scanner's local time without a zone, so it is only a fallback.
    """
    if epoch:
        try:
            return datetime.fromtimestamp(int(epoch), tz=UTC).replace(tzinfo=None)
        except (ValueError, OverflowError, OSError):
            pass
    if text:
        try:
            return datetime.strptime(text.strip(), NESSUS_TIME_FORMAT)  # noqa: DTZ007
        except ValueError:
            pass
    return None


def _parse_item(item) -> ParsedFinding:
    def text(tag: str) -> str | None:
        return item.findtext(tag)

    cves: list[str] = []
    for node in item.findall("cve"):
        cve = (node.text or "").strip().upper()
        if CVE_PATTERN.match(cve) and cve not in cves:
            cves.append(cve)
        if len(cves) >= MAX_CVES_PER_FINDING:
            break

    cvss3 = _to_score(text("cvss3_base_score"))
    cvss = cvss3 if cvss3 is not None else _to_score(text("cvss_base_score"))
    vector = text("cvss3_vector") if cvss3 is not None else text("cvss_vector")

    return ParsedFinding(
        plugin_id=_clip(item.get("pluginID"), 64),
        plugin_name=_clip(item.get("pluginName"), MAX_NAME),
        plugin_family=_clip(item.get("pluginFamily"), MAX_SHORT),
        severity=min(4, max(0, _to_int(item.get("severity")))),
        port=min(65535, max(0, _to_int(item.get("port")))),
        protocol=_clip(item.get("protocol"), 16).lower(),
        service=_clip(item.get("svc_name"), 64),
        cvss_base=cvss,
        cvss_vector=_clip(vector, 128),
        exploit_available=(text("exploit_available") or "").strip().lower() == "true",
        synopsis=_clip(text("synopsis"), MAX_TEXT),
        description=_clip(text("description"), MAX_TEXT),
        solution=_clip(text("solution"), MAX_TEXT),
        plugin_output=_clip(text("plugin_output"), MAX_TEXT),
        cves=cves,
    )


def _parse_host(element) -> ParsedHost | None:
    props: dict[str, str] = {}
    properties = element.find("HostProperties")
    if properties is not None:
        for tag in properties.findall("tag"):
            name = tag.get("name")
            if name:
                props[name] = tag.text or ""

    ip = _clip(props.get("host-ip") or element.get("name"), 64)
    if not ip:
        return None

    host = ParsedHost(
        ip=ip,
        hostname=_clip(props.get("netbios-name") or props.get("hostname"), MAX_SHORT),
        fqdn=_clip(props.get("host-fqdn"), MAX_SHORT),
        os=_clip(props.get("operating-system"), MAX_SHORT),
        mac=_clip(props.get("mac-address"), 64),
        scan_start=_parse_time(props.get("HOST_START"), props.get("HOST_START_TIMESTAMP")),
        scan_end=_parse_time(props.get("HOST_END"), props.get("HOST_END_TIMESTAMP")),
    )
    for item in element.findall("ReportItem"):
        finding = _parse_item(item)
        if finding.plugin_id:
            host.findings.append(finding)
    return host


class NessusParser:
    source = "nessus"

    def parse(self, fileobj: BinaryIO) -> ParsedScan:
        scan = ParsedScan(source=self.source)
        root = None
        try:
            events = SafeET.iterparse(
                fileobj,
                events=("start", "end"),
                forbid_dtd=True,
                forbid_entities=True,
                forbid_external=True,
            )
            for event, element in events:
                if root is None:
                    root = element
                    if root.tag != ROOT_TAG:
                        raise ScanParseError(
                            "This is not a Nessus v2 export. In Nessus, open the scan and "
                            "choose Export, then Nessus."
                        )
                    continue
                if event == "start" and element.tag == "Report":
                    scan.report_name = _clip(element.get("name"), MAX_SHORT)
                elif event == "end" and element.tag == "ReportHost":
                    host = _parse_host(element)
                    if host is not None:
                        scan.hosts.append(host)
                    element.clear()  # release this host's XML before reading the next
        except DefusedXmlException as exc:
            raise ScanParseError(
                "The file contains XML features that are not allowed (DTD or entities)."
            ) from exc
        except ParseError as exc:
            raise ScanParseError(f"The file is not well-formed XML: {exc}") from exc

        if root is None:
            raise ScanParseError("The file is empty.")
        return scan
