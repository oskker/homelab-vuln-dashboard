"""The scanner-neutral shape every parser produces."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import BinaryIO, Protocol


class ScanParseError(ValueError):
    """The file is not a scan export this parser can safely read."""


@dataclass
class ParsedFinding:
    plugin_id: str
    plugin_name: str
    severity: int  # 0 info .. 4 critical
    port: int = 0
    protocol: str = ""
    service: str = ""
    plugin_family: str = ""
    cvss_base: float | None = None
    cvss_vector: str = ""
    exploit_available: bool = False
    synopsis: str = ""
    description: str = ""
    solution: str = ""
    plugin_output: str = ""
    cves: list[str] = field(default_factory=list)


@dataclass
class ParsedHost:
    ip: str
    hostname: str = ""
    fqdn: str = ""
    os: str = ""
    mac: str = ""
    scan_start: datetime | None = None
    scan_end: datetime | None = None
    findings: list[ParsedFinding] = field(default_factory=list)


@dataclass
class ParsedScan:
    source: str
    report_name: str = ""
    hosts: list[ParsedHost] = field(default_factory=list)


class ScanParser(Protocol):
    source: str

    def parse(self, fileobj: BinaryIO) -> ParsedScan:
        """Read a scan export. Raises ScanParseError for anything unexpected."""
        ...
