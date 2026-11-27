"""Scan parsers. Each scanner format implements the small interface in base.py."""

from typing import BinaryIO

from .base import ParsedFinding, ParsedHost, ParsedScan, ScanParseError
from .nessus import NessusParser
from .nessus_html import NessusHtmlParser
from .openvas import DEFAULT_MIN_QOD, OpenVasParser

SNIFF_BYTES = 4096
NESSUS_ROOT = b"<NessusClientData_v2"

UNSUPPORTED = (
    "This file is not a supported scan report. Import an OpenVAS report in the XML "
    "format (in Greenbone, open the report and download it as XML), a Nessus .nessus "
    "export, or a Nessus HTML report."
)


def parse_scan(fileobj: BinaryIO, *, min_qod: int = DEFAULT_MIN_QOD) -> ParsedScan:
    """Pick the parser from the file's first bytes, then parse.

    - OpenVAS / Greenbone: the XML report format, from the web interface or over GMP.
    - Nessus Professional: the .nessus export (XML).
    - Nessus Essentials / Essentials Plus: the HTML report, "Detailed Vulnerabilities By
      Host" template, because those editions cannot export .nessus files.
    """
    head = fileobj.read(SNIFF_BYTES)
    fileobj.seek(0)
    if OpenVasParser.looks_like(head):
        return OpenVasParser(min_qod=min_qod).parse(fileobj)
    if NessusHtmlParser.looks_like(head):
        return NessusHtmlParser().parse(fileobj)
    if NESSUS_ROOT in head:
        return NessusParser().parse(fileobj)
    raise ScanParseError(UNSUPPORTED)


__all__ = [
    "NessusHtmlParser",
    "NessusParser",
    "OpenVasParser",
    "ParsedFinding",
    "ParsedHost",
    "ParsedScan",
    "ScanParseError",
    "parse_scan",
]
