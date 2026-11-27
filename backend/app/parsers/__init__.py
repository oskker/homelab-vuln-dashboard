"""Scan parsers. Each scanner format implements the small interface in base.py."""

from typing import BinaryIO

from .base import ParsedFinding, ParsedHost, ParsedScan, ScanParseError
from .nessus import NessusParser
from .nessus_html import NessusHtmlParser

SNIFF_BYTES = 4096

# Register new formats here (Nmap XML and OpenVAS are on the roadmap).
PARSERS = [NessusParser(), NessusHtmlParser()]


def parse_scan(fileobj: BinaryIO) -> ParsedScan:
    """Pick the parser from the file's first bytes, then parse.

    - Nessus Professional: the .nessus export (XML).
    - Nessus Essentials / Essentials Plus: the HTML report, "Detailed Vulnerabilities By
      Host" template, because those editions cannot export .nessus files.
    """
    head = fileobj.read(SNIFF_BYTES)
    fileobj.seek(0)
    if NessusHtmlParser.looks_like(head):
        return NessusHtmlParser().parse(fileobj)
    return NessusParser().parse(fileobj)


__all__ = [
    "PARSERS",
    "NessusHtmlParser",
    "NessusParser",
    "ParsedFinding",
    "ParsedHost",
    "ParsedScan",
    "ScanParseError",
    "parse_scan",
]
