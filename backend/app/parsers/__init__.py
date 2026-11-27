"""Scan parsers. Each scanner format implements the small interface in base.py."""

from .base import ParsedFinding, ParsedHost, ParsedScan, ScanParseError
from .nessus import NessusParser

# Register new formats here (Nmap XML and OpenVAS are on the roadmap).
PARSERS = [NessusParser()]

__all__ = [
    "PARSERS",
    "NessusParser",
    "ParsedFinding",
    "ParsedHost",
    "ParsedScan",
    "ScanParseError",
]
