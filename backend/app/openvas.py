"""OpenVAS integration: read tasks, create and start scans, and import finished reports.

The dashboard talks to gvmd (the Greenbone manager) over GMP. Greenbone stays the place
where scans run; the dashboard keeps the long-term history. Every finished report is
pulled in automatically, oldest first, so trends build up without anyone exporting files.

Guardrails:
- Scans the dashboard creates may only target private addresses (RFC 1918, link-local,
  loopback, IPv6 unique-local) and local host names, unless OPENVAS_ALLOW_PUBLIC_TARGETS
  is set. Scanning networks you do not own is illegal in most places.
- Only reports from finished scans are imported. A stopped or interrupted scan would
  otherwise make every finding it did not reach look fixed.
"""

import hashlib
import ipaddress
import logging
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from io import BytesIO
from xml.etree.ElementTree import Element  # noqa: S405 - type only

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings
from .db import utcnow
from .gmp import (
    GmpAuthError,
    GmpCommandError,
    GmpConnection,
    GmpConnectionError,
    GmpError,
    child,
    element,
)
from .importer import DuplicateScanError, import_scan
from .models import ORIGIN_SYNC, Scan
from .parsers import ScanParseError
from .parsers.openvas import FINISHED, OpenVasParser, parse_time

# Objects every Greenbone installation ships with, under fixed IDs. They are looked up
# by name as a fallback in case an installation differs.
FULL_AND_FAST = ("daba56c8-73ec-11df-a475-002264764cea", "Full and fast")
OPENVAS_SCANNER = ("08b69003-5fc2-4037-a479-93b440211c73", "OpenVAS Default")
ALL_IANA_TCP = ("33d0cd82-57c6-11e1-8ed1-406186ea4fc5", "All IANA assigned TCP")

ALIVE_DEFAULT = ["ICMP Ping", "TCP-ACK Service Ping", "ARP Ping"]
ALIVE_LEGACY = {"default": "ICMP, TCP-ACK Service & ARP Ping", "consider": "Consider Alive"}
REPEATS = {"none": None, "daily": "DAILY", "weekly": "WEEKLY"}
STATUS_TIMEOUT = 8.0
MAX_TARGET_ENTRIES = 32
MAX_ADDRESSES = 4096
MAX_REPORTS_PER_SYNC = 20
LOCAL_SUFFIXES = (".local", ".lan", ".home", ".home.arpa", ".internal", ".localdomain")
LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
HOSTNAME = re.compile(rf"^(?=.{{1,253}}$){LABEL}(?:\.{LABEL})*$")
TIMEZONE = re.compile(r"^[A-Za-z]+(?:[/_+-][A-Za-z0-9]+){0,4}$")
SAFE_NAME = re.compile(r"[^\w .,()'@#+-]")


log = logging.getLogger("vulndash.openvas")

NOT_CONFIGURED = (
    "OpenVAS is not connected. Run start.bat to start it with the dashboard, or import "
    "OpenVAS XML reports by hand."
)
NOT_REACHABLE = (
    "OpenVAS is not answering yet. It takes several minutes to start; the dashboard "
    "connects on its own."
)
AUTH_FAILED = (
    "OpenVAS rejected the user name or password set in OPENVAS_USERNAME and OPENVAS_PASSWORD."
)
REFUSED = "OpenVAS refused the request. The app log has the details."
UNUSABLE = "OpenVAS sent a reply the dashboard could not use. The app log has the details."


class OpenVasError(RuntimeError):
    """Raised with a message written for the user."""


class OpenVasNotConfigured(OpenVasError):
    pass


def public_error(exc: Exception) -> str:
    """A fixed message for the user. Exception text, which can carry internal detail,
    goes to the log instead of into API replies."""
    if isinstance(exc, OpenVasNotConfigured):
        return NOT_CONFIGURED
    if isinstance(exc, GmpAuthError):
        return AUTH_FAILED
    if isinstance(exc, GmpConnectionError):
        return NOT_REACHABLE
    if isinstance(exc, GmpCommandError):
        return REFUSED
    return UNUSABLE


# ---------- Target validation ----------


def _is_local(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return address.is_private or address.is_link_local or address.is_loopback


def parse_targets(text: str, *, allow_public: bool = False) -> list[str]:
    """Validate a list of IPs, CIDR blocks, IPv4 ranges and local host names.

    Returns the cleaned entries. Raises OpenVasError with a message for the user.
    """
    entries = [e for e in re.split(r"[\s,;]+", text.strip()) if e]
    if not entries:
        raise OpenVasError("Enter at least one IP address, network or host name.")
    if len(entries) > MAX_TARGET_ENTRIES:
        raise OpenVasError(f"Enter at most {MAX_TARGET_ENTRIES} targets per scan.")

    cleaned: list[str] = []
    total = 0
    for entry in entries:
        count, addresses = _target_size(entry)
        if addresses is None:
            if not HOSTNAME.match(entry) or entry.replace(".", "").isdigit():
                raise OpenVasError(f"'{entry[:60]}' is not an IP address, network or host name.")
            local_name = "." not in entry or entry.lower().endswith(LOCAL_SUFFIXES)
            if not allow_public and not local_name:
                raise OpenVasError(
                    f"'{entry[:60]}' does not look like a name on your own network. Use an IP "
                    "address, or a name ending in .local, .lan, .home.arpa or .internal."
                )
        elif not allow_public and not all(_is_local(a) for a in addresses):
            raise OpenVasError(
                f"'{entry}' includes public internet addresses. The dashboard only scans "
                "private networks (such as 192.168.x.x) unless OPENVAS_ALLOW_PUBLIC_TARGETS "
                "is turned on. Only scan networks you own or have permission to scan."
            )
        total += count
        cleaned.append(entry)
    if total > MAX_ADDRESSES:
        raise OpenVasError(
            f"That is {total} addresses. Keep a scan to {MAX_ADDRESSES} addresses or fewer, "
            "for example one /24 network (256 addresses)."
        )
    return cleaned


def _target_size(entry: str):
    """Return (address count, boundary addresses) or (1, None) for a host name."""
    try:
        if "/" in entry:
            network = ipaddress.ip_network(entry, strict=False)
            return network.num_addresses, [network.network_address, network.broadcast_address]
        if "-" in entry:
            first_text, last_text = entry.split("-", 1)
            first = ipaddress.ip_address(first_text)
            last = (
                ipaddress.ip_address(last_text)
                if not last_text.isdigit()
                else ipaddress.ip_address(f"{first_text.rsplit('.', 1)[0]}.{last_text}")
            )
            if first.version != last.version or int(last) < int(first):
                raise ValueError("bad range")
            return int(last) - int(first) + 1, [first, last]
        address = ipaddress.ip_address(entry)
        return 1, [address]
    except ValueError:
        return 1, None


def clean_name(text: str, fallback: str) -> str:
    name = " ".join(SAFE_NAME.sub("", text).split())[:80].strip()
    return name or fallback


def icalendar(start: datetime, repeat: str, now: datetime) -> str:
    """An iCalendar event the way gvmd expects schedules. Times are UTC."""
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//HomeLab Vuln Dashboard//EN",
        "BEGIN:VEVENT",
        f"UID:{uuid.uuid4()}",
        f"DTSTAMP:{now:%Y%m%dT%H%M%SZ}",
        f"DTSTART:{start:%Y%m%dT%H%M%SZ}",
        "DURATION:PT0S",
    ]
    if REPEATS.get(repeat):
        lines.append(f"RRULE:FREQ={REPEATS[repeat]}")
    lines += ["END:VEVENT", "END:VCALENDAR"]
    return "\r\n".join(lines) + "\r\n"


# ---------- Reading GMP replies ----------


def _text(node: Element | None, path: str) -> str:
    if node is None:
        return ""
    return (node.findtext(path) or "").strip()


def _int(text: str, default: int = 0) -> int:
    try:
        return int(float(text))
    except ValueError:
        return default


def read_tasks(reply: Element) -> list[dict]:
    tasks = []
    for task in reply.findall("task"):
        report_count = task.find("report_count")
        last = task.find("last_report/report")
        schedule = task.find("schedule")
        tasks.append(
            {
                "id": task.get("id", ""),
                "name": _text(task, "name")[:255],
                "status": _text(task, "status")[:40],
                "progress": _int(_text(task, "progress"), -1),
                "target": _text(task, "target/name")[:255],
                "config": _text(task, "config/name")[:255],
                "schedule": _text(schedule, "name")[:255] if schedule is not None else "",
                "reports": _int((report_count.text or "0") if report_count is not None else "0"),
                "last_report_id": last.get("id", "") if last is not None else "",
                "last_report_time": parse_time(_text(last, "timestamp")),
                "usage_type": _text(task, "usage_type") or "scan",
            }
        )
    return tasks


def read_reports(reply: Element) -> list[dict]:
    reports = []
    for report in reply.findall("report"):
        inner = report.find("report")
        task = report.find("task")
        reports.append(
            {
                "id": report.get("id", ""),
                "task_id": task.get("id", "") if task is not None else "",
                "task_name": _text(report, "task/name")[:255],
                "status": _text(inner, "scan_run_status"),
                "time": parse_time(_text(inner, "scan_end"))
                or parse_time(_text(inner, "scan_start"))
                or parse_time(_text(inner, "timestamp"))
                or parse_time(_text(report, "creation_time")),
            }
        )
    return reports


def feeds_loading(reply: Element) -> bool:
    return any(feed.find("currently_syncing") is not None for feed in reply.findall("feed"))


# ---------- The service ----------


@dataclass
class SyncResult:
    imported: list[dict] = field(default_factory=list)
    waiting: int = 0  # reports from scans that are still running
    unfinished: int = 0  # stopped or interrupted scans, which are never imported
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "imported": self.imported,
            "waiting": self.waiting,
            "unfinished": self.unfinished,
            "errors": self.errors,
        }


class OpenVasService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.sync_lock = threading.Lock()
        self.last_sync: dict | None = None
        self._failed_reports: set[str] = set()

    @property
    def configured(self) -> bool:
        return bool(self.settings.openvas_socket)

    def connect(self, timeout: float | None = None) -> GmpConnection:
        if not self.configured:
            raise OpenVasNotConfigured(NOT_CONFIGURED)
        connection = GmpConnection(
            self.settings.openvas_socket,
            timeout=timeout or self.settings.openvas_timeout_seconds,
            max_reply_bytes=self.settings.max_upload_bytes,
        )
        connection.open()
        try:
            connection.authenticate(
                self.settings.openvas_username, self.settings.openvas_password.get_secret_value()
            )
        except Exception:
            connection.close()
            raise
        return connection

    # --- status and tasks ---

    def status(self) -> dict:
        info: dict = {
            "configured": self.configured,
            "connected": False,
            "version": None,
            "feed_loading": None,
            "ready": False,
            "message": "",
            "web_url": self.settings.openvas_web_url,
            "sync_minutes": self.settings.openvas_sync_minutes,
            "last_sync": self.last_sync,
            "min_qod": self.settings.openvas_min_qod,
        }
        if not self.configured:
            info["message"] = NOT_CONFIGURED
            return info
        try:
            with self.connect(timeout=STATUS_TIMEOUT) as gmp:
                info["connected"] = True
                info["version"] = _text(gmp.request(element("get_version")), "version")[:20]
                loading = feeds_loading(gmp.request(element("get_feeds")))
                has_config = self._find(gmp, "get_configs", "config", FULL_AND_FAST) is not None
                info["feed_loading"] = loading or not has_config
                info["ready"] = not info["feed_loading"]
                info["message"] = (
                    "OpenVAS is ready."
                    if info["ready"]
                    else "OpenVAS is loading its vulnerability feed. The first start can take "
                    "30 minutes or more; scans can start when it finishes."
                )
        except GmpError as exc:
            log.info("OpenVAS status check failed: %s", exc)
            info["message"] = public_error(exc)
        return info

    def tasks(self) -> list[dict]:
        with self.connect() as gmp:
            reply = gmp.request(element("get_tasks", {"filter": "rows=-1 sort=name"}))
        return [t for t in read_tasks(reply) if t["usage_type"] == "scan"]

    def start_task(self, task_id: str) -> str:
        task_id = str(uuid.UUID(task_id))
        with self.connect() as gmp:
            reply = gmp.request(element("start_task", {"task_id": task_id}))
        return _text(reply, "report_id")

    # --- creating scans ---

    @staticmethod
    def _find(gmp: GmpConnection, command: str, tag: str, wanted: tuple[str, str]) -> str | None:
        known_id, name = wanted
        reply = gmp.request(element(command, {"filter": "rows=-1"}))
        items = reply.findall(tag)
        for item in items:
            if item.get("id") == known_id:
                return known_id
        for item in items:
            if _text(item, "name") == name:
                return item.get("id")
        return None

    def create_scan(
        self,
        *,
        name: str,
        targets: str,
        consider_alive: bool,
        repeat: str,
        start_at: datetime | None,
        timezone: str,
    ) -> dict:
        hosts = parse_targets(targets, allow_public=self.settings.openvas_allow_public_targets)
        if repeat not in REPEATS:
            raise OpenVasError("Repeat must be none, daily or weekly.")
        if not TIMEZONE.match(timezone):
            timezone = "UTC"
        now = utcnow()
        if start_at is not None and start_at < now:
            start_at = None  # "now" from a browser with a slow clock
        if repeat != "none" and start_at is None:
            raise OpenVasError("Pick when the first scan should run.")
        label = clean_name(name, "Home network")
        stamp = now.strftime("%Y-%m-%d %H:%M")

        with self.connect() as gmp:
            config_id = self._find(gmp, "get_configs", "config", FULL_AND_FAST)
            scanner_id = self._find(gmp, "get_scanners", "scanner", OPENVAS_SCANNER)
            port_list_id = self._find(gmp, "get_port_lists", "port_list", ALL_IANA_TCP)
            if not (config_id and scanner_id and port_list_id):
                raise OpenVasError(
                    "OpenVAS has not finished loading its scan configurations. Try again "
                    "when the status shows it is ready."
                )
            target_id = self._create_target(
                gmp, f"{label} targets ({stamp})", hosts, port_list_id, consider_alive
            )
            schedule_id = None
            if start_at is not None:
                command = element("create_schedule")
                child(command, "name", text=f"{label} schedule ({stamp})")
                child(command, "icalendar", text=icalendar(start_at, repeat, now))
                child(command, "timezone", text=timezone)
                schedule_id = gmp.request(command).get("id")

            command = element("create_task")
            child(command, "name", text=label)
            child(command, "comment", text="Created by HomeLab Vuln Dashboard")
            child(command, "config", {"id": config_id})
            child(command, "target", {"id": target_id})
            child(command, "scanner", {"id": scanner_id})
            if schedule_id:
                child(command, "schedule", {"id": schedule_id})
            task_id = gmp.request(command).get("id", "")

            started = False
            if schedule_id is None:
                gmp.request(element("start_task", {"task_id": task_id}))
                started = True
        return {"task_id": task_id, "started": started, "targets": hosts}

    @staticmethod
    def _create_target(
        gmp: GmpConnection, name: str, hosts: list[str], port_list_id: str, consider_alive: bool
    ) -> str:
        def build(modern: bool) -> Element:
            command = element("create_target")
            child(command, "name", text=name)
            child(command, "hosts", text=",".join(hosts))
            child(command, "port_list", {"id": port_list_id})
            child(command, "comment", text="Created by HomeLab Vuln Dashboard")
            if modern:
                tests = child(command, "alive_tests")
                for test in ["Consider Alive"] if consider_alive else ALIVE_DEFAULT:
                    child(tests, "alive_test", text=test)
            else:  # GMP versions before alive_test sub-elements
                key = "consider" if consider_alive else "default"
                child(command, "alive_tests", text=ALIVE_LEGACY[key])
            return command

        try:
            return gmp.request(build(modern=True)).get("id", "")
        except GmpCommandError as exc:
            if "alive" not in exc.text.lower():
                raise
            return gmp.request(build(modern=False)).get("id", "")

    # --- importing finished reports ---

    def fetch_report(self, gmp: GmpConnection, report_id: str) -> bytes:
        report_filter = (
            f"apply_overrides=1 min_qod={self.settings.openvas_min_qod} "
            "rows=-1 first=1 sort=name result_hosts_only=0"
        )
        command = element(
            "get_reports",
            {
                "report_id": report_id,
                "filter": report_filter,
                "details": "1",
                "ignore_pagination": "1",
            },
        )
        return gmp.exchange(command)

    def sync(self, db: Session) -> SyncResult:
        """Import every finished report that is not in the dashboard yet, oldest first."""
        result = SyncResult()
        with self.connect() as gmp:
            listing = gmp.request(
                element(
                    "get_reports",
                    {
                        "report_filter": "rows=-1 first=1 sort=date",
                        "details": "0",
                        "ignore_pagination": "1",
                        "usage_type": "scan",
                    },
                )
            )
            known = set(
                db.scalars(select(Scan.external_id).where(Scan.external_id.is_not(None)))
            )
            pending = []
            for report in read_reports(listing):
                if not report["id"] or report["id"] in known:
                    continue
                if report["status"] == FINISHED:
                    if report["id"] not in self._failed_reports:
                        pending.append(report)
                elif report["status"] in ("Stopped", "Interrupted"):
                    result.unfinished += 1
                else:
                    result.waiting += 1
            pending.sort(key=lambda r: r["time"] or datetime.min)

            parser = OpenVasParser(min_qod=self.settings.openvas_min_qod)
            for report in pending[:MAX_REPORTS_PER_SYNC]:
                try:
                    raw = self.fetch_report(gmp, report["id"])
                    parsed = parser.parse(BytesIO(raw))
                    when = (report["time"] or utcnow()).strftime("%Y-%m-%d")
                    task = clean_name(report["task_name"] or parsed.task_name, "openvas")
                    imported = import_scan(
                        db,
                        parsed,
                        filename=f"{task} {when}.xml",
                        sha256=hashlib.sha256(raw).hexdigest(),
                        raw=raw,
                        media_type="application/xml",
                        origin=ORIGIN_SYNC,
                    )
                except DuplicateScanError:
                    db.rollback()
                    continue
                except (ScanParseError, GmpCommandError) as exc:
                    db.rollback()
                    self._failed_reports.add(report["id"])
                    log.warning("OpenVAS report %s was not imported: %s", report["id"], exc)
                    reason = (
                        "OpenVAS refused to send it"
                        if isinstance(exc, GmpCommandError)
                        else "it could not be read as a finished OpenVAS report"
                    )
                    result.errors.append(
                        f"Report {report['id'][:8]} was not imported: {reason}. "
                        "The app log has the details."
                    )
                    continue
                result.imported.append(
                    {
                        "scan_id": imported.scan.id,
                        "task_name": imported.scan.task_name,
                        "scan_time": imported.scan.scan_time,
                        "new": imported.new,
                        "fixed": imported.fixed,
                        "reopened": imported.reopened,
                    }
                )
        return result

    def run_sync(self, db: Session) -> dict:
        """Sync once, unless a sync is already running. Records the outcome for the UI."""
        if not self.sync_lock.acquire(blocking=False):
            raise OpenVasError("A sync is already running.")
        try:
            try:
                outcome = self.sync(db).as_dict()
                outcome["error"] = None
            except (GmpError, OpenVasError) as exc:
                db.rollback()
                log.warning("OpenVAS sync failed: %s", exc)
                outcome = SyncResult().as_dict()
                outcome["error"] = public_error(exc)
            outcome["at"] = utcnow()
            self.last_sync = outcome
            return outcome
        finally:
            self.sync_lock.release()
