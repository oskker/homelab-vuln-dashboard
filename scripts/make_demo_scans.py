"""Generate the synthetic OpenVAS demo reports in sample-data/.

Eight weekly reports for a made-up home network, in the same XML report format that the
Greenbone web interface downloads and that GMP returns. Nothing here came from a real
network or a real scanner: the hosts are invented, the NVT OIDs are fake (999001 and up)
and the descriptions were written for this project. The CVE IDs are real, so the CISA
KEV and EPSS lookups have something to match.

The eight weeks tell a story the trend charts can show:
  week 1  baseline
  week 2  a check times out on the NAS (its finding must stay open, not count as fixed)
  week 3  Log4Shell patched on the media server
  week 4  printer SNMP locked down; a smart TV joins the network
  week 5  NAS Apache patched; router TLS 1.0 turned off
  week 6  router reset to factory settings: TLS 1.0 is back (reopened); RDP fixed;
          the NVR host does not finish (its findings must stay open)
  week 7  default admin login found on the NVR; OpenSSH patched
  week 8  router TLS fixed again; SMBv1 off on the NAS; smart TV updated

Usage:  python scripts/make_demo_scans.py
"""

import uuid
from datetime import datetime, timedelta
from pathlib import Path
from xml.etree import ElementTree as ET  # building XML here, not parsing untrusted input

from make_nessus_fixtures import HOSTILE_BANNER, HOSTS, PLUGINS

OUT_DIR = Path(__file__).resolve().parent.parent / "sample-data"
NAMESPACE = uuid.UUID("6f1c2a3e-6d0b-4c55-9a4e-2d6f0b6d9e10")
XML_FORMAT = "a994b278-1f62-11e1-96ac-406186ea4fc5"
TASK = "Home network weekly"
OID_PREFIX = "1.3.6.1.4.1.25623.1.0."

HOSTS = {
    **HOSTS,
    "tv": ("192.168.50.60", "SMART-TV", "smart-tv.home.arpa", "Embedded Linux (smart TV)", "02:00:5E:10:00:3C"),
}

# Nessus plugin ID -> (OID suffix, OpenVAS family, QoD, QoD type, solution type)
OPENVAS = {
    "900001": ("999001", "Web application abuses", 95, "remote_active", "VendorFix"),
    "900002": ("999002", "Windows : Microsoft Bulletins", 95, "remote_active", "VendorFix"),
    "900003": ("999003", "SSL and TLS", 95, "remote_vul", "VendorFix"),
    "900004": ("999004", "General", 80, "remote_banner", "VendorFix"),
    "900005": ("999005", "Web Servers", 95, "remote_vul", "VendorFix"),
    "900006": ("999006", "SSL and TLS", 98, "remote_app", "Mitigation"),
    "900007": ("999007", "SSL and TLS", 99, "remote_vul", "Mitigation"),
    "900008": ("999008", "Product detection", 80, "remote_banner", "Mitigation"),
    "900009": ("999009", "General", 95, "remote_active", "Mitigation"),
    "900010": ("999010", "SNMP", 80, "remote_vul", "Mitigation"),
    "900011": ("999011", "Default Accounts", 95, "remote_vul", "Mitigation"),
    "900012": ("999012", "General", 80, "remote_banner", "Mitigation"),
    "900013": ("999013", "Windows", 70, "remote_analysis", "Mitigation"),
}

UPNP = (
    "999020",
    "UPnP service answers on the internet-facing side",
    "Service detection",
    2,
    5.3,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "The device advertises a UPnP service that discloses its model and firmware.",
    "The UPnP description document can be read without authentication and lists the "
    "exact model, firmware version and services, which helps an attacker pick an exploit.",
    "Turn UPnP off in the device settings if nothing needs it.",
    80,
)

LOW_QOD = (  # a guess with low quality of detection; the dashboard ignores it by default
    "999030",
    "Possible outdated web server (version guess)",
    "Web Servers",
    6.1,
    30,
)

# (host, Nessus plugin ID, port, protocol, output)
BASE = [
    ("router", "900006", 443, "tcp", "TLSv1.0 is enabled and the server supports at least one cipher."),
    ("router", "900007", 443, "tcp", "Subject: CN=edge-router  Issuer: CN=edge-router"),
    ("router", "900009", 22, "tcp", "diffie-hellman-group1-sha1\ndiffie-hellman-group14-sha1"),
    ("router", "900012", 0, "icmp", "The difference between the local and remote clocks is 2 seconds."),
    ("nas", "900002", 445, "tcp", "The remote host answered an SMBv1 negotiation and is missing the fix."),
    ("nas", "900005", 80, "tcp", "Server: Apache/2.4.49 (Unix)"),
    ("nas", "900007", 443, "tcp", "Subject: CN=NAS01  Issuer: CN=NAS01"),
    ("nas", "900008", 445, "tcp", "Message signing: enabled but not required"),
    ("desktop", "900008", 445, "tcp", "Message signing: enabled but not required"),
    ("desktop", "900013", 3389, "tcp", "Network Level Authentication is not enforced."),
    ("media", "900001", 8080, "tcp", "A JNDI lookup placed in a request header triggered a callback."),
    ("media", "900004", 22, "tcp", "Installed version: 8.9p1\nFixed version:     9.8p1"),
    ("media", "900009", 22, "tcp", "diffie-hellman-group14-sha1"),
    ("nvr", "900003", 443, "tcp", HOSTILE_BANNER),
    ("nvr", "900006", 443, "tcp", "TLSv1.0 is enabled and the server supports at least one cipher."),
    ("nvr", "900007", 443, "tcp", "Subject: CN=CAM-NVR  Issuer: CN=CAM-NVR"),
    ("nvr", "900012", 0, "icmp", "The difference between the local and remote clocks is 41 seconds."),
    ("printer", "900006", 443, "tcp", "TLSv1.0 is enabled and the server supports at least one cipher."),
    ("printer", "900007", 443, "tcp", "Subject: CN=PRINTER  Issuer: CN=PRINTER"),
    ("printer", "900010", 161, "udp", "The community name 'public' returned the system description."),
]

LOG4SHELL = ("media", "900001")
SMB_NAS = ("nas", "900002")
APACHE_NAS = ("nas", "900005")
SNMP = ("printer", "900010")
ROUTER_TLS = ("router", "900006")
RDP = ("desktop", "900013")
OPENSSH = ("media", "900004")
TV_TLS = ("tv", "900006", 443, "tcp", "TLSv1.0 is enabled and the server supports at least one cipher.")
TV_UPNP = ("tv", "upnp", 1900, "udp", "Model: SmartView 55 (firmware 3.1.7)")
DEFAULT_CREDS = ("nvr", "900011", 80, "tcp", "Login succeeded with the documented default account.")
LOW_QOD_ITEM = ("media", "lowqod", 8080, "tcp", "Server header suggests an old release.")


def without(items, *keys):
    return [item for item in items if item[:2] not in keys]


WEEK1 = BASE + [LOW_QOD_ITEM]
WEEK3 = without(WEEK1, LOG4SHELL)
WEEK4 = [*without(WEEK3, SNMP), TV_TLS, TV_UPNP]
WEEK5 = without(WEEK4, APACHE_NAS, ROUTER_TLS)
WEEK6 = [*without(WEEK5, RDP), ("router", *BASE[0][1:])]
WEEK7 = [*without(WEEK6, OPENSSH), DEFAULT_CREDS]
WEEK8 = without(WEEK7, ROUTER_TLS, SMB_NAS, ("tv", "900006"))

# (items, hosts in scope, errors as (host, plugin), hosts that did not finish)
WEEKS = [
    (WEEK1, set(HOSTS) - {"tv"}, [], set()),
    (without(WEEK1, SMB_NAS), set(HOSTS) - {"tv"}, [SMB_NAS], set()),
    (WEEK3, set(HOSTS) - {"tv"}, [], set()),
    (WEEK4, set(HOSTS), [], set()),
    (WEEK5, set(HOSTS), [], set()),
    (without(WEEK6, ("nvr", "900007"), ("nvr", "900012")), set(HOSTS), [], {"nvr"}),
    (WEEK7, set(HOSTS), [], set()),
    (WEEK8, set(HOSTS), [], set()),
]
FIRST_SCAN = datetime(2026, 10, 4, 10, 0)  # 02:00 in California, a typical overnight slot


def iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def sub(parent, tag, text=None, **attrs):
    node = ET.SubElement(parent, tag, {k: str(v) for k, v in attrs.items()})
    if text is not None:
        node.text = str(text)
    return node


def threat(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low" if score > 0 else "Log"


def nvt_fields(plugin: str):
    """Return (oid, name, family, score, vector, cves, summary, insight, solution, qod, qod type, solution type)."""
    if plugin == "upnp":
        oid, name, family, _sev, score, vector, summary, insight, solution, qod = UPNP
        return OID_PREFIX + oid, name, family, score, vector, [], summary, insight, solution, qod, "remote_banner", "Mitigation"
    if plugin == "lowqod":
        oid, name, family, score, qod = LOW_QOD
        return (
            OID_PREFIX + oid, name, family, score, "", [], "The web server version might be outdated.",
            "The version was guessed from a generic header and could not be confirmed.",
            "Check the installed version and update it if needed.", qod, "remote_banner_unreliable", "VendorFix",
        )
    name, _family, _sev, score, vector, cves, _exploit, synopsis, description, solution = PLUGINS[plugin]
    suffix, family, qod, qod_type, solution_type = OPENVAS[plugin]
    score = score if score is not None else 2.1
    return OID_PREFIX + suffix, name, family, score, vector, cves, synopsis, description, solution, qod, qod_type, solution_type


def add_result(results, week, index, host_key, plugin, port, protocol, output, when):
    ip, _name, fqdn, _os, _mac = HOSTS[host_key]
    oid, name, family, score, vector, cves, summary, insight, solution, qod, qod_type, solution_type = nvt_fields(plugin)
    result = sub(results, "result", id=uuid.uuid5(NAMESPACE, f"result-{week}-{index}"))
    sub(result, "name", name)
    owner = sub(result, "owner")
    sub(owner, "name", "admin")
    sub(result, "modification_time", iso(when))
    sub(result, "comment")
    sub(result, "creation_time", iso(when))
    host = sub(result, "host", ip)
    sub(host, "asset", asset_id=uuid.uuid5(NAMESPACE, f"asset-{host_key}"))
    sub(host, "hostname", fqdn)
    sub(result, "port", f"{port}/{protocol}" if port else f"general/{protocol}")
    nvt = sub(result, "nvt", oid=oid)
    sub(nvt, "type", "nvt")
    sub(nvt, "name", name)
    sub(nvt, "family", family)
    sub(nvt, "cvss_base", f"{score:.1f}")
    if vector:
        severities = sub(nvt, "severities", score=f"{score:.1f}")
        severity = sub(severities, "severity", type="cvss_base_v3")
        sub(severity, "origin", "NVD")
        sub(severity, "score", f"{score:.1f}")
        sub(severity, "value", vector)
    tags = [f"cvss_base_vector={vector}"] if vector else []
    tags += [
        f"summary={summary}",
        f"insight={insight}",
        "affected=The version installed on this synthetic demo host.",
        f"solution={solution}",
        "vuldetect=Sends a crafted request and checks the response.",
        f"solution_type={solution_type}",
    ]
    sub(nvt, "tags", "|".join(tags))
    sub(nvt, "solution", solution, type=solution_type)
    refs = sub(nvt, "refs")
    for cve in cves:
        sub(refs, "ref", type="cve", id=cve)
    sub(result, "scan_nvt_version", "2026-09-30T08:00:00Z")
    sub(result, "threat", threat(score))
    sub(result, "severity", f"{score:.1f}")
    qod_node = sub(result, "qod")
    sub(qod_node, "value", qod)
    sub(qod_node, "type", qod_type)
    sub(result, "description", output)
    sub(result, "original_threat", threat(score))
    sub(result, "original_severity", f"{score:.1f}")


def add_log_result(results, week, host_key, when):
    """A log entry (severity 0). Real reports have many; the dashboard skips them."""
    ip, _name, fqdn, os_name, _mac = HOSTS[host_key]
    result = sub(results, "result", id=uuid.uuid5(NAMESPACE, f"log-{week}-{host_key}"))
    sub(result, "name", "OS Detection Consolidation and Reporting")
    sub(result, "creation_time", iso(when))
    host = sub(result, "host", ip)
    sub(host, "hostname", fqdn)
    sub(result, "port", "general/tcp")
    nvt = sub(result, "nvt", oid=OID_PREFIX + "999099")
    sub(nvt, "type", "nvt")
    sub(nvt, "name", "OS Detection Consolidation and Reporting")
    sub(nvt, "family", "Product detection")
    sub(nvt, "cvss_base", "0.0")
    sub(nvt, "tags", "summary=Reports the detected operating system.|solution_type=")
    sub(result, "threat", "Log")
    sub(result, "severity", "0.0")
    qod_node = sub(result, "qod")
    sub(qod_node, "value", 80)
    sub(qod_node, "type", "remote_banner")
    sub(result, "description", f"Best matching OS: {os_name}")


def build(week: int, items, in_scope, errors, unfinished) -> str:
    start = FIRST_SCAN + timedelta(weeks=week - 1)
    report_id = uuid.uuid5(NAMESPACE, f"report-{week}")
    task_id = uuid.uuid5(NAMESPACE, "task")
    root = ET.Element(
        "report", {"id": str(report_id), "format_id": XML_FORMAT, "extension": "xml", "content_type": "text/xml"}
    )
    root.append(ET.Comment(" SYNTHETIC DEMO DATA. Generated by scripts/make_demo_scans.py, not by a scanner. "))
    owner = sub(root, "owner")
    sub(owner, "name", "admin")
    sub(root, "name", iso(start))
    sub(root, "comment")
    sub(root, "creation_time", iso(start))
    sub(root, "modification_time", iso(start + timedelta(minutes=40)))
    sub(root, "writable", 0)
    sub(root, "in_use", 0)
    task = sub(root, "task", id=task_id)
    sub(task, "name", TASK)
    report_format = sub(root, "report_format", id=XML_FORMAT)
    sub(report_format, "name", "XML")

    inner = sub(root, "report", id=report_id)
    gmp = sub(inner, "gmp")
    sub(gmp, "version", "22.8")
    sub(inner, "scan_run_status", "Done")
    hosts_node = sub(inner, "hosts")
    sub(hosts_node, "count", len(in_scope))
    inner_task = sub(inner, "task", id=task_id)
    sub(inner_task, "name", TASK)
    target = sub(inner_task, "target", id=uuid.uuid5(NAMESPACE, "target"))
    sub(target, "trash", 0)
    sub(target, "name", "Home LAN 192.168.50.0/24")
    sub(inner_task, "progress", 100)
    sub(inner, "timestamp", iso(start))
    sub(inner, "scan_start", iso(start))
    sub(inner, "timezone", "UTC")
    sub(inner, "timezone_abbrev", "UTC")

    results = sub(inner, "results", start=1, max=-1)
    order = [key for key in HOSTS if key in in_scope]
    host_times = {key: start + timedelta(minutes=4 * i) for i, key in enumerate(order)}
    for index, (host_key, plugin, port, protocol, output) in enumerate(items):
        if host_key in in_scope:
            add_result(results, week, index, host_key, plugin, port, protocol, output, host_times[host_key] + timedelta(minutes=2))
    for host_key in order:
        add_log_result(results, week, host_key, host_times[host_key])

    for host_key in order:
        ip, _name, fqdn, os_name, mac = HOSTS[host_key]
        host = sub(inner, "host")
        sub(host, "ip", ip)
        sub(host, "asset", asset_id=uuid.uuid5(NAMESPACE, f"asset-{host_key}"))
        sub(host, "start", iso(host_times[host_key]))
        sub(host, "end", "" if host_key in unfinished else iso(host_times[host_key] + timedelta(minutes=3, seconds=17)))
        for name, value in (("hostname", fqdn), ("best_os_txt", os_name), ("MAC", mac)):
            detail = sub(host, "detail")
            sub(detail, "name", name)
            sub(detail, "value", value)

    sub(inner, "scan_end", iso(start + timedelta(minutes=4 * len(order) + 5)))
    errors_node = sub(inner, "errors")
    sub(errors_node, "count", len(errors))
    for host_key, plugin in errors:
        ip = HOSTS[host_key][0]
        error = sub(errors_node, "error")
        host = sub(error, "host", ip)
        sub(host, "asset", asset_id="")
        sub(error, "port", "445/tcp")
        sub(error, "description", "NVT timed out after 320 seconds.")
        oid, name, *_ = nvt_fields(plugin)
        nvt = sub(error, "nvt", oid=oid)
        sub(nvt, "type", "nvt")
        sub(nvt, "name", name)
        sub(error, "severity", "-3.0")
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=False)


def main():
    OUT_DIR.mkdir(exist_ok=True)
    for week, (items, in_scope, errors, unfinished) in enumerate(WEEKS, start=1):
        day = (FIRST_SCAN + timedelta(weeks=week - 1)).strftime("%Y-%m-%d")
        path = OUT_DIR / f"openvas-demo-{week}-{day}.xml"
        xml = '<?xml version="1.0" encoding="UTF-8"?>\n' + build(week, items, in_scope, errors, unfinished) + "\n"
        path.write_text(xml, encoding="utf-8", newline="\n")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
