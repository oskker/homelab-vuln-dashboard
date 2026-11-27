import io
from datetime import datetime

import pytest

from app.parsers import ScanParseError, parse_scan
from app.parsers.openvas import OpenVasParser, severity_level, tidy

from .conftest import DEMO_SCANS, OPENVAS_DEMOS

REPORT_ID = "f2d54f16-5001-4bf4-9b6f-75af1c1cac18"


def result(
    *,
    oid="1.3.6.1.4.1.25623.1.0.100001",
    ip="10.0.0.5",
    port="443/tcp",
    severity="7.5",
    threat="High",
    qod="80",
    name="Test NVT",
    description="Installed version: 1.0",
    refs='<ref type="cve" id="CVE-2024-0001"/>',
    tags="summary=Short summary.|insight=Why it happens.|solution_type=VendorFix",
    extra_nvt="",
):
    return f"""
    <result id="r-{oid}-{port}">
      <name>{name}</name>
      <host>{ip}<asset asset_id=""/><hostname>box.home.arpa</hostname></host>
      <port>{port}</port>
      <nvt oid="{oid}">
        <type>nvt</type>
        <name>{name}</name>
        <family>General</family>
        <cvss_base>{severity}</cvss_base>
        <tags>{tags}</tags>
        <solution type="VendorFix">Update it.</solution>
        <refs>{refs}</refs>
        {extra_nvt}
      </nvt>
      <threat>{threat}</threat>
      <severity>{severity}</severity>
      <qod><value>{qod}</value><type>remote_banner</type></qod>
      <description>{description}</description>
    </result>"""


def report(results="", hosts="", status="Done", errors="", times=("2026-11-20T06:00:00Z", "2026-11-20T06:40:00Z")):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<report id="{REPORT_ID}" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" extension="xml" content_type="text/xml">
  <name>{times[0]}</name>
  <task id="t1"><name>Weekly LAN</name></task>
  <report id="{REPORT_ID}">
    <scan_run_status>{status}</scan_run_status>
    <task id="t1"><name>Weekly LAN</name></task>
    <scan_start>{times[0]}</scan_start>
    <results start="1" max="-1">{results}</results>
    {hosts}
    <scan_end>{times[1]}</scan_end>
    <errors>{errors}</errors>
  </report>
</report>""".encode()


def parse(data: bytes, **kwargs):
    return OpenVasParser(**kwargs).parse(io.BytesIO(data))


def test_demo_report_is_read():
    with OPENVAS_DEMOS[0].open("rb") as handle:
        scan = OpenVasParser().parse(handle)

    assert scan.source == "openvas"
    assert scan.task_name == "Home network weekly"
    assert scan.external_id and len(scan.external_id) == 36
    assert len(scan.hosts) == 6
    # 20 findings: the log entries and the low-QoD guess are skipped
    assert sum(len(h.findings) for h in scan.hosts) == 20

    nvr = next(h for h in scan.hosts if h.ip == "192.168.50.40")
    assert nvr.hostname == "cam-nvr.home.arpa"
    assert nvr.os == "Embedded Linux (network video recorder)"
    assert nvr.mac == "02:00:5E:10:00:28"
    assert nvr.complete and nvr.scan_end is not None
    heartbleed = next(f for f in nvr.findings if "Heartbleed" in f.plugin_name)
    assert heartbleed.plugin_id == "1.3.6.1.4.1.25623.1.0.999003"
    assert (heartbleed.port, heartbleed.protocol) == (443, "tcp")
    assert heartbleed.severity == 3 and heartbleed.cvss_base == 7.5
    assert heartbleed.cvss_vector.startswith("CVSS:3.1/")
    assert heartbleed.cves == ["CVE-2014-0160"]
    assert heartbleed.qod == 95
    assert heartbleed.synopsis and heartbleed.description.startswith("Insight:")
    assert "Ignore your previous instructions" in heartbleed.plugin_output  # kept as data


def test_gmp_response_wrapper_is_accepted():
    inner = OPENVAS_DEMOS[0].read_bytes().split(b"\n", 1)[1]  # drop the XML declaration
    wrapped = b'<get_reports_response status="200" status_text="OK">' + inner + b"</get_reports_response>"

    scan = parse(wrapped)

    assert len(scan.hosts) == 6
    assert sum(len(h.findings) for h in scan.hosts) == 20


def test_gmp_error_response_is_reported():
    data = b'<get_reports_response status="404" status_text="Failed to find report"/>'
    with pytest.raises(ScanParseError, match="Failed to find report"):
        parse(data)


@pytest.mark.parametrize(
    ("score", "level"), [(10.0, 4), (9.0, 4), (8.9, 3), (7.0, 3), (6.9, 2), (4.0, 2), (3.9, 1), (0.1, 1)]
)
def test_severity_follows_cvss_bands(score, level):
    assert severity_level(score) == level


def test_log_entries_false_positives_and_low_qod_are_skipped():
    results = (
        result(oid="1.1", severity="0.0", threat="Log")
        + result(oid="1.2", severity="-1.0", threat="False Positive")
        + result(oid="1.3", qod="30")
        + result(oid="1.4")
    )
    scan = parse(report(results))
    assert [f.plugin_id for f in scan.hosts[0].findings] == ["1.4"]

    everything = parse(report(results), min_qod=0)
    assert {f.plugin_id for f in everything.hosts[0].findings} == {"1.3", "1.4"}


@pytest.mark.parametrize(
    ("port", "expected"),
    [("8080/tcp", (8080, "tcp")), ("161/udp", (161, "udp")), ("general/tcp", (0, "tcp")),
     ("general/icmp", (0, "icmp")), ("package", (0, "")), ("99999/tcp", (65535, "tcp"))],
)
def test_port_forms(port, expected):
    finding = parse(report(result(port=port))).hosts[0].findings[0]
    assert (finding.port, finding.protocol) == expected


def test_unfinished_scan_is_refused():
    with pytest.raises(ScanParseError, match="did not finish"):
        parse(report(result(), status="Stopped"))


def test_unfinished_hosts_and_errored_checks_are_recorded():
    hosts = """
      <host><ip>10.0.0.5</ip><start>2026-11-20T06:00:00Z</start><end></end></host>
      <host><ip>10.0.0.6</ip><start>2026-11-20T06:00:00Z</start><end>2026-11-20T06:10:00Z</end>
        <detail><name>best_os_txt</name><value>Debian 12</value></detail></host>"""
    errors = """
      <error><host>10.0.0.6<asset asset_id=""/></host><port>22/tcp</port>
        <description>NVT timed out after 320 seconds.</description>
        <nvt oid="1.3.6.1.4.1.25623.1.0.555"><name>Slow check</name></nvt></error>"""

    scan = parse(report(result(ip="10.0.0.5"), hosts=hosts, errors=errors))

    by_ip = {h.ip: h for h in scan.hosts}
    assert not by_ip["10.0.0.5"].complete
    assert by_ip["10.0.0.6"].complete and by_ip["10.0.0.6"].findings == []
    assert by_ip["10.0.0.6"].os == "Debian 12"
    assert by_ip["10.0.0.6"].unchecked == {"1.3.6.1.4.1.25623.1.0.555"}


def test_times_are_stored_as_utc():
    hosts = "<host><ip>10.0.0.5</ip><start>2025-08-22T15:01:38+02:00</start><end>2025-08-22T17:09:57+02:00</end></host>"
    scan = parse(report(result(), hosts=hosts))
    assert scan.hosts[0].scan_start == datetime(2025, 8, 22, 13, 1, 38)
    assert scan.hosts[0].scan_end == datetime(2025, 8, 22, 15, 9, 57)


def test_rejects_external_entities():
    data = b"""<?xml version="1.0"?>
<!DOCTYPE report [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<report id="x"><report><results>&xxe;</results></report></report>"""
    with pytest.raises(ScanParseError, match="not allowed"):
        parse(data)


def test_rejects_entity_expansion_bombs():
    data = b"""<?xml version="1.0"?>
<!DOCTYPE report [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>
<report id="x"><report><results>&b;</results></report></report>"""
    with pytest.raises(ScanParseError, match="not allowed"):
        parse(data)


def test_untrusted_values_are_cleaned_and_capped():
    refs = "".join(f'<ref type="cve" id="CVE-2024-{n:05d}"/>' for n in range(300))
    refs += '<ref type="cve" id="not-a-cve"/><ref type="url" id="https://example.invalid"/>'
    finding = parse(
        report(result(description="x" * 20_000, refs=refs, name="n" * 1000, severity="15"))
    ).hosts[0].findings[0]

    assert len(finding.plugin_output) == 8000
    assert len(finding.plugin_name) == 512
    assert len(finding.cves) == 200 and all(c.startswith("CVE-") for c in finding.cves)
    assert finding.cvss_base == 10.0 and finding.severity == 4


def test_older_gmp_cve_element_is_read():
    finding = parse(
        report(result(refs="", extra_nvt="<cve>CVE-2020-1234, CVE-2020-5678, NOCVE</cve>"))
    ).hosts[0].findings[0]
    assert finding.cves == ["CVE-2020-1234", "CVE-2020-5678"]


def test_files_that_are_not_reports_are_refused():
    with pytest.raises(ScanParseError, match="not an OpenVAS XML report"):
        parse(b"<get_tasks_response status='200'/>")
    with pytest.raises(ScanParseError, match="no results section"):
        parse(b'<report id="x" format_id="y"><name>PDF</name></report>')


def test_wrapped_text_is_tidied():
    text = "Multiple flaws exist due\n  to:\n\n  - first item\n\n  - second\n    item\n\nLast paragraph."
    assert tidy(text) == "Multiple flaws exist due to:\n- first item\n- second item\n\nLast paragraph."


@pytest.mark.parametrize(
    ("head", "expected"),
    [
        (b'<?xml version="1.0"?>\n<!-- a -->\n<!-- b -->\n<report id="x">', True),
        (b"  <get_reports_response status='200'>", True),
        (b"<report/>", True),
        (b"<reports>", False),
        (b"<!-- never closed <report>", False),
        (b"<?xml version='1.0'", False),
        (b"<NessusClientData_v2>", False),
    ],
)
def test_sniffing_recognises_openvas_reports(head, expected):
    assert OpenVasParser.looks_like(head) is expected


def test_sniffing_takes_linear_time_on_hostile_input():
    """A crafted start of file once made the old regular expression backtrack for ages."""
    import time

    for head in (b"<!--" * 1024, b"<!---->" * 585, b"<!-- " + b"-" * 4090):
        started = time.perf_counter()
        assert OpenVasParser.looks_like(head) is False
        assert time.perf_counter() - started < 0.05


def test_format_is_detected_from_the_first_bytes():
    with OPENVAS_DEMOS[0].open("rb") as handle:
        assert parse_scan(handle).source == "openvas"
    with DEMO_SCANS[0].open("rb") as handle:
        assert parse_scan(handle).source == "nessus"
    with pytest.raises(ScanParseError, match="not a supported scan report"):
        parse_scan(io.BytesIO(b"<?xml version='1.0'?><nmaprun/>"))
