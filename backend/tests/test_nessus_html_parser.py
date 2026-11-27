import io
from datetime import datetime

import pytest

from app.parsers import NessusHtmlParser, ParsedScan, ScanParseError, parse_scan
from app.parsers.nessus_html import (
    NOT_A_REPORT,
    WRONG_TEMPLATE_BY_PLUGIN,
    WRONG_TEMPLATE_SUMMARY,
)

from .conftest import DEMO_SCANS, WRITE, upload, upload_bytes
from .html_report import Host, Plugin, build_report, build_summary_report

ICMP = Plugin(
    "10114",
    "ICMP Timestamp Request Remote Date Disclosure",
    severity=2,
    risk_factor="Low",  # Risk Factor follows CVSS v2; the colour follows the scan's severity
    description="The remote host answers to an ICMP timestamp request.<br><br>Second paragraph.",
    cvss3="4.0 (CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)",
    cvss2="2.1 (CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N)",
    cves=["CVE-1999-0524", "CVE-1999-0524"],
    xrefs=['<a href="http://cwe.mitre.org/data/definitions/200">CWE:200</a>', "IAVT:0001-T-0030"],
    ports=[("icmp/0", "The difference between the local and remote clocks is 11 seconds.")],
)

CERT = Plugin(
    "51192",
    "SSL Certificate Cannot Be Trusted",
    severity=2,
    cvss3="6.5 (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)",
    ports=[
        (
            "tcp/443/www",
            "The following certificate<br>chain is untrusted :<br> <br>|-Subject : CN=demo",
        ),
        ("tcp/8443/www", "Same problem on the admin port."),
    ],
)

SERVICE = Plugin(
    "22964",
    "Service Detection",
    severity=0,
    risk_factor="None",
    ports=[
        ("tcp/443/www", "A TLSv1.3 server answered on this port."),
        ("tcp/443/www", "A web server is running on this port through TLSv1.3."),
        ("tcp/53/dns", None),
    ],
)


def parse(text: str) -> ParsedScan:
    return NessusHtmlParser().parse(io.BytesIO(text.encode("utf-8")))


def report(*plugins: Plugin, **host_kwargs) -> str:
    host_kwargs.setdefault("info", {"DNS Name:": "nvr.home.arpa", "OS:": "Embedded Linux"})
    return build_report([Host("10.0.0.40", list(plugins), **host_kwargs)])


def by_key(scan: ParsedScan) -> dict[tuple[str, int, str], object]:
    return {(f.plugin_id, f.port, f.protocol): f for h in scan.hosts for f in h.findings}


def test_reads_host_details_and_scan_times():
    scan = parse(
        report(
            ICMP,
            info={
                "DNS Name:": "nvr.home.arpa",
                "Netbios Name:": "CAM-NVR",
                "MAC Address:": "02:00:5E:10:00:28",
                "OS:": "Embedded Linux",
            },
        )
    )

    assert scan.source == "nessus"  # same source as .nessus imports, so history carries over
    assert scan.report_name == "Demo"
    [host] = scan.hosts
    assert host.ip == "10.0.0.40"
    assert host.hostname == "CAM-NVR"
    assert host.fqdn == "nvr.home.arpa"
    assert host.os == "Embedded Linux"
    assert host.mac == "02:00:5E:10:00:28"
    assert host.scan_start == datetime(2026, 11, 22, 9, 30)
    assert host.scan_end == datetime(2026, 11, 22, 9, 41, 12)


def test_hostname_falls_back_to_the_dns_name():
    [host] = parse(report(ICMP)).hosts

    assert host.hostname == "nvr.home.arpa"


def test_reads_a_finding_with_scores_and_references():
    finding = by_key(parse(report(ICMP)))[("10114", 0, "icmp")]

    assert finding.plugin_name == "ICMP Timestamp Request Remote Date Disclosure"
    assert finding.severity == 2  # from the title colour, not the "Low" risk factor
    assert finding.cvss_base == 4.0  # CVSS v3 preferred over v2
    assert finding.cvss_vector == "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
    assert finding.cves == ["CVE-1999-0524"]
    assert finding.description == (
        "The remote host answers to an ICMP timestamp request.\n\nSecond paragraph."
    )
    assert finding.solution == "Solution text."
    assert (
        finding.plugin_output == "The difference between the local and remote clocks is 11 seconds."
    )
    assert finding.exploit_available is False  # the HTML report does not include it


def test_one_finding_per_port_and_duplicate_ports_are_merged():
    findings = by_key(parse(report(CERT, SERVICE)))

    assert set(findings) == {
        ("51192", 443, "tcp"),
        ("51192", 8443, "tcp"),
        ("22964", 443, "tcp"),
        ("22964", 53, "tcp"),
    }
    assert findings[("51192", 443, "tcp")].service == "www"
    assert findings[("51192", 443, "tcp")].plugin_output == (
        "The following certificate\nchain is untrusted :\n\n|-Subject : CN=demo"
    )
    assert findings[("22964", 443, "tcp")].plugin_output == (
        "A TLSv1.3 server answered on this port.\n\n"
        "A web server is running on this port through TLSv1.3."
    )
    assert findings[("22964", 53, "tcp")].plugin_output == ""
    assert findings[("22964", 443, "tcp")].severity == 0


def test_cvss_v2_is_used_when_v3_is_missing_and_bad_scores_are_dropped():
    v2_only = Plugin("1", "v2 only", cvss2="4.3 (CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N)")
    broken = Plugin("2", "broken", cvss3="eleven (nope)")
    findings = by_key(parse(report(v2_only, broken)))

    assert findings[("1", 443, "tcp")].cvss_base == 4.3
    assert findings[("1", 443, "tcp")].cvss_vector == "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
    assert findings[("2", 443, "tcp")].cvss_base is None


def test_severity_falls_back_to_the_risk_factor_without_a_colour():
    plain = Plugin("3", "No colour", severity=None, risk_factor="High")

    assert by_key(parse(report(plain)))[("3", 443, "tcp")].severity == 3


def test_markup_in_scanner_output_stays_text():
    hostile = Plugin(
        "4",
        "Banner <b>bold</b>",  # the report builder escapes titles, as Nessus does
        ports=[
            (
                "tcp/80/www",
                "Server: &lt;img src=x onerror=alert(1)&gt;<br>"
                "<script>alert('raw tags lose their markup')</script>",
            )
        ],
    )
    finding = by_key(parse(report(hostile)))[("4", 80, "tcp")]

    assert finding.plugin_name == "Banner <b>bold</b>"
    assert finding.plugin_output == (
        "Server: <img src=x onerror=alert(1)>\nalert('raw tags lose their markup')"
    )


def test_text_between_hosts_does_not_leak_into_the_previous_finding():
    hosts = [
        Host("10.0.0.1", [CERT]),
        Host("10.0.0.2", [ICMP], start="Sun Nov 22 10:00:00 2026", end="Sun Nov 22 10:05:00 2026"),
    ]
    scan = parse(build_report(hosts))

    assert [h.ip for h in scan.hosts] == ["10.0.0.1", "10.0.0.2"]
    last_of_first_host = scan.hosts[0].findings[-1]
    assert last_of_first_host.plugin_output == "Same problem on the admin port."
    assert [f.plugin_id for f in scan.hosts[1].findings] == ["10114"]
    assert scan.hosts[1].scan_end == datetime(2026, 11, 22, 10, 5)


def test_long_output_is_capped():
    huge = Plugin("5", "Huge", ports=[("tcp/80/www", "A" * 50_000)])

    assert len(by_key(parse(report(huge)))[("5", 80, "tcp")].plugin_output) == 8000


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (build_summary_report("10.0.0.40"), WRONG_TEMPLATE_SUMMARY),
        (
            build_report([Host("10.0.0.40", [ICMP])], heading="Vulnerabilities by Plugin"),
            WRONG_TEMPLATE_BY_PLUGIN,
        ),
        ("<html><body><h1>My holiday photos</h1></body></html>", NOT_A_REPORT),
        ("<html></html>", NOT_A_REPORT),
    ],
)
def test_wrong_reports_get_a_clear_message(text, message):
    with pytest.raises(ScanParseError) as error:
        parse(text)

    assert str(error.value) == message


def test_format_detection():
    html = report(ICMP).encode()

    assert NessusHtmlParser.looks_like(html)
    assert NessusHtmlParser.looks_like(b"\xef\xbb\xbf  \n<!DOCTYPE html><html>")
    assert not NessusHtmlParser.looks_like(DEMO_SCANS[0].read_bytes()[:4096])
    assert parse_scan(io.BytesIO(html)).hosts[0].ip == "10.0.0.40"
    with DEMO_SCANS[0].open("rb") as handle:
        assert len(parse_scan(handle).hosts) == 6


def test_html_report_upload_continues_the_history_of_nessus_imports(client):
    """Findings from an HTML report line up with the same findings from a .nessus export."""
    assert upload(client, DEMO_SCANS[0]).status_code == 201
    nas = Host(
        "192.168.50.10",
        [
            Plugin(
                "900002",
                "Windows SMBv1 remote code execution (EternalBlue)",
                severity=3,
                ports=[("tcp/445/cifs", "still vulnerable")],
            ),
            Plugin("900008", "SMB signing not required", ports=[("tcp/445/cifs", "not required")]),
            Plugin("900090", "Scan information", severity=0, ports=[("tcp/0", "info")]),
        ],
        start="Sun Nov 15 09:30:00 2026",
        end="Sun Nov 15 09:35:00 2026",
    )

    response = upload_bytes(client, build_report([nas]).encode(), name="nas-report.html")

    assert response.status_code == 201, response.text
    body = response.json()
    assert (body["new"], body["fixed"], body["reopened"]) == (0, 2, 0)  # Apache and TLS cert gone
    assert body["filename"] == "nas-report.html"


def test_wrong_template_upload_explains_what_to_do(client):
    response = upload_bytes(client, build_summary_report("10.0.0.40").encode(), name="summary.html")

    assert response.status_code == 400
    assert "Detailed Vulnerabilities By Host" in response.json()["detail"]
    assert client.get("/api/scans", headers=WRITE).json() == []
