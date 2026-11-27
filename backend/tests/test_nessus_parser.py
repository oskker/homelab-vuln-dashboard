import io
from datetime import datetime

import pytest

from app.parsers import NessusParser, ScanParseError

from .conftest import DEMO_SCANS


def parse(data: bytes):
    return NessusParser().parse(io.BytesIO(data))


def wrap(report_items: str, host_props: str = "") -> bytes:
    return f"""<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="unit test">
    <ReportHost name="10.0.0.5">
      <HostProperties>
        <tag name="host-ip">10.0.0.5</tag>
        {host_props}
      </HostProperties>
      {report_items}
    </ReportHost>
  </Report>
</NessusClientData_v2>""".encode()


def test_parses_demo_scan():
    with DEMO_SCANS[0].open("rb") as handle:
        scan = NessusParser().parse(handle)

    assert scan.source == "nessus"
    assert scan.report_name.startswith("Home lab weekly")
    assert len(scan.hosts) == 6

    media = next(h for h in scan.hosts if h.ip == "192.168.50.30")
    assert media.hostname == "MEDIA01"
    assert media.fqdn == "media01.home.arpa"
    assert media.os == "Ubuntu 22.04 LTS"
    assert media.scan_end == datetime(2026, 11, 8, 9, 41, 41)

    log4shell = next(f for f in media.findings if f.plugin_id == "900001")
    assert log4shell.severity == 4
    assert log4shell.port == 8080
    assert log4shell.protocol == "tcp"
    assert log4shell.cvss_base == 10.0
    assert log4shell.cves == ["CVE-2021-44228"]
    assert log4shell.exploit_available is True
    assert "Log4j" in log4shell.description


def test_prefers_cvss3_and_falls_back_to_cvss2():
    scan = parse(
        wrap(
            """
        <ReportItem port="80" svc_name="www" protocol="tcp" severity="3" pluginID="1" pluginName="both">
          <cvss_base_score>5.0</cvss_base_score><cvss3_base_score>7.5</cvss3_base_score>
        </ReportItem>
        <ReportItem port="81" svc_name="www" protocol="tcp" severity="2" pluginID="2" pluginName="v2 only">
          <cvss_base_score>4.3</cvss_base_score>
        </ReportItem>
        <ReportItem port="82" svc_name="www" protocol="tcp" severity="2" pluginID="3" pluginName="junk">
          <cvss3_base_score>eleven</cvss3_base_score>
        </ReportItem>"""
        )
    )
    scores = {f.plugin_id: f.cvss_base for f in scan.hosts[0].findings}
    assert scores == {"1": 7.5, "2": 4.3, "3": None}


def test_cleans_untrusted_values():
    scan = parse(
        wrap(
            f"""
        <ReportItem port="99999" svc_name="www" protocol="TCP" severity="42" pluginID="7" pluginName="clamp me">
          <cve>CVE-2024-12345</cve><cve>cve-2024-12345</cve><cve>not-a-cve</cve>
          <cve>CVE-2024-1'; DROP TABLE findings;--</cve>
          <plugin_output>{"A" * 20000}</plugin_output>
        </ReportItem>"""
        )
    )
    finding = scan.hosts[0].findings[0]
    assert finding.severity == 4
    assert finding.port == 65535
    assert finding.protocol == "tcp"
    assert finding.cves == ["CVE-2024-12345"]
    assert len(finding.plugin_output) == 8000


def test_reads_epoch_timestamps_when_text_time_is_missing():
    scan = parse(wrap("", '<tag name="HOST_END_TIMESTAMP">1794130901</tag>'))
    assert scan.hosts[0].scan_end is not None
    assert scan.hosts[0].scan_end.year == 2026


def test_rejects_external_entities():
    xxe = b"""<?xml version="1.0"?>
<!DOCTYPE NessusClientData_v2 [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<NessusClientData_v2><Report name="&xxe;"></Report></NessusClientData_v2>"""
    with pytest.raises(ScanParseError):
        parse(xxe)


def test_rejects_entity_expansion_bombs():
    bomb = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]>
<NessusClientData_v2><Report name="&b;"></Report></NessusClientData_v2>"""
    with pytest.raises(ScanParseError):
        parse(bomb)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"this is not xml",
        b"<?xml version='1.0'?><nmaprun></nmaprun>",
        b"<NessusClientData_v2><Report>",
    ],
)
def test_rejects_files_that_are_not_nessus_exports(data):
    with pytest.raises(ScanParseError):
        parse(data)
