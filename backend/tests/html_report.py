"""Builds synthetic Nessus HTML reports for the tests.

The markup copies the structure of a real "Detailed Vulnerabilities By Host" report
(element ids, classes and the inline styles the parser relies on). All content is made
up; no real scan data is stored in the repository.
"""

from dataclasses import dataclass, field
from html import escape

COLOURS = {4: "#91243E", 3: "#DD4B50", 2: "#F18C43", 1: "#F8C851", 0: "#67ACE1"}
TEXT_STYLE = "line-height: 20px; padding: 0 0 20px 0; overflow-wrap: break-word;"
OUTPUT_STYLE = (
    "box-sizing: border-box; width: 100%; background: #eee; overflow-wrap: break-word; "
    "font-family: monospace; padding: 20px; margin: 5px 0 20px 0;"
)


@dataclass
class Plugin:
    plugin_id: str
    name: str
    severity: int | None = 2  # None leaves the title bar without a colour
    risk_factor: str = "Medium"
    synopsis: str = "Synopsis text."
    description: str = "Description text."
    solution: str = "Solution text."
    cvss3: str | None = None  # e.g. "6.5 (CVSS:3.0/AV:N/...)"
    cvss2: str | None = None
    cves: list[str] = field(default_factory=list)
    xrefs: list[str] = field(default_factory=list)
    # (port label, output or None). Outputs are inserted as-is, so they may hold markup.
    ports: list[tuple[str, str | None]] = field(default_factory=lambda: [("tcp/443/www", "x")])


@dataclass
class Host:
    ip: str
    plugins: list[Plugin]
    start: str = "Sun Nov 22 09:30:00 2026"
    end: str = "Sun Nov 22 09:41:12 2026"
    info: dict[str, str] = field(default_factory=dict)  # extra rows such as "OS:"


class _Ids:
    def __init__(self) -> None:
        self.value = 1

    def __call__(self) -> str:
        self.value += 1
        return f"id{self.value}"


def _header(label: str) -> str:
    return f'<div class="details-header">{label}<div class="clear"></div>\n</div>\n'


def _text(label: str, value: str) -> str:
    return _header(label) + f'<div style="{TEXT_STYLE}">{value}<div class="clear"></div>\n</div>\n'


def _table(ids: _Ids, rows: list[tuple[str, str]], css: str = "table-wrapper details") -> str:
    body = "".join(
        f'<tr class="">\n<td class="#ffffff" style=" " colspan="1">{a}</td>\n'
        f'<td class="#ffffff" style=" " colspan="1">{b}</td>\n</tr>\n'
        for a, b in rows
    )
    return (
        f'<div id="{ids()}" class="{css}">\n<table cellpadding="0" cellspacing="0">\n'
        f'<thead><tr>\n<th width="20%"></th>\n<th width="80%"></th>\n</tr></thead>\n'
        f'<tbody>\n{body}</tbody>\n</table>\n<div class="clear"></div>\n</div>\n'
    )


def _counts(ids: _Ids, host: Host) -> str:
    cells = "".join(
        f'<td class="{COLOURS[s]}" style=" " colspan="1"><div style="font-size: 45px; '
        f'background: {COLOURS[s]};">{sum(1 for p in host.plugins if p.severity == s)}</div></td>\n'
        for s in (4, 3, 2, 1, 0)
    )
    return (
        f'<div id="{ids()}" style="display: block;" class="table-wrapper ">\n<table>\n'
        f'<tbody>\n<tr class="">\n{cells}</tr>\n</tbody>\n</table>\n<div class="clear"></div>\n</div>\n'
    )


def _plugin(ids: _Ids, plugin: Plugin) -> str:
    section = ids()
    colour = f" background: {COLOURS[plugin.severity]};" if plugin.severity is not None else ""
    out = [
        '<h2 class=""></h2>\n',
        f'<div id="{section}" style="box-sizing: border-box; width: 100%; padding: 5px 10px;'
        f'{colour} font-weight: 700; color: #fff;" class="" '
        f"onclick=\"toggleSection('{section}-container');\" "
        f"onmouseover=\"this.style.cursor='pointer'\">{escape(plugin.plugin_id)} - "
        f'{escape(plugin.name)}<div id="{section}-toggletext" style="float: right;">\n'
        "                -\n            </div>\n</div>\n",
        f'<div id="{section}-container" style="margin: 0 0 45px 0;" class="section-wrapper">\n',
        _text("Synopsis", plugin.synopsis),
        _text("Description", plugin.description),
        _text("Solution", plugin.solution),
        _text("Risk Factor", plugin.risk_factor),
    ]
    if plugin.cvss3:
        out.append(_text("CVSS v3.0 Base Score", plugin.cvss3))
    if plugin.cvss2:
        out.append(_text("CVSS v2.0 Base Score", plugin.cvss2))
    refs = [
        ("CVE", f'<a href="http://web.nvd.nist.gov/view/vuln/detail?vulnId={c}">{c}</a>')
        for c in plugin.cves
    ] + [("XREF", x) for x in plugin.xrefs]
    if refs:
        out.append(_header("References") + _table(ids, refs, "table-wrapper see-also"))
    out.append(_text("Plugin Information", "Published: 2020/01/01, Modified: 2026/11/01"))
    out.append(_header("Plugin Output"))
    for label, output in plugin.ports:
        out.append(f'<h2>{label}</h2>\n<div class="clear"></div>\n')
        if output is not None:
            out.append(f'<div style="{OUTPUT_STYLE}">{output}<div class="clear"></div>\n</div>\n')
        out.append('<div class="clear"></div>\n')
    out.append('<div class="clear"></div>\n</div>\n<div class="clear"></div>\n')
    return "".join(out)


def build_report(
    hosts: list[Host], heading: str = "Vulnerabilities by Host", title: str = "Demo"
) -> str:
    ids = _Ids()
    toc = "".join(f'<li><a href="#h{i}">{h.ip}</a></li>' for i, h in enumerate(hosts))
    parts = [
        '<html>\n<head>\n<meta http-equiv="Content-Type" content="text/html; charset=utf-8">\n',
        f'<title>{title}</title>\n<script type="text/javascript">var toggle = function (id) {{}};</script>\n',
        '</head>\n<body>\n<div id="report">\n',
        '<header><div style="float: right;"><h2 style="color: #999;">Report generated by Tenable Nessus™</h2></div></header>\n',
        f'<h3 style="font-size: 24px; font-weight: 300;">{title}</h3>\n',
        '<h4 style="color: #999;">Sun, 22 Nov 2026 09:45:00 Pacific Standard Time</h4>\n',
        f"<ul>{toc}</ul>\n",
        f'<h6 id="id1" style="font-size: 22px;">{heading}<span onclick="toggleAll();" class="expand">'
        'Expand All</span><span class="expand-spacer"> | </span><span onclick="toggleAll(true);" '
        'class="expand">Collapse All</span>\n</h6>\n',
    ]
    for host in hosts:
        parts.append(
            f'<div id="{ids()}" style="font-size: 22px; font-weight: 700; padding: 10px 0; '
            f'overflow-wrap: break-word">{host.ip}<div class="clear"></div>\n</div>\n'
        )
        parts.append(_counts(ids, host))
        parts.append(_header("Scan Information"))
        parts.append(_table(ids, [("Start time:", host.start), ("End time:", host.end)]))
        info = {"IP:": host.ip, **host.info}
        parts.append(_header("Host Information"))
        parts.append(_table(ids, list(info.items())))
        parts.append(_header("Vulnerabilities"))
        parts.extend(_plugin(ids, plugin) for plugin in host.plugins)
    parts.append(
        '<div class="clear"></div>\n</div>\n<div style="width: 1024px; text-align: center;">'
        "© 2026 Example footer</div>\n</body>\n</html>\n"
    )
    return "".join(parts)


def build_summary_report(ip: str) -> str:
    """The 'Complete List of Vulnerabilities by Host' template: a table per host, no details."""
    return (
        '<html>\n<body>\n<div id="report">\n<h3 style="font-size: 24px;">Demo</h3>\n'
        '<h6 id="id1">Vulnerabilities by Host<span class="expand">Expand All</span></h6>\n'
        f'<div id="id2" style="font-size: 22px; font-weight: 700;">{ip}<div class="clear"></div>\n</div>\n'
        '<div id="id3" class="table-wrapper "><table><tbody>\n'
        '<tr class="plugin-row-header"><td>Severity</td><td>Plugin</td><td>Name</td></tr>\n'
        '<tr class="plugin-row"><td><span>Medium</span></td><td><a href="#">10114</a></td>'
        "<td>ICMP Timestamp Request Remote Date Disclosure</td></tr>\n"
        "</tbody></table></div>\n</div>\n</body>\n</html>\n"
    )
