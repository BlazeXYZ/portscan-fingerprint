#!/usr/bin/env python3
"""HTML report: one self-contained file (no external CSS, JS or fonts) from scan JSON.

    python3 portscan.py 127.0.0.1 --html report.html      # during a scan
    python3 report.py scan-lab.json -o report.html        # from saved JSON

Banners come from the scanned host, so they are attacker-controlled input:
every value is HTML-escaped before it reaches the page.
"""
from __future__ import annotations

import argparse
import json
import sys
from html import escape

from findings import SEVERITY_ORDER

CSS = """
:root{--bg:#f6f7f9;--panel:#fff;--text:#16181d;--muted:#5d6472;--line:#e3e6eb;--mono-bg:#f0f2f5;
--crit:#b3261e;--high:#d0531a;--med:#a87400;--low:#2f6fb3;--info:#677080;--accent:#3a55c4}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0f1115;--panel:#171a21;--text:#e7e9ee;
--muted:#9aa2b1;--line:#2a2f3a;--mono-bg:#1f232c;--crit:#ff6b5f;--high:#ff8a4c;--med:#e3b341;--low:#6ea8ff;
--info:#9aa2b1;--accent:#8ea2ff}}
:root[data-theme="dark"]{--bg:#0f1115;--panel:#171a21;--text:#e7e9ee;--muted:#9aa2b1;--line:#2a2f3a;--mono-bg:#1f232c;
--crit:#ff6b5f;--high:#ff8a4c;--med:#e3b341;--low:#6ea8ff;--info:#9aa2b1;--accent:#8ea2ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1080px;margin:0 auto;padding:32px 16px 48px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:36px 0 12px}
.meta{color:var(--muted);font-size:13px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:24px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.tile .n{font-size:28px;font-weight:650;line-height:1.1}.tile .l{color:var(--muted);font-size:13px}
.bar{display:flex;height:8px;border-radius:4px;overflow:hidden;margin-top:16px;background:var(--line)}
.legend{display:flex;flex-wrap:wrap;gap:14px;margin-top:8px;font-size:13px;color:var(--muted)}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px;vertical-align:baseline}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:600}
tr:last-child td{border-bottom:0}
code,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px}
.banner{background:var(--mono-bg);padding:2px 6px;border-radius:4px;word-break:break-all}
.pill{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.04em;padding:2px 8px;border-radius:999px;
color:#fff;white-space:nowrap}
.CRITICAL{background:var(--crit)}.HIGH{background:var(--high)}.MEDIUM{background:var(--med)}
.LOW{background:var(--low)}.INFO,.UNKNOWN,.NONE{background:var(--info)}
.detail{color:var(--muted);font-size:13px;margin-top:2px}
.chip{display:inline-block;font-size:12px;border:1px solid var(--line);border-radius:6px;padding:1px 6px;margin:4px 4px 0 0;
color:var(--accent);text-decoration:none}.chip:hover{border-color:var(--accent)}
a{color:var(--accent)}
.svc{margin-top:14px}.svc h3{font-size:15px;margin:0;padding:12px 12px 0}
.badge{font-size:12px;color:var(--muted);font-weight:400;margin-left:6px}
.note{color:var(--muted);font-size:13px;padding:8px 12px 12px}
.certs{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}
.cert{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;font-size:14px}
.cert dl{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;margin:8px 0 0}.cert dt{color:var(--muted)}.cert dd{margin:0}
.warn{color:var(--high);font-weight:600}
footer{margin-top:40px;color:var(--muted);font-size:13px;border-top:1px solid var(--line);padding-top:16px}
@media (max-width:640px){th,td{padding:8px}.tile .n{font-size:22px}h1{font-size:20px}}
"""

SEV_VAR = {"CRITICAL": "--crit", "HIGH": "--high", "MEDIUM": "--med", "LOW": "--low", "INFO": "--info"}


def e(value) -> str:
    return escape("" if value is None else str(value), quote=True)


def pill(sev: str) -> str:
    sev = sev if sev in SEV_VAR or sev in ("UNKNOWN", "NONE") else "UNKNOWN"
    return f'<span class="pill {sev}">{sev}</span>'


def chips(attack: list) -> str:
    return "".join(f'<a class="chip" href="{e(t["url"])}" title="{e(t["name"])}" target="_blank" rel="noopener">'
                   f'{e(t["id"])} {e(t["name"])}</a>' for t in attack)


def _tiles(data: dict, findings: list) -> str:
    services = data.get("open", [])
    cve_total = sum(s.get("cve_total") or 0 for s in services)
    scores = [c["score"] for s in services for c in s.get("cves") or [] if c.get("score") is not None]
    worst = next((s for s in SEVERITY_ORDER if any(f["severity"] == s for _, f in findings)), None)
    tiles = [
        (len(services), f'open of {e(data.get("ports_scanned"))} scanned'),
        (len(findings), f"findings (worst: {worst.lower()})" if worst else "findings"),
        (cve_total, "CVE candidates"),
        (f"{max(scores):.1f}" if scores else "–", "highest CVSS"),
    ]
    return '<div class="tiles">' + "".join(
        f'<div class="tile"><div class="n">{e(n)}</div><div class="l">{label}</div></div>' for n, label in tiles) + "</div>"


def _severity_bar(counts: dict) -> str:
    total = sum(counts.values())
    if not total:
        return ""
    segs = "".join(f'<span style="width:{100 * counts[s] / total:.2f}%;background:var({SEV_VAR[s]})"></span>'
                   for s in SEVERITY_ORDER if counts.get(s))
    legend = "".join(f'<span><span class="dot" style="background:var({SEV_VAR[s]})"></span>{counts.get(s, 0)} {s.lower()}</span>'
                     for s in SEVERITY_ORDER)
    return f'<div class="bar" role="img" aria-label="findings by severity">{segs}</div><div class="legend">{legend}</div>'


def _findings_table(findings: list) -> str:
    if not findings:
        return '<div class="panel"><p class="note">No exposure findings.</p></div>'
    rows = "".join(
        f'<tr><td>{pill(f["severity"])}</td><td class="mono">{port}/tcp</td>'
        f'<td><strong>{e(f["title"])}</strong><div class="detail">{e(f["detail"])}</div>{chips(f["attack"])}</td></tr>'
        for port, f in findings)
    return f'<div class="panel"><table><thead><tr><th>Severity</th><th>Port</th><th>Finding and ATT&amp;CK technique</th></tr></thead><tbody>{rows}</tbody></table></div>'


def _services_table(services: list) -> str:
    if not services:
        return '<div class="panel"><p class="note">No open ports found.</p></div>'
    rows = "".join(
        f'<tr><td class="mono">{e(s["port"])}/tcp</td><td>{e(s.get("service") or "unknown")}</td>'
        f'<td>{e(" ".join(x for x in (s.get("product"), s.get("version")) if x) or "–")}</td>'
        f'<td>{e(s.get("tls") or "–")}</td>'
        f'<td>{"<code class=banner>" + e(s["banner"]) + "</code>" if s.get("banner") else "–"}</td></tr>'
        for s in services)
    return f'<div class="panel"><table><thead><tr><th>Port</th><th>Service</th><th>Product / version</th><th>TLS</th><th>Banner</th></tr></thead><tbody>{rows}</tbody></table></div>'


def _certs(services: list) -> str:
    cards = []
    for s in services:
        c = s.get("cert")
        if not c:
            continue
        flags = [x for x in ("Self-signed" if c.get("self_signed") else "", "Expired" if c.get("expired") else "") if x]
        expiry = f'{e(c["not_after"][:10])} ({e(c["days_left"])} days)'
        if c.get("expired") or (c.get("days_left") or 0) < 30:
            expiry = f'<span class="warn">{expiry}</span>'
        cards.append(
            f'<div class="cert"><strong class="mono">{e(s["port"])}/tcp</strong> {e(s.get("tls") or "")}'
            f'{"".join(f" <span class=warn>· {x}</span>" for x in flags)}<dl>'
            f'<dt>Subject</dt><dd>{e(c.get("subject") or "–")}</dd><dt>Issuer</dt><dd>{e(c.get("issuer") or "–")}</dd>'
            f'<dt>Valid from</dt><dd>{e(c["not_before"][:10])}</dd><dt>Expires</dt><dd>{expiry}</dd>'
            f'<dt>SANs</dt><dd class="mono">{e(", ".join(c.get("sans") or []) or "–")}</dd></dl></div>')
    if not cards:
        return ""
    return "<h2>TLS certificates</h2><div class=\"certs\">" + "".join(cards) + "</div>"


def _cves(services: list) -> str:
    looked_up = [s for s in services if s.get("cve_method") or s.get("cve_error")]
    if not looked_up:
        return ""
    out = ["<h2>CVE candidates</h2>"]
    for s in looked_up:
        method = {"cpe": "CPE match", "keyword": "keyword match (noisier)"}.get(s.get("cve_method"), "")
        head = f'{e(s["port"])}/tcp · {e(s.get("product"))} {e(s.get("version"))}<span class="badge">{method}</span>'
        if s.get("cve_error"):
            body = f'<p class="note">Lookup failed: {e(s["cve_error"])}</p>'
        elif not s.get("cves"):
            body = '<p class="note">No candidates returned.</p>'
        else:
            rows = "".join(
                f'<tr><td class="mono"><a href="https://nvd.nist.gov/vuln/detail/{e(c["id"])}" target="_blank" rel="noopener">{e(c["id"])}</a></td>'
                f'<td class="mono">{"%.1f" % c["score"] if c.get("score") is not None else "n/a"}</td>'
                f'<td>{pill(c.get("severity") or "UNKNOWN")}</td><td>{e(c.get("summary"))}</td></tr>'
                for c in s["cves"])
            body = (f'<table><thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>Summary</th></tr></thead><tbody>{rows}</tbody></table>'
                    f'<p class="note">Top {len(s["cves"])} of {e(s.get("cve_total"))} matches by CVSS score. '
                    'Distro backports are not considered.</p>')
        out.append(f'<div class="panel svc"><h3>{head}</h3>{body}</div>')
    return "".join(out)


def _techniques(data: dict) -> str:
    techs = data.get("attack_techniques") or []
    if not techs:
        return ""
    return ("<h2>MITRE ATT&amp;CK coverage</h2><p class=\"meta\">Techniques an attacker could use against what this scan "
            "found. Detecting them, and the scan itself (" + chips([{"id": "T1046", "name": "Network Service Discovery",
            "url": "https://attack.mitre.org/techniques/T1046/"}]) + "), is the defender's job.</p><div>" + chips(techs) + "</div>")


def render_html(data: dict) -> str:
    services = data.get("open", [])
    findings = [(s["port"], f) for s in services for f in s.get("findings") or []]
    findings.sort(key=lambda pf: (SEVERITY_ORDER.index(pf[1]["severity"]) if pf[1]["severity"] in SEVERITY_ORDER else 99, pf[0]))
    counts = data.get("severity_counts") or {s: sum(f["severity"] == s for _, f in findings) for s in SEVERITY_ORDER}
    target, address = data.get("target"), data.get("address")
    title = f"Scan report · {target}"
    meta = (f'{e(address)} · {e(data.get("scanned_at"))} · {e(data.get("duration_seconds"))}s · '
            f'{e(data.get("closed", 0))} closed, {e(data.get("filtered", 0))} filtered · {e(data.get("tool", "portscan-fingerprint"))}')
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>{CSS}</style></head>
<body><main>
<h1>Scan report: {e(target)}</h1><div class="meta">{meta}</div>
{_tiles(data, findings)}
{_severity_bar(counts)}
<h2>Exposure findings</h2>{_findings_table(findings)}
<h2>Open services</h2>{_services_table(services)}
{_certs(services)}
{_cves(services)}
{_techniques(data)}
<footer>Authorized use only: scan systems you own or have written permission to test. Findings describe exposure,
not confirmed compromise, and CVE matches are candidates to verify against the installed patch level.</footer>
</main></body></html>
"""


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Render a portscan JSON file as a self-contained HTML report.")
    p.add_argument("json_file")
    p.add_argument("-o", "--output", default="report.html")
    args = p.parse_args(argv)
    try:
        with open(args.json_file, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as err:
        print(f"error: cannot read {args.json_file}: {err}", file=sys.stderr)
        return 2
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(render_html(data))
    print(f"HTML report written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
