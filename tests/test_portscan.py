import asyncio
import ssl
import urllib.error
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

import lab
import portscan
from certinfo import parse_cert
from findings import assess, attack_url
from fingerprint import fingerprint
from nvd import NVDClient, build_cpe, build_query, parse_response, severity
from report import render_html


@pytest.mark.parametrize(
    "raw,expected",
    [
        (b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n", ("ssh", "OpenSSH", "8.9p1")),
        (b"SSH-2.0-dropbear_2020.81\r\n", ("ssh", "Dropbear", "2020.81")),
        (b"SSH-2.0-weirdssh\r\n", ("ssh", None, None)),
        (b"220 (vsFTPd 3.0.3)\r\n", ("ftp", "vsftpd", "3.0.3")),
        (b"220 ProFTPD 1.3.5e Server ready.\r\n", ("ftp", "ProFTPD", "1.3.5e")),
        (b"220 mail.example.com ESMTP Postfix\r\n", ("smtp", "Postfix", None)),
        (b"220 host ESMTP Exim 4.94.2 Tue\r\n", ("smtp", "Exim", "4.94.2")),
        (b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n\r\n", ("http", "nginx", "1.18.0")),
        (b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\n\r\n", ("http", "Apache httpd", "2.4.52")),
        (b"HTTP/1.0 200 OK\r\nServer: gunicorn/20.1.0\r\n\r\n", ("http", "gunicorn", "20.1.0")),
        (b"HTTP/1.1 404 Not Found\r\n\r\n", ("http", None, None)),
        (b"+PONG\r\n", ("redis", "Redis", None)),
        (lab.mysql_handshake(), ("mysql", "MySQL", "5.7.30")),
        (lab.mysql_handshake(b"5.5.5-10.6.12-MariaDB"), ("mysql", "MariaDB", "10.6.12")),
        (lab.TELNET_BANNER, ("telnet", None, None)),
        (b"\x16\x03\x01garbage", (None, None, None)),
        (b"", (None, None, None)),
    ],
)
def test_fingerprint(raw, expected):
    fp = fingerprint(raw)
    assert (fp.service, fp.product, fp.version) == expected


def test_parse_ports():
    assert portscan.parse_ports("80,22,20-22") == [20, 21, 22, 80]
    for bad in ("0", "70000", "9-3", "abc", ""):
        with pytest.raises(ValueError):
            portscan.parse_ports(bad)


def test_authorization_guard(capsys):
    assert portscan.is_internal("127.0.0.1")
    assert portscan.is_internal("192.168.1.10")
    assert portscan.is_internal("::1")
    assert not portscan.is_internal("8.8.8.8")
    assert portscan.main(["8.8.8.8", "-p", "80"]) == 2
    assert "refusing to scan" in capsys.readouterr().err


SAMPLE_NVD = {
    "totalResults": 3,
    "vulnerabilities": [
        {"cve": {"id": "CVE-0000-0002", "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "medium one"}],
                 "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.5}}]}}},
        {"cve": {"id": "CVE-0000-0001", "descriptions": [{"lang": "en", "value": "critical one"}],
                 "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 9.8}}]}}},
        {"cve": {"id": "CVE-0000-0003", "descriptions": [], "metrics": {}}},
        {"nonsense": True},
    ],
}


def test_nvd_parse_ranks_by_score_and_tolerates_gaps():
    out = parse_response(SAMPLE_NVD, top=10)
    assert [c["id"] for c in out["cves"]] == ["CVE-0000-0001", "CVE-0000-0002", "CVE-0000-0003"]
    assert out["cves"][0]["severity"] == "CRITICAL"
    assert out["cves"][1]["summary"] == "medium one"
    assert out["cves"][2]["score"] is None
    assert severity(7.0) == "HIGH" and severity(3.9) == "LOW"


def test_nvd_query_cache_and_errors(tmp_path):
    calls = []

    def fake_fetch(url):
        calls.append(url)
        return SAMPLE_NVD

    client = NVDClient(cache_path=str(tmp_path / "c.json"), fetch=fake_fetch, use_cpe=False)
    assert build_query("OpenSSH", "8.2p1") == "OpenSSH 8.2"
    first = client.lookup("OpenSSH", "8.2p1", top=1)
    second = client.lookup("OpenSSH", "8.2p1", top=1)
    assert len(calls) == 1 and not first["cached"] and second["cached"]
    assert "keywordSearch=OpenSSH+8.2" in calls[0] and first["method"] == "keyword"

    def boom(url):
        raise urllib.error.URLError("no network")

    bad = NVDClient(cache_path=str(tmp_path / "d.json"), fetch=boom).lookup("nginx", "1.18.0")
    assert bad["error"].startswith("network error") and bad["cves"] == []

    def limited(url):
        raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)

    rl = NVDClient(cache_path=str(tmp_path / "e.json"), fetch=limited).lookup("nginx", "1.18.0")
    assert "rate limited" in rl["error"]


def test_scan_finds_and_fingerprints_lab_services():
    async def run():
        servers, ports = await lab.start_lab(ports={k: 0 for k in lab.LAB_PORTS})
        try:
            closed_port = 1  # nothing listens here
            # Windows retries a refused connect for ~2 s before reporting it, so allow 3 s.
            results = await portscan.scan("127.0.0.1", sorted(ports.values()) + [closed_port], timeout=3.0)
        finally:
            for s in servers:
                s.close()
        return ports, results

    ports, results = asyncio.run(run())
    by_port = {r.port: r for r in results}
    assert by_port[1].state == "closed"
    got = {name: (by_port[p].state, by_port[p].product, by_port[p].version) for name, p in ports.items()}
    expected = {
        "ssh": ("open", "OpenSSH", "8.2p1"),
        "http": ("open", "Apache httpd", "2.4.49"),
        "ftp": ("open", "vsftpd", "3.0.3"),
        "smtp": ("open", "Postfix", None),
        "mysql": ("open", "MySQL", "5.7.30"),
        "telnet": ("open", None, None),
    }
    if "https" in ports:  # needs openssl to mint the lab certificate
        expected["https"] = ("open", "nginx", "1.18.0")
        https = by_port[ports["https"]]
        # A random port is not in TLS_PORTS, so this proves the TLS auto-detection fallback.
        assert https.service == "https" and https.tls and https.cert["subject"] == "lab.local"
        assert https.cert["self_signed"]
    assert got == expected
    assert by_port[ports["telnet"]].service == "telnet"
    assert any(f.title.startswith("Telnet") for f in by_port[ports["telnet"]].findings)


# ---------------------------------------------------------------- CPE matching

def test_build_cpe():
    assert build_cpe("OpenSSH", "8.2p1") == "cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*"
    assert build_cpe("ProFTPD", "1.3.5e") == "cpe:2.3:a:proftpd:proftpd:1.3.5:e:*:*:*:*:*:*"
    assert build_cpe("nginx", "1.18.0") == "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"
    assert build_cpe("gunicorn", "20.1.0") is None  # unmapped product
    assert build_cpe("OpenSSH", "") is None


def test_cpe_lookup_and_404_fallback(tmp_path):
    calls = []

    def fetch(url):
        calls.append(url)
        return SAMPLE_NVD

    out = NVDClient(cache_path=str(tmp_path / "a.json"), fetch=fetch).lookup("Apache httpd", "2.4.49")
    assert out["method"] == "cpe" and "cpeName=cpe%3A2.3%3Aa%3Aapache%3Ahttp_server%3A2.4.49" in calls[0]

    def reject_cpe(url):
        calls.append(url)
        if "cpeName" in url:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        return SAMPLE_NVD

    calls.clear()
    out = NVDClient(cache_path=str(tmp_path / "b.json"), fetch=reject_cpe).lookup("OpenSSH", "8.2p1")
    assert out["method"] == "keyword" and out["error"] is None and len(calls) == 2

    calls.clear()
    out = NVDClient(cache_path=str(tmp_path / "c.json"), fetch=fetch).lookup("gunicorn", "20.1.0")
    assert out["method"] == "keyword" and "keywordSearch" in calls[0]


# ---------------------------------------------------------------- TLS certificates

# Self-signed certificate for lab.local (public half only; the key was discarded).
LAB_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDTDCCAjSgAwIBAgIUXn3NBxoCjiw3uch3BJ+W4n7+9fAwDQYJKoZIhvcNAQEL
BQAwIjESMBAGA1UEAwwJbGFiLmxvY2FsMQwwCgYDVQQKDANMYWIwHhcNMjYxMTAy
MDgwMzAzWhcNMjYxMjAyMDgwMzAzWjAiMRIwEAYDVQQDDAlsYWIubG9jYWwxDDAK
BgNVBAoMA0xhYjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANY2ZbTp
yEjU+i5xECwDMx0wB70OMkoQfeuYaMcZPATvHdHwxSPyBhm8NqCLGWKkpkHfx4cF
ayJStsYiC9xldPBojGwUqITRLuLW//jCmqxrJVKMhj4U/k1EAq6TWzWdgILPye2r
7lchA8zaZNIfrQXOoOqgu+rtFZBd9oQHRrCo0p1bQa2r9/7cRtdTTTIwKI0y9xvk
XdEcwmMzuMCnKBhKwl4cyc69UHIM1AHXf37QUM2OcNxHXemHrhg2petkZVu5nudr
494402YgojLn9kQKiHnqsJiKpWh0C9jy/5qOVLdj5bQ/X7CX8CxjJA1MxB80d9wa
OdTIXpV7GTp9DdsCAwEAAaN6MHgwHQYDVR0OBBYEFJEx+t81ko/VgmJfpudoy/XH
+S70MB8GA1UdIwQYMBaAFJEx+t81ko/VgmJfpudoy/XH+S70MA8GA1UdEwEB/wQF
MAMBAf8wJQYDVR0RBB4wHIIJbGFiLmxvY2Fsgglsb2NhbGhvc3SHBH8AAAEwDQYJ
KoZIhvcNAQELBQADggEBAEZYUYyZR8yCLpJExvBU6EIQSOLkC08SzC2DQyeRsRyj
vLI6NoaUrJwJVBnLEBTQc4c8e9xAo4jW6/vF2uchsJFVIrPlBMuScp8ek8EBWuwM
/Z/y3GCc0S4F3DY1pyA2OdBOi/fSurhH/ds5IVMRaJx+Q8Wam+KPeFNHmAVg9CcT
kAwWFCEurFmApP0Mo6aDogxkaeneGyEkhUIbNX5iWq3yXLHrfRMR1QAh9wJrIU9I
r7JXugEdlMIF5c/j1sygbe2QUzPa3ONZHcS3uHm4BXKKT/JA4wKCQ0Pbzg2vTUH1
lR/kDE6VMDHzYjwgEfoA42Zo7wRhX10N2jNd1FIVsJY=
-----END CERTIFICATE-----
"""


def test_parse_cert():
    der = ssl.PEM_cert_to_DER_cert(LAB_CERT_PEM)
    now = datetime(2026, 11, 20, tzinfo=timezone.utc)
    c = parse_cert(der, now=now)
    assert c["subject"] == "lab.local" and c["issuer"] == "lab.local" and c["self_signed"]
    assert c["sans"] == ["lab.local", "localhost", "127.0.0.1"]
    # Certificate text is attacker-controlled: an ANSI escape must not reach the terminal.
    evil = der.replace(b"lab.local", b"\x1b[2Jlocal")  # same length, so the DER stays valid
    assert parse_cert(evil, now=now)["subject"] == "?[2Jlocal"
    assert c["not_after"].startswith("2026-12-02") and c["days_left"] == 12 and not c["expired"]
    assert parse_cert(der, now=datetime(2027, 1, 1, tzinfo=timezone.utc))["expired"]
    for junk in (b"", b"\x30\x82\xff\xff", der[:100], b"not a cert"):
        assert parse_cert(junk) is None


# ---------------------------------------------------------------- findings

def port(**kw):
    base = dict(port=1, state="open", service=None, product=None, version=None, banner="", tls=None,
                cert=None, cves=[], cve_total=0)
    return SimpleNamespace(**{**base, **kw})


def titles(r):
    return [(f.severity, f.title) for f in assess(r)]


def test_findings_rules():
    assert assess(port(state="closed", service="telnet")) == []
    assert ("HIGH", "Telnet: cleartext remote login") in titles(port(service="telnet"))
    assert ("MEDIUM", "FTP without TLS") in titles(port(service="ftp"))
    assert not any("FTP" in t for _, t in titles(port(service="ftp", tls="TLSv1.3")))
    assert ("HIGH", "Redis answers without authentication") in titles(port(service="redis", banner="+PONG"))
    assert ("MEDIUM", "Database reachable over the network (redis)") in titles(port(service="redis", banner="-NOAUTH"))
    assert ("MEDIUM", "Deprecated protocol negotiated (TLSv1)") in titles(port(service="https", tls="TLSv1"))
    expired = {"expired": True, "days_left": -3, "not_after": "2026-01-01T00:00:00+00:00", "self_signed": False}
    assert ("MEDIUM", "TLS certificate expired") in titles(port(service="https", tls="TLSv1.2", cert=expired))

    crit = port(service="http", product="Apache httpd", version="2.4.49", cve_total=100,
                cves=[{"id": "CVE-2021-41773", "score": 9.8, "severity": "CRITICAL"}])
    f = next(f for f in assess(crit) if f.severity == "CRITICAL")
    assert f.attack == ["T1190"] and "CVE-2021-41773" in f.detail
    ssh = assess(port(service="ssh", product="OpenSSH", version="8.2p1"))
    assert ssh[0].attack == ["T1021.004", "T1110"]
    assert attack_url("T1021.004") == "https://attack.mitre.org/techniques/T1021/004/"


# ---------------------------------------------------------------- reporting

def test_html_report_escapes_banners_and_shows_findings():
    r = portscan.PortResult(port=8080, state="open", service="http", product="Apache httpd", version="2.4.49",
                            banner='<script>alert("x")</script>')
    portscan.assess_all([r])
    data = portscan.to_json([r, portscan.PortResult(port=81, state="closed")], "lab", "127.0.0.1", 2, 0.1)
    assert data["closed"] == 1 and data["attack_techniques"][0]["id"] == "T1592.002"
    html = render_html(data)
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "Web server discloses its version" in html and "attack.mitre.org/techniques/T1592/002/" in html
    assert render_html({"target": "x", "open": []})  # older or empty JSON still renders


def test_cli_writes_json_and_html(tmp_path):
    out_json, out_html = tmp_path / "s.json", tmp_path / "s.html"
    assert portscan.main(["127.0.0.1", "-p", "1", "--json", str(out_json), "--html", str(out_html)]) == 0
    assert out_json.exists() and "<!doctype html>" in out_html.read_text(encoding="utf-8")
