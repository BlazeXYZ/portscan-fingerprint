#!/usr/bin/env python3
"""portscan: async TCP connect scanner with banner grabbing, service fingerprinting,
TLS certificate inspection, ATT&CK-mapped exposure findings and optional CVE
candidate lookup against the NVD.

Only scan systems you own or are explicitly authorised to test. Private and
loopback addresses are allowed by default; anything else needs --i-own-this.
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

from certinfo import parse_cert
from findings import SEVERITY_ORDER, TECHNIQUES, assess, attack_url, sort_findings
from fingerprint import banner_summary, fingerprint
from nvd import NVDClient

VERSION = "1.1"
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 631, 636,
    993, 995, 1433, 1521, 2049, 2121, 2222, 2375, 3000, 3306, 3389, 5000, 5432, 5900,
    5985, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9200, 11211, 27017,
]
SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 5985: "winrm", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}
HTTP_PORTS = {80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888}
TLS_PORTS = {443, 465, 636, 993, 995, 8443}
USER_AGENT = f"portscan-fingerprint/{VERSION}"


@dataclass
class PortResult:
    port: int
    state: str  # open | closed | filtered
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: str = ""
    tls: Optional[str] = None
    cert: Optional[dict] = None
    cves: list = field(default_factory=list)
    cve_total: int = 0
    cve_method: Optional[str] = None  # cpe | keyword
    cve_error: Optional[str] = None
    findings: list = field(default_factory=list)  # findings.Finding


# ---------------------------------------------------------------- input handling

def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            lo, hi = int(a), int(b)
        else:
            lo = hi = int(part)
        if not (1 <= lo <= hi <= 65535):
            raise ValueError(f"invalid port range: {part!r}")
        ports.update(range(lo, hi + 1))
    if not ports:
        raise ValueError("no ports specified")
    return sorted(ports)


def resolve(target: str) -> str:
    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"cannot resolve {target!r} (this tool scans a single host, not ranges): {e}")
    return infos[0][4][0]


def is_internal(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%")[0])
    return ip.is_private or ip.is_loopback or ip.is_link_local


# ---------------------------------------------------------------- scanning

async def probe_state(host: str, port: int, timeout: float) -> str:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (asyncio.TimeoutError, TimeoutError):
        return "filtered"
    except ConnectionRefusedError:
        return "closed"
    except OSError:
        return "filtered"
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return "open"


def http_probe(host: str) -> bytes:
    return f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\nConnection: close\r\n\r\n".encode()


def tls_context() -> ssl.SSLContext:
    """A context that accepts anything, so old protocols and bad certificates get reported, not rejected."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we are fingerprinting, not trusting
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass  # some OpenSSL builds refuse; the defaults still work for modern servers
    return ctx


def looks_like_tls(data: bytes) -> bool:
    """A TLS alert record (0x15 0x03 ..) in reply to plaintext means a TLS listener."""
    return len(data) >= 2 and data[0] == 0x15 and data[1] == 0x03


async def read_banner(reader: asyncio.StreamReader, first_wait: float, limit: int = 2048) -> bytes:
    try:
        chunk = await asyncio.wait_for(reader.read(limit), first_wait)
    except (asyncio.TimeoutError, TimeoutError, OSError):
        return b""
    buf = chunk
    while chunk and len(buf) < limit:
        try:
            chunk = await asyncio.wait_for(reader.read(limit - len(buf)), 0.15)
        except (asyncio.TimeoutError, TimeoutError, OSError):
            break
        buf += chunk
    return buf


async def grab_banner(host: str, port: int, timeout: float, use_tls: bool = False):
    """Open a fresh connection, listen for a greeting, and probe if the service stays quiet.
    Returns (banner bytes, TLS version or None, certificate dict or None); a failed TLS
    handshake returns TLS version None."""
    ctx = tls_context() if use_tls else None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host if ctx else None),
            timeout,
        )
    except (asyncio.TimeoutError, TimeoutError, OSError, ssl.SSLError):
        return b"", None, None

    tls_version = cert = None
    if ctx:
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj:
            tls_version = ssl_obj.version()
            cert = parse_cert(ssl_obj.getpeercert(binary_form=True) or b"")

    wait = min(timeout, 1.0)
    data = b""
    try:
        if port in HTTP_PORTS:
            writer.write(http_probe(host))
            await writer.drain()
            data = await read_banner(reader, wait)
        else:
            data = await read_banner(reader, wait)  # SSH/FTP/SMTP/MySQL speak first
            if not data:
                # Quiet service: Redis gets PING, anything else gets an HTTP request,
                # since most unidentified listeners on odd ports are web servers.
                probe = b"PING\r\n" if port == 6379 else http_probe(host)
                writer.write(probe)
                await writer.drain()
                data = await read_banner(reader, wait)
    except (OSError, ssl.SSLError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass
    return data, tls_version, cert


async def scan_port(host: str, port: int, timeout: float, sem: asyncio.Semaphore) -> PortResult:
    async with sem:
        state = await probe_state(host, port, timeout)
        if state != "open":
            return PortResult(port, state)
        use_tls = port in TLS_PORTS
        raw, tls, cert = await grab_banner(host, port, timeout, use_tls)
        if not use_tls and (not raw or looks_like_tls(raw)):
            # Silent or alerting on plaintext: try a TLS handshake (catches HTTPS on odd ports).
            t_raw, t_tls, t_cert = await grab_banner(host, port, timeout, use_tls=True)
            if t_tls:
                raw, tls, cert = t_raw, t_tls, t_cert
    fp = fingerprint(raw)
    service = fp.service or SERVICE_NAMES.get(port)
    if tls and service == "http":
        service = "https"
    return PortResult(
        port=port,
        state="open",
        service=service,
        product=fp.product,
        version=fp.version,
        banner=banner_summary(raw),
        tls=tls,
        cert=cert,
    )


async def scan(host: str, ports: list[int], timeout: float = 1.0, concurrency: int = 200) -> list[PortResult]:
    sem = asyncio.Semaphore(concurrency)
    results = await asyncio.gather(*(scan_port(host, p, timeout, sem) for p in ports))
    results = sorted(results, key=lambda r: r.port)
    assess_all(results)
    return results


def enrich_cves(results: list[PortResult], client: NVDClient, top: int = 5) -> None:
    for r in results:
        if r.state == "open" and r.product and r.version:
            info = client.lookup(r.product, r.version, top)
            r.cves, r.cve_total, r.cve_error = info["cves"], info["total"], info["error"]
            r.cve_method = info.get("method")
    assess_all(results)  # CVE severity feeds into the findings


def assess_all(results: list[PortResult]) -> None:
    for r in results:
        r.findings = assess(r)


def all_findings(results: list[PortResult]) -> list:
    return sort_findings([(r.port, f) for r in results for f in r.findings])


# ---------------------------------------------------------------- output

def render(results: list[PortResult], target: str, address: str, elapsed: float, scanned: int, with_cves: bool) -> str:
    open_ports = [r for r in results if r.state == "open"]
    closed = sum(r.state == "closed" for r in results)
    filtered = sum(r.state == "filtered" for r in results)
    lines = [f"Scan report for {target} ({address})", ""]
    if open_ports:
        rows = [("PORT", "SERVICE", "PRODUCT / VERSION", "BANNER")]
        for r in open_ports:
            pv = " ".join(x for x in (r.product, r.version) if x) or "-"
            if r.tls:
                pv += f" [{r.tls}]"
            rows.append((f"{r.port}/tcp", r.service or "unknown", pv, r.banner or "-"))
        widths = [max(len(row[i]) for row in rows) for i in range(3)]
        for row in rows:
            lines.append("  ".join(row[i].ljust(widths[i]) for i in range(3)) + "  " + row[3])
    else:
        lines.append("No open ports found.")
    lines += ["", f"{len(open_ports)} open, {closed} closed, {filtered} filtered of {scanned} ports in {elapsed:.2f}s"]

    certs = [r for r in open_ports if r.cert]
    if certs:
        lines += ["", "TLS certificates"]
        for r in certs:
            c = r.cert
            flags = ", ".join(x for x in ("self-signed" if c["self_signed"] else "", "EXPIRED" if c["expired"] else "") if x)
            lines.append(f"  {r.port}/tcp  CN={c['subject'] or '-'}  issuer={c['issuer'] or '-'}  "
                         f"expires {c['not_after'][:10]} ({c['days_left']}d){'  [' + flags + ']' if flags else ''}")
            if c["sans"]:
                lines.append(f"            SANs: {', '.join(c['sans'][:6])}")

    findings = all_findings(results)
    lines += ["", "Exposure findings (MITRE ATT&CK technique an attacker would use)"]
    if findings:
        for port, f in findings:
            tech = ", ".join(f.attack) or "-"
            lines.append(f"  {f.severity:<8}  {port}/tcp  {f.title}  [{tech}]")
    else:
        lines.append("  none")

    if with_cves:
        lines += ["", "CVE candidates (verify the installed patch level before acting)"]
        shown = False
        for r in open_ports:
            if not (r.product and r.version):
                continue
            shown = True
            method = {"cpe": "CPE match", "keyword": "keyword match"}.get(r.cve_method, "")
            lines.append(f"  {r.port}/tcp {r.product} {r.version}" + (f"  ({method})" if method else ""))
            if r.cve_error:
                lines.append(f"    lookup failed: {r.cve_error}")
            elif not r.cves:
                lines.append("    no candidates returned")
            else:
                for c in r.cves:
                    score = f"{c['score']:.1f}" if c["score"] is not None else "n/a"
                    lines.append(f"    {c['id']:<15} {score:>4} {c['severity']:<8}  {c['summary'][:70]}")
                lines.append(f"    ({r.cve_total} total matches; distro backports are not considered)")
        if not shown:
            lines.append("  no services with an identified product and version")
    return "\n".join(lines)


def to_json(results, target, address, scanned, elapsed) -> dict:
    open_ports = []
    for r in results:
        if r.state != "open":
            continue
        d = asdict(r)
        d["findings"] = [f.to_dict() for f in r.findings]
        open_ports.append(d)
    findings = all_findings(results)
    techniques = sorted({t for _, f in findings for t in f.attack})
    return {
        "tool": f"portscan-fingerprint {VERSION}",
        "target": target,
        "address": address,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ports_scanned": scanned,
        "duration_seconds": round(elapsed, 2),
        "open": open_ports,
        "closed": sum(r.state == "closed" for r in results),
        "filtered": sum(r.state == "filtered" for r in results),
        "severity_counts": {s: sum(f.severity == s for _, f in findings) for s in SEVERITY_ORDER},
        "attack_techniques": [{"id": t, "name": TECHNIQUES.get(t, ""), "url": attack_url(t)} for t in techniques],
    }


# ---------------------------------------------------------------- CLI

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Async TCP scanner with banner grabbing, fingerprinting, findings and CVE lookup.")
    p.add_argument("target", help="single host or IP you own or are authorised to scan")
    p.add_argument("-p", "--ports", help="e.g. 22,80,443 or 1-1024 (default: 43 common ports)")
    p.add_argument("-t", "--timeout", type=float, default=1.0, help="per-connection timeout in seconds (default 1.0)")
    p.add_argument("-c", "--concurrency", type=int, default=200, help="parallel connections, max 500 (default 200)")
    p.add_argument("--cve", action="store_true", help="look up CVE candidates in the NVD (rate limited; set NVD_API_KEY to speed up)")
    p.add_argument("--cve-mode", choices=("cpe", "keyword"), default="cpe",
                   help="cpe: exact product/version match, keyword fallback for unknown products (default); keyword: text search only")
    p.add_argument("--json", metavar="FILE", help="also write results to a JSON file")
    p.add_argument("--html", metavar="FILE", help="also write a self-contained HTML report")
    p.add_argument("--i-own-this", action="store_true", help="confirm you are authorised to scan a non-private address")
    p.add_argument("--version", action="version", version=f"portscan-fingerprint {VERSION}")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ports = parse_ports(args.ports) if args.ports else COMMON_PORTS
        address = resolve(args.target)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if not is_internal(address) and not args.i_own_this:
        print(
            f"refusing to scan {address}: it is not a private or loopback address.\n"
            "Only scan systems you own or have written permission to test. "
            "If that applies, re-run with --i-own-this.",
            file=sys.stderr,
        )
        return 2
    if not 0 < args.timeout <= 30 or not 0 < args.concurrency:
        print("error: timeout must be in (0, 30] and concurrency must be positive", file=sys.stderr)
        return 2
    concurrency = min(args.concurrency, 500)

    started = time.monotonic()
    results = asyncio.run(scan(address, ports, args.timeout, concurrency))
    elapsed = time.monotonic() - started

    if args.cve:
        client = NVDClient(use_cpe=args.cve_mode == "cpe")
        n = sum(1 for r in results if r.state == "open" and r.product and r.version)
        if n:
            pace = "fast (API key)" if client.api_key else "~7s per uncached service (no API key)"
            print(f"Looking up {n} service(s) in the NVD, {pace}...", file=sys.stderr)
        enrich_cves(results, client)

    print(render(results, args.target, address, elapsed, len(ports), args.cve))
    data = to_json(results, args.target, address, len(ports), elapsed)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        print(f"\nJSON written to {args.json}")
    if args.html:
        from report import render_html
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(data))
        print(f"HTML report written to {args.html}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
