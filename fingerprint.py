"""Service fingerprinting: turn raw banner bytes into (service, product, version).

Pure functions only, so everything here is unit-testable without a network.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class Fingerprint:
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


FLAGS = re.IGNORECASE | re.MULTILINE

# (pattern, service, default product). A named group `v` captures the version,
# and a named group `p` overrides the default product. Order matters: specific
# signatures come before generic ones.
SIGNATURES = [
    (re.compile(r"^SSH-\d\.\d-OpenSSH_(?P<v>\d[\w.]*)", FLAGS), "ssh", "OpenSSH"),
    (re.compile(r"^SSH-\d\.\d-dropbear_(?P<v>\d[\w.]*)", FLAGS), "ssh", "Dropbear"),
    (re.compile(r"^SSH-\d\.\d-", FLAGS), "ssh", None),
    (re.compile(r"^220[ -].*ProFTPD (?P<v>\d[\w.]*)", FLAGS), "ftp", "ProFTPD"),
    (re.compile(r"^220[ -].*vsFTPd (?P<v>\d[\d.]*)", FLAGS), "ftp", "vsftpd"),
    (re.compile(r"^220[ -].*Pure-FTPd", FLAGS), "ftp", "Pure-FTPd"),
    (re.compile(r"^220[ -].*\bFTP\b", FLAGS), "ftp", None),
    (re.compile(r"^220[ -].*Exim (?P<v>\d[\d.]*)", FLAGS), "smtp", "Exim"),
    (re.compile(r"^220[ -].*Postfix", FLAGS), "smtp", "Postfix"),
    (re.compile(r"^220[ -].*SMTP", FLAGS), "smtp", None),
    (re.compile(r"^Server:\s*Apache/(?P<v>\d[\d.]*)", FLAGS), "http", "Apache httpd"),
    (re.compile(r"^Server:\s*nginx/(?P<v>\d[\d.]*)", FLAGS), "http", "nginx"),
    (re.compile(r"^Server:\s*Microsoft-IIS/(?P<v>\d[\d.]*)", FLAGS), "http", "Microsoft IIS"),
    (re.compile(r"^Server:\s*(?P<p>[^\s/\r\n]+)(?:/(?P<v>\d[\w.\-]*))?", FLAGS), "http", None),
    (re.compile(r"^HTTP/\d(?:\.\d)? \d{3}", FLAGS), "http", None),
    (re.compile(r"^\* OK .*Dovecot", FLAGS), "imap", "Dovecot"),
    (re.compile(r"^(?:\+PONG|-NOAUTH|-DENIED)", FLAGS), "redis", "Redis"),
]


def clean_text(raw: bytes) -> str:
    """Decode bytes to printable text, keeping CR/LF, replacing the rest."""
    text = raw.decode("latin-1", errors="replace")
    return "".join(ch if ch in "\r\n" or 32 <= ord(ch) < 127 else "." for ch in text)


def banner_summary(raw: bytes, limit: int = 80) -> str:
    """One-line, printable summary of a banner for display."""
    if not raw.strip():
        return ""
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in raw)
    if printable / len(raw) < 0.7:  # binary greeting (e.g. MySQL): show the readable strings only
        runs = re.findall(rb"[\x20-\x7e]{4,}", raw)
        text = " ".join(r.decode("ascii") for r in runs[:2]) or "<binary data>"
    else:
        text = clean_text(raw).strip()
    if not text:
        return ""
    first = text.splitlines()[0].strip()
    return first if len(first) <= limit else first[: limit - 3] + "..."


def _parse_mysql(raw: bytes) -> Optional[Fingerprint]:
    """MySQL/MariaDB send a binary handshake: 4-byte header, 0x0a, version string, NUL."""
    if len(raw) < 8 or raw[4] != 0x0A:
        return None
    end = raw.find(b"\x00", 5)
    if end == -1:
        return None
    ver = raw[5:end].decode("latin-1", errors="replace")
    if ver.startswith("5.5.5-"):  # MariaDB prefixes a fake 5.5.5 for compatibility
        ver = ver[len("5.5.5-"):]
    m = re.match(r"(\d+\.\d+\.\d+)", ver)
    if not m:
        return None
    product = "MariaDB" if "mariadb" in ver.lower() else "MySQL"
    return Fingerprint("mysql", product, m.group(1))


def fingerprint(raw: bytes) -> Fingerprint:
    """Identify a service from whatever it sent us. Unknown input gives an empty Fingerprint."""
    if not raw:
        return Fingerprint()
    mysql = _parse_mysql(raw)
    if mysql:
        return mysql
    if len(raw) >= 3 and raw[0] == 0xFF and 0xFB <= raw[1] <= 0xFE:  # Telnet IAC WILL/WONT/DO/DONT
        return Fingerprint("telnet")
    text = clean_text(raw)
    for pattern, service, default_product in SIGNATURES:
        m = pattern.search(text)
        if not m:
            continue
        groups = m.groupdict()
        return Fingerprint(
            service=service,
            product=groups.get("p") or default_product,
            version=groups.get("v"),
        )
    return Fingerprint()
