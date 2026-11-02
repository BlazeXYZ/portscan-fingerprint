#!/usr/bin/env python3
"""Local test lab: fake services on 127.0.0.1 that speak just enough protocol to be fingerprinted.

    python3 lab.py            # start the lab, Ctrl-C to stop
    python3 portscan.py 127.0.0.1 -p 2121,2222,2323,2525,3307,8080,8443 --cve --html report.html

Nothing here is vulnerable; these are banners only. The versions are deliberately old
so the CVE lookup has something to return.

The HTTPS service needs a throwaway self-signed certificate, which the lab creates
with the `openssl` command line tool. Without it, the lab runs everything else.
"""
from __future__ import annotations

import asyncio
import shutil
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

LAB_PORTS = {"ssh": 2222, "http": 8080, "ftp": 2121, "smtp": 2525, "mysql": 3307, "telnet": 2323, "https": 8443}

SSH_BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
FTP_BANNER = b"220 (vsFTPd 3.0.3)\r\n"
SMTP_BANNER = b"220 mail.lab ESMTP Postfix (Ubuntu)\r\n"
HTTP_RESPONSE = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
HTTPS_RESPONSE = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
TELNET_BANNER = b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\r\nlab login: "  # IAC WILL ECHO, WILL SGA, DO TTYPE


def mysql_handshake(version: bytes = b"5.7.30-0ubuntu0.18.04.1") -> bytes:
    payload = b"\x0a" + version + b"\x00" + b"\x01\x00\x00\x00" + b"abcdefgh\x00" + b"\xff\xf7\x08\x02\x00\xff\x81\x15" + b"\x00" * 10
    return len(payload).to_bytes(3, "little") + b"\x00" + payload


def _greeter(banner: bytes):
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            writer.write(banner)
            await writer.drain()
            await asyncio.wait_for(reader.read(100), 2)
        except (asyncio.TimeoutError, OSError):
            pass
        finally:
            writer.close()
    return handle


def _http(response: bytes):
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
            writer.write(response)
            await writer.drain()
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, OSError, ssl.SSLError):
            pass
        finally:
            writer.close()
    return handle


def make_tls_context(workdir: Path) -> ssl.SSLContext | None:
    """Create a throwaway self-signed certificate for lab.local (valid 20 days, so the
    scanner's "expires soon" check fires). Returns None if openssl is not installed."""
    openssl = shutil.which("openssl")
    if not openssl:
        return None
    cert, key = workdir / "lab-cert.pem", workdir / "lab-key.pem"
    try:
        subprocess.run(
            [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "20",
             "-keyout", str(key), "-out", str(cert), "-subj", "/CN=lab.local/O=portscan lab",
             "-addext", "subjectAltName=DNS:lab.local,DNS:localhost,IP:127.0.0.1"],
            check=True, capture_output=True, timeout=30,
        )
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(cert, key)
    except (OSError, subprocess.SubprocessError, ssl.SSLError):
        return None
    return ctx


async def start_lab(host: str = "127.0.0.1", ports: dict | None = None):
    """Start all fake services. Pass port 0 values for ephemeral ports (used by tests).
    Returns (servers, actual_ports). HTTPS is skipped when no certificate can be made."""
    ports = dict(ports or LAB_PORTS)
    handlers = {
        "ssh": _greeter(SSH_BANNER),
        "http": _http(HTTP_RESPONSE),
        "https": _http(HTTPS_RESPONSE),
        "ftp": _greeter(FTP_BANNER),
        "smtp": _greeter(SMTP_BANNER),
        "mysql": _greeter(mysql_handshake()),
        "telnet": _greeter(TELNET_BANNER),
    }
    tls_ctx = None
    if "https" in ports:
        with tempfile.TemporaryDirectory() as tmp:  # the key is loaded into memory, then deleted
            tls_ctx = make_tls_context(Path(tmp))
        if tls_ctx is None:
            print("lab: openssl not found, skipping the HTTPS service", file=sys.stderr)
            del ports["https"]
    servers, actual = [], {}
    for name, port in ports.items():
        server = await asyncio.start_server(handlers[name], host, port, ssl=tls_ctx if name == "https" else None)
        servers.append(server)
        actual[name] = server.sockets[0].getsockname()[1]
    return servers, actual


async def _main() -> None:
    servers, actual = await start_lab()
    print("Lab running on 127.0.0.1:", ", ".join(f"{n}={p}" for n, p in actual.items()))
    print("Ctrl-C to stop.")
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
