"""Minimal X.509 certificate reader: just enough DER parsing to report on a TLS service.

The standard library only decodes a peer certificate after it has been verified,
and a scanner deliberately skips verification. So this reads the raw DER bytes
itself: subject and issuer common names, validity dates, and DNS/IP SANs.
Pure functions only, so it is unit-testable without a network.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Optional

OID_CN = bytes.fromhex("550403")      # 2.5.4.3 commonName
OID_ORG = bytes.fromhex("55040a")     # 2.5.4.10 organizationName
OID_SAN = bytes.fromhex("551d11")     # 2.5.29.17 subjectAltName


def _tlv(buf: bytes, i: int) -> tuple[int, int, int]:
    """Read one DER element at offset i. Returns (tag, content_start, content_end)."""
    tag, length = buf[i], buf[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        if not 1 <= n <= 4:
            raise ValueError("unsupported DER length")
        length = int.from_bytes(buf[i:i + n], "big")
        i += n
    if i + length > len(buf):
        raise ValueError("truncated DER element")
    return tag, i, i + length


def _children(buf: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out, i = [], start
    while i < end:
        tag, s, e = _tlv(buf, i)
        out.append((tag, s, e))
        i = e
    return out


def _printable(text: str) -> str:
    """Certificates are attacker-supplied: replace control characters (e.g. ANSI escapes) before display."""
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def _name_attr(buf: bytes, start: int, end: int, oid: bytes) -> Optional[str]:
    """Find an attribute in an X.501 Name (SEQUENCE OF SET OF SEQUENCE {OID, value})."""
    for _, rs, re_ in _children(buf, start, end):
        for _, as_, ae in _children(buf, rs, re_):
            parts = _children(buf, as_, ae)
            if len(parts) == 2 and buf[parts[0][1]:parts[0][2]] == oid:
                return _printable(buf[parts[1][1]:parts[1][2]].decode("utf-8", errors="replace"))
    return None


def _time(buf: bytes, tag: int, start: int, end: int) -> datetime:
    text = buf[start:end].decode("ascii")
    fmt = "%y%m%d%H%M%SZ" if tag == 0x17 else "%Y%m%d%H%M%SZ"  # UTCTime vs GeneralizedTime
    return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)


def _sans(buf: bytes, start: int, end: int) -> list[str]:
    names = []
    for tag, s, e in _children(buf, start, end):
        if tag == 0x82:  # [2] dNSName
            names.append(_printable(buf[s:e].decode("ascii", errors="replace")))
        elif tag == 0x87 and e - s in (4, 16):  # [7] iPAddress
            names.append(str(ipaddress.ip_address(buf[s:e])))
    return names


def parse_cert(der: bytes, now: Optional[datetime] = None) -> Optional[dict]:
    """Summarise a DER certificate. Returns None if it cannot be parsed."""
    if not der:
        return None
    now = now or datetime.now(timezone.utc)
    try:
        _, cs, ce = _tlv(der, 0)
        tbs_tag, ts, te = _children(der, cs, ce)[0]
        fields = _children(der, ts, te)
        if fields and fields[0][0] == 0xA0:  # explicit [0] version
            fields = fields[1:]
        # serial, signature algorithm, issuer, validity, subject, public key, then optional extras
        issuer, validity, subject = fields[2], fields[3], fields[4]
        (nb_tag, nbs, nbe), (na_tag, nas, nae) = _children(der, validity[1], validity[2])[:2]
        not_before, not_after = _time(der, nb_tag, nbs, nbe), _time(der, na_tag, nas, nae)

        sans: list[str] = []
        for tag, s, e in fields[6:]:
            if tag != 0xA3:  # [3] extensions
                continue
            for _, xs, xe in _children(der, *_children(der, s, e)[0][1:]):
                ext = _children(der, xs, xe)
                if der[ext[0][1]:ext[0][2]] == OID_SAN:
                    _, os_, oe = ext[-1]  # OCTET STRING wrapping GeneralNames
                    _, gs, ge = _tlv(der, os_)
                    sans = _sans(der, gs, ge)
    except (ValueError, IndexError, UnicodeDecodeError):
        return None

    return {
        "subject": _name_attr(der, subject[1], subject[2], OID_CN),
        "issuer": _name_attr(der, issuer[1], issuer[2], OID_CN) or _name_attr(der, issuer[1], issuer[2], OID_ORG),
        "sans": sans,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": (not_after - now).days,
        "expired": now > not_after,
        # Issuer and subject DNs encode identically, which is the textbook self-signed signal.
        "self_signed": der[issuer[1]:issuer[2]] == der[subject[1]:subject[2]],
    }
