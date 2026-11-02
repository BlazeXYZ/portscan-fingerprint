"""Minimal NVD CVE 2.0 client: CPE or keyword lookup, rate limiting, on-disk cache.

Design notes
- Known products are looked up by CPE name (cpe:2.3:a:vendor:product:version),
  which the NVD evaluates against each CVE's affected-version ranges. Unknown
  products fall back to a keyword search, which is much noisier.
- Either way the result is a *candidate* list, not a verdict. Distros backport
  fixes without changing the version string, so a hit here means "worth
  checking", never "vulnerable".
- Response parsing is defensive (.get everywhere): a missing field degrades the
  output instead of crashing a scan.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Optional

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL = 24 * 3600
FETCH_LIMIT = 20  # keyword: pull a page, rank locally by CVSS, show the top few
CPE_FETCH_LIMIT = 200  # CPE matches are precise, so pull enough to rank them all
USER_AGENT = "portscan-fingerprint/1.1 (educational)"

# Fingerprint product name -> NVD "vendor:product". Each entry was checked
# against the live API; nginx moved to the f5 vendor, so nginx:nginx returns nothing.
CPE_PRODUCTS = {
    "OpenSSH": "openbsd:openssh",
    "Dropbear": "dropbear_ssh_project:dropbear_ssh",
    "vsftpd": "vsftpd_project:vsftpd",
    "ProFTPD": "proftpd:proftpd",
    "Exim": "exim:exim",
    "Apache httpd": "apache:http_server",
    "nginx": "f5:nginx",
    "Microsoft IIS": "microsoft:internet_information_services",
    "MySQL": "oracle:mysql",
    "MariaDB": "mariadb:mariadb",
    "Redis": "redis:redis",
}


def severity(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0 else "NONE"


def best_score(metrics: dict) -> Optional[float]:
    """Prefer CVSS v3.1, then v3.0, then v2."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            score = ((entries[0] or {}).get("cvssData") or {}).get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
    return None


def build_query(product: str, version: str) -> str:
    version = re.sub(r"p\d+$", "", version)  # OpenSSH "8.2p1" -> "8.2"
    return f"{product} {version}".strip()


def build_cpe(product: str, version: str) -> Optional[str]:
    """Return a CPE 2.3 name, or None if the product is unmapped.
    A trailing patch tag becomes the CPE update field: "8.2p1" -> 8.2 / p1, "1.3.5e" -> 1.3.5 / e."""
    vendor_product = CPE_PRODUCTS.get(product)
    m = re.fullmatch(r"(\d[\d.]*\d|\d)([a-z]\w*)?", version or "", re.IGNORECASE)
    if not vendor_product or not m:
        return None
    update = (m.group(2) or "*").lower()
    return f"cpe:2.3:a:{vendor_product}:{m.group(1)}:{update}:*:*:*:*:*:*"


def parse_response(payload: dict, top: int = 10) -> dict:
    vulns = payload.get("vulnerabilities") or []
    total = payload.get("totalResults", len(vulns))
    items = []
    for entry in vulns:
        cve = (entry or {}).get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        summary = next(
            (d.get("value", "") for d in (cve.get("descriptions") or []) if d.get("lang") == "en"),
            "",
        )
        score = best_score(cve.get("metrics") or {})
        items.append(
            {
                "id": cve_id,
                "score": score,
                "severity": severity(score),
                "summary": (summary[:137] + "...") if len(summary) > 140 else summary,
            }
        )
    items.sort(key=lambda i: (i["score"] is None, -(i["score"] or 0.0), i["id"]))
    return {"total": total, "cves": items[:top]}


class NVDClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_path: str = ".nvd_cache.json",
        fetch: Optional[Callable[[str], dict]] = None,
        timeout: float = 15.0,
        use_cpe: bool = True,
    ):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.use_cpe = use_cpe
        self.cache_path = Path(cache_path)
        self.timeout = timeout
        self._fetch = fetch or self._http_get
        self._lock = threading.Lock()
        self._last_call = 0.0
        self._cache = self._load_cache()

    @property
    def min_interval(self) -> float:
        # Published public limits: 5 requests / 30 s without a key, 50 with one.
        return 0.7 if self.api_key else 6.5

    def _load_cache(self) -> dict:
        try:
            return json.loads(self.cache_path.read_text())
        except (OSError, ValueError):
            return {}

    def _save_cache(self) -> None:
        try:
            self.cache_path.write_text(json.dumps(self._cache))
        except OSError:
            pass  # a read-only directory should not break a scan

    def _http_get(self, url: str) -> dict:
        with self._lock:
            wait = self.min_interval - (time.monotonic() - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()
        headers = {"User-Agent": USER_AGENT}
        if self.api_key:
            headers["apiKey"] = self.api_key
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.load(resp)

    def lookup(self, product: str, version: str, top: int = 5) -> dict:
        cpe = build_cpe(product, version) if self.use_cpe else None
        if cpe:
            result = self._query("cpe", cpe, {"cpeName": cpe, "resultsPerPage": CPE_FETCH_LIMIT}, top)
            if not (result["error"] or "").startswith("HTTP 404"):
                return result
            # 404 means the NVD rejected the CPE name: fall back to keywords
        query = build_query(product, version)
        return self._query("keyword", query, {"keywordSearch": query, "resultsPerPage": FETCH_LIMIT}, top)

    def _query(self, method: str, query: str, params: dict, top: int) -> dict:
        key = query  # keyword keys stay plain, so caches from 1.0 remain valid; CPE keys start with "cpe:"
        base = {"query": query, "method": method}
        hit = self._cache.get(key)
        if hit and time.time() - hit["ts"] < CACHE_TTL:
            return {**hit["data"], **base, "cves": hit["data"]["cves"][:top], "cached": True, "error": None}

        url = NVD_URL + "?" + urllib.parse.urlencode(params)
        try:
            payload = self._fetch(url)
        except urllib.error.HTTPError as e:
            note = " (rate limited, try again later or set NVD_API_KEY)" if e.code in (403, 429) else ""
            return {**base, "total": 0, "cves": [], "cached": False, "error": f"HTTP {e.code}{note}"}
        except (urllib.error.URLError, OSError, ValueError) as e:
            reason = getattr(e, "reason", e)
            return {**base, "total": 0, "cves": [], "cached": False, "error": f"network error: {reason}"}

        data = parse_response(payload, top=10)
        self._cache[key] = {"ts": time.time(), "data": data}
        self._save_cache()
        return {**data, **base, "cves": data["cves"][:top], "cached": False, "error": None}
