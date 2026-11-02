# Changelog

## 1.1.0 (2026-11-02)

### Added
- **CPE-based CVE matching** (`--cve-mode cpe`, the default). Known products are looked up by
  CPE 2.3 name so the NVD evaluates real affected-version ranges. Unknown products and
  NVD-rejected names (HTTP 404) fall back to keyword search. Results record which method was used.
- **TLS certificate inspection.** A minimal DER/X.509 parser (`certinfo.py`) reports subject,
  issuer, SANs, validity, days left and self-signed status for unverified certificates.
- **TLS auto-detection** on non-standard ports: a silent port, or one that answers plaintext with
  a TLS alert record, is retried with a TLS handshake.
- **Exposure findings mapped to MITRE ATT&CK** (`findings.py`), ranked CRITICAL to INFO.
- **Self-contained HTML report** (`--html`, or `report.py` from saved JSON) with escaped output,
  light and dark themes and a phone-width layout.
- Telnet fingerprinting from IAC option negotiation.
- Control characters in certificate names are replaced before display (terminal-injection defense).
- Lab services for HTTPS (self-signed, nginx 1.18.0) and Telnet.
- Tests for all of the above (21 to 28 tests) and CI on Linux, Windows and macOS.

### Changed
- TLS client context accepts legacy protocol versions so weak servers are reported instead of
  failing the handshake.
- JSON output adds `tool`, `cert`, `cve_method`, `findings`, `severity_counts` and `attack_techniques`.

### Fixed
- Documented that Windows retries a refused TCP connect for about 2 s, so closed ports show as
  filtered with timeouts below that. The end-to-end test now uses a 3 s timeout.

## 1.0.0 (2026-10-29)

- Async TCP connect scan, banner grabbing, signature and MySQL-handshake fingerprinting,
  keyword CVE lookup against NVD 2.0 with rate limiting and caching, terminal and JSON output,
  local test lab, private-address authorization guard.
