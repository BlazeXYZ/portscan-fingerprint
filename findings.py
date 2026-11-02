"""Exposure findings: turn a fingerprinted port into ranked, ATT&CK-mapped observations.

Each rule answers "what could an attacker do with this?" and names the MITRE
ATT&CK technique a defender should watch for. Findings describe exposure, not
confirmed compromise. Pure functions only, so they are unit-testable.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

TECHNIQUES = {
    "T1021": "Remote Services",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1021.004": "Remote Services: SSH",
    "T1021.005": "Remote Services: VNC",
    "T1021.006": "Remote Services: Windows Remote Management",
    "T1040": "Network Sniffing",
    "T1110": "Brute Force",
    "T1190": "Exploit Public-Facing Application",
    "T1210": "Exploitation of Remote Services",
    "T1557": "Adversary-in-the-Middle",
    "T1592.002": "Gather Victim Host Information: Software",
    "T1610": "Deploy Container",
}

REMOTE_ACCESS = {
    "ssh": ("INFO", "SSH remote login exposed", "T1021.004"),
    "rdp": ("MEDIUM", "Remote Desktop exposed", "T1021.001"),
    "vnc": ("MEDIUM", "VNC remote desktop exposed", "T1021.005"),
    "winrm": ("MEDIUM", "WinRM remote management exposed", "T1021.006"),
}
DATABASES = {"mysql", "mssql", "postgresql", "oracle", "mongodb", "redis", "elasticsearch", "memcached"}
WEB = {"http", "https", "http-alt", "https-alt"}


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    attack: list = field(default_factory=list)  # technique IDs

    def to_dict(self) -> dict:
        d = asdict(self)
        d["attack"] = [{"id": t, "name": TECHNIQUES.get(t, ""), "url": attack_url(t)} for t in self.attack]
        return d


def attack_url(technique: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"


def assess(r) -> list[Finding]:
    """Findings for one open port. `r` is a PortResult (or anything with the same attributes)."""
    if r.state != "open":
        return []
    out: list[Finding] = []
    svc = r.service or ""
    label = " ".join(x for x in (r.product, r.version) if x) or svc or "service"

    # Cleartext protocols: credentials cross the wire readable.
    if svc == "telnet":
        out.append(Finding("HIGH", "Telnet: cleartext remote login",
                           "Telnet sends usernames, passwords and session data unencrypted. Replace it with SSH.",
                           ["T1040", "T1021", "T1110"]))
    elif svc == "ftp" and not r.tls:
        out.append(Finding("MEDIUM", "FTP without TLS",
                           "FTP logins and file contents are sent in cleartext. Prefer SFTP or FTPS.",
                           ["T1040", "T1110"]))

    if svc in REMOTE_ACCESS:
        sev, title, tech = REMOTE_ACCESS[svc]
        out.append(Finding(sev, title, "Interactive login is reachable here; expect password-guessing traffic. "
                           "Restrict by firewall or VPN and require keys or MFA.", [tech, "T1110"]))
    if svc in ("smb", "netbios"):
        out.append(Finding("HIGH", "SMB file sharing exposed",
                           "SMB is a frequent lateral-movement and wormable-exploit path (e.g. EternalBlue). "
                           "It should not be reachable outside a trusted segment.", ["T1021.002", "T1210"]))
    if svc == "docker":
        out.append(Finding("CRITICAL", "Docker API port open (2375)",
                           "Port 2375 is Docker's unauthenticated API by convention; access is equivalent to root "
                           "on the host. Identified by port number only, so confirm before acting.", ["T1610", "T1190"]))

    if svc == "redis" and r.banner.startswith("+PONG"):
        out.append(Finding("HIGH", "Redis answers without authentication",
                           "PING succeeded without a password, so any client that can reach this port can read "
                           "and write data. Enable requirepass or ACLs and bind to localhost.", ["T1210"]))
    elif svc in DATABASES:
        out.append(Finding("MEDIUM", f"Database reachable over the network ({svc})",
                           "Databases are rarely meant to face the network directly. Limit access to application "
                           "hosts.", ["T1110", "T1210"]))

    if svc in WEB and r.product and r.version:
        out.append(Finding("LOW", "Web server discloses its version",
                           f"The Server header reveals '{label}', which lets an attacker match exploits without "
                           "probing. Suppress the version (e.g. ServerTokens Prod, server_tokens off).", ["T1592.002"]))

    # TLS hygiene.
    if r.tls in ("TLSv1", "TLSv1.1", "SSLv3"):
        out.append(Finding("MEDIUM", f"Deprecated protocol negotiated ({r.tls})",
                           "The server's best offer is a protocol version with known weaknesses. Require TLS 1.2 or later.",
                           ["T1557"]))
    cert = getattr(r, "cert", None)
    if cert:
        if cert.get("expired"):
            out.append(Finding("MEDIUM", "TLS certificate expired",
                               f"Expired on {cert['not_after'][:10]}. Clients that click through warnings are open "
                               "to interception.", ["T1557"]))
        elif cert.get("days_left") is not None and cert["days_left"] < 30:
            out.append(Finding("LOW", "TLS certificate expires soon",
                               f"{cert['days_left']} days left (until {cert['not_after'][:10]}).", []))
        if cert.get("self_signed"):
            out.append(Finding("LOW", "Self-signed TLS certificate",
                               "No trusted CA vouches for this certificate, so clients cannot tell it apart from an "
                               "attacker's.", ["T1557"]))

    # Known-vulnerable versions, worst CVE first.
    scored = [c for c in (r.cves or []) if c.get("score") is not None]
    if scored:
        worst = max(scored, key=lambda c: c["score"])
        if worst["score"] >= 7.0:
            tech = "T1190" if svc in WEB else "T1210"
            out.append(Finding("CRITICAL" if worst["score"] >= 9.0 else "HIGH",
                               f"Known {worst['severity'].lower()} CVEs for {label}",
                               f"Worst candidate {worst['id']} (CVSS {worst['score']:.1f}) out of {r.cve_total} "
                               "matches. Confirm the installed patch level; distros backport fixes.", [tech]))
    return out


def sort_findings(items: list) -> list:
    """Sort (port, Finding) pairs worst first."""
    return sorted(items, key=lambda pf: (SEVERITY_ORDER.index(pf[1].severity), pf[0]))
