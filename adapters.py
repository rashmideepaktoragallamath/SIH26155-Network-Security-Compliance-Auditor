"""Vendor adapters -> Common Security Model (CSM).
Each CSM attribute = {"value": ..., "evidence": [{"line": n, "text": raw}]}.
Comments are ignored, so '! ip http server' is never counted.
"""
import re

PW_ORDER = ["plaintext", "reversible", "weak-hash", "unknown", "strong"]  # weakest first


def _lines(text):
    return [(i, l.strip()) for i, l in enumerate(text.splitlines(), 1) if l.strip()]


def _grep(lines, pattern):
    out = []
    for n, t in lines:
        m = re.search(pattern, t, re.I)
        if m:
            out.append((n, t, m))
    return out


def _attr(value, hits):
    return {"value": value, "evidence": [{"line": n, "text": t} for n, t, _ in hits]}


def _weakest(levels):
    return min(levels, key=PW_ORDER.index) if levels else "missing"


def junos_to_set(text):
    """Flatten Junos curly-brace config to 'set' lines (keeps line numbers)."""
    raw = _lines(text)
    if any(t.startswith("set ") for _, t in raw):
        return [(n, t) for n, t in raw if t.startswith("set ")]
    out, stack = [], []
    for n, l in raw:
        if l.startswith(("#", "/*", "*")):
            continue
        if l.endswith("{"):
            stack.append(l[:-1].strip())
        elif l == "}":
            if stack:
                stack.pop()
        elif l.endswith(";"):
            out.append((n, "set " + " ".join(stack + [l[:-1].strip()])))
    return out


def detect_vendor(text):
    raw = _lines(text)
    cisco = len(_grep(raw, r"^(hostname |ip ssh |ip http |service password-encryption|enable secret|line vty|interface [a-z]+)"))
    junos = len(_grep(raw, r"^set (system|interfaces|security|snmp) ")) + \
        len(_grep(raw, r"^(system|interfaces|security|snmp)\s*\{"))
    if cisco > junos:
        return "Cisco", cisco
    if junos > cisco:
        return "Juniper", junos
    return "Unknown", 0


def parse_cisco(text):
    L = [(n, t) for n, t in _lines(text) if not t.startswith("!")]
    m = {}
    h = _grep(L, r"^ip ssh version (\d)")
    m["ssh_version"] = _attr(int(h[-1][2].group(1)) if h else None, h)
    h = _grep(L, r"^transport input .*\b(telnet|all)\b")
    m["telnet_enabled"] = _attr(bool(h), h)
    h = _grep(L, r"^ip http server$")
    m["http_mgmt_enabled"] = _attr(bool(h), h)
    h = _grep(L, r"^logging (host )?\d+\.\d+\.\d+\.\d+|^logging host \S+")
    m["remote_logging"] = _attr(bool(h), h)
    h = _grep(L, r"^enable (secret|password)(?: (\d))? (\S+)")
    lv = []
    for _, _, x in h:
        kind, typ = x.group(1).lower(), x.group(2)
        lv.append("plaintext" if kind == "password" or typ in (None, "0") else
                  {"7": "reversible", "5": "weak-hash", "4": "weak-hash"}.get(typ, "strong"))
    m["privileged_password"] = _attr(_weakest(lv), h)
    h = _grep(L, r"^snmp-server community (public|private)\b")
    m["snmp_default_community"] = _attr(bool(h), h)
    h = _grep(L, r"^ntp server ")
    m["ntp_configured"] = _attr(bool(h), h)
    h = _grep(L, r"^banner (login|motd|exec)")
    m["login_banner"] = _attr(bool(h), h)
    return m


def parse_juniper(text):
    L = junos_to_set(text)
    m = {}
    v = _grep(L, r"^set system services ssh protocol-version (v\d)")
    s = _grep(L, r"^set system services ssh")
    if v:
        val = 2 if v[-1][2].group(1).lower() == "v2" else 1
    else:
        val = "unspecified" if s else None
    m["ssh_version"] = _attr(val, v or s)
    h = _grep(L, r"^set system services telnet")
    m["telnet_enabled"] = _attr(bool(h), h)
    h = _grep(L, r"^set system services web-management http( |$)")
    m["http_mgmt_enabled"] = _attr(bool(h), h)
    h = _grep(L, r"^set system syslog host ")
    m["remote_logging"] = _attr(bool(h), h)
    h = _grep(L, r'encrypted-password "?(\S+?)"?$')
    lv = [{"$6$": "strong", "$5$": "strong", "$1$": "weak-hash"}.get(x.group(1)[:3], "unknown") for _, _, x in h]
    m["privileged_password"] = _attr(_weakest(lv), h)
    h = _grep(L, r"^set snmp community (public|private)\b")
    m["snmp_default_community"] = _attr(bool(h), h)
    h = _grep(L, r"^set system ntp server ")
    m["ntp_configured"] = _attr(bool(h), h)
    h = _grep(L, r"^set system login message")
    m["login_banner"] = _attr(bool(h), h)
    return m


PARSERS = {"Cisco": parse_cisco, "Juniper": parse_juniper}  # add a vendor = add one function here
