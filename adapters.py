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


# Secrets are masked in stored evidence, so neither the UI, the JSON report nor any AI step ever sees them.
_SECRET_MASKS = [
    (re.compile(r"^(enable (?:secret|password)(?: \d)?) \S+", re.I), r"\1 ********"),
    (re.compile(r"(encrypted-password|plain-text-password)\s+\S+$", re.I), r"\1 ********"),
    (re.compile(r"^(set password ENC)\s+\S+", re.I), r"\1 ********"),
]


def _mask(text):
    for pat, repl in _SECRET_MASKS:
        text = pat.sub(repl, text)
    return text


def _attr(value, hits):
    return {"value": value, "evidence": [{"line": n, "text": _mask(t)} for n, t, _ in hits]}


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
    score = {
        "Cisco": len(_grep(raw, r"^(hostname |ip ssh |ip http |service password-encryption|enable secret|line vty|interface [a-z]+)")),
        "Juniper": len(_grep(raw, r"^set (system|interfaces|security|snmp) ")) +
                   len(_grep(raw, r"^(system|interfaces|security|snmp)\s*\{")),
        "Fortinet": len(_grep(raw, r"^config (system|firewall|log|router|user|vpn|wireless) ")),
    }
    top = sorted(score.items(), key=lambda kv: -kv[1])
    if top[0][1] == 0 or top[0][1] == top[1][1]:
        return "Unknown", 0
    return top[0]


def parse_cisco(text):
    L = [(n, t) for n, t in _lines(text) if not t.startswith("!")]
    m = {}
    h = _grep(L, r"^ip ssh version (\d)")
    m["ssh_version"] = _attr(int(h[-1][2].group(1)) if h else None, h)
    h = _grep(L, r"^transport input .*\b(telnet|all)\b")
    t = _grep(L, r"^transport input ")
    # No explicit VTY transport setting: many IOS versions default to allowing Telnet, so it cannot be confirmed.
    val = True if h else (False if t else "unspecified")
    m["telnet_enabled"] = _attr(val, h or t)
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


def forti_flat(text):
    """FortiOS 'config / edit / set' tree -> (line, section_path, text). Keeps line numbers."""
    out, stack = [], []
    for n, l in _lines(text):
        if l.startswith("#"):
            continue
        if l.startswith("config "):
            stack.append(l[7:].strip())
        elif l.startswith("edit "):
            stack.append("edit " + l[5:].strip().strip('"'))
        elif l in ("next", "end"):
            if stack:
                stack.pop()
        elif l.startswith("set "):
            out.append((n, " / ".join(stack), l))
    return out


def parse_fortinet(text):
    F = forti_flat(text)
    m = {}

    def sec(prefix):
        return [(n, t) for n, p, t in F if p.startswith(prefix)]

    # Management access is set per interface: 'set allowaccess ping https ssh http telnet'
    acc = _grep(sec("system interface"), r"^set allowaccess (.*)")
    words = [(n, t, set(x.group(1).lower().replace('"', "").split())) for n, t, x in acc]
    legacy = _grep(sec("system global"), r"^set admin-telnet enable")
    ssh = [(n, t, None) for n, t, w in words if "ssh" in w]
    # FortiOS offers SSH v2 only, so SSH enabled on any interface is treated as v2 (check your FortiOS version).
    m["ssh_version"] = _attr(2 if ssh else None, ssh)
    tel = [(n, t, None) for n, t, w in words if "telnet" in w] + legacy
    m["telnet_enabled"] = _attr(bool(tel), tel)
    http = [(n, t, None) for n, t, w in words if "http" in w]
    m["http_mgmt_enabled"] = _attr(bool(http), http)
    st = _grep(sec("log syslogd setting"), r"^set status enable")
    sv = _grep(sec("log syslogd setting"), r"^set server ")
    m["remote_logging"] = _attr(bool(st and sv), st + sv)
    h = _grep(sec("system admin"), r"^set password ENC (\S+)")
    lv = ["strong" if x.group(1).startswith("SH2") else "weak-hash" if x.group(1).startswith(("AK1", "SH1")) else "unknown"
          for _, _, x in h]
    plain = _grep(sec("system admin"), r"^set password (?!ENC)\S+")
    lv += ["plaintext"] * len(plain)
    m["privileged_password"] = _attr(_weakest(lv), h + plain)
    h = _grep(sec("system snmp community"), r'^set name "?(public|private)"?$')
    m["snmp_default_community"] = _attr(bool(h), h)
    h = _grep(sec("system ntp"), r"^set (server|ntpsync enable)")
    m["ntp_configured"] = _attr(bool(h), h)
    h = _grep(sec("system global"), r"^set pre-login-banner enable")
    m["login_banner"] = _attr(bool(h), h)
    return m


PARSERS = {"Cisco": parse_cisco, "Juniper": parse_juniper, "Fortinet": parse_fortinet}  # add a vendor = add one function here