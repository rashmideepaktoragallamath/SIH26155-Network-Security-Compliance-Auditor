"""Deterministic compliance engine. AI never decides pass/fail here.
CIS / CERT-In clause IDs are intentionally 'VERIFY' until checked against the source documents.
"""
VERIFY = "VERIFY against source document"
CERTIN = "CERT-In Directions (28 Apr 2022)"

RULES = [
    dict(id="AG-01", name="SSH Version 2 enforced", attr="ssh_version", sev="High",
         ok=lambda v: v == 2, nist="AC-17", certin=None,
         why="SSH v2 is not explicitly enforced (value: {v}).",
         fix={"Fortinet": ["(SSH is v2 only on FortiOS; keep ssh in allowaccess only on management interfaces)"], "Cisco": ["ip ssh version 2"], "Juniper": ["set system services ssh protocol-version v2"]},
         rollback={"Fortinet": ["(none needed)"], "Cisco": ["no ip ssh version 2"], "Juniper": ["delete system services ssh protocol-version"]}),
    dict(id="AG-02", name="Telnet management disabled", attr="telnet_enabled", sev="High",
         ok=lambda v: v is False, nist="AC-17, CM-7", certin=None,
         review=lambda v: v == "unspecified",
         review_why="No 'transport input' setting found on VTY lines. Many IOS versions allow Telnet by default, "
                    "so this cannot be confirmed from the config. Verify the device.",
         why="Telnet sends credentials in clear text.",
         fix={"Fortinet": ["config system interface"," edit <INTERFACE>","  set allowaccess ping https ssh"," next","end"], "Cisco": ["line vty 0 15", " transport input ssh"], "Juniper": ["delete system services telnet"]},
         rollback={"Fortinet": ["config system interface"," edit <INTERFACE>","  set allowaccess ping https ssh telnet"," next","end"], "Cisco": ["line vty 0 15", " transport input all"], "Juniper": ["set system services telnet"]}),
    dict(id="AG-03", name="HTTP management disabled", attr="http_mgmt_enabled", sev="Medium",
         ok=lambda v: v is False, nist="CM-7", certin=None,
         why="Unencrypted HTTP management service is enabled.",
         fix={"Fortinet": ["config system interface"," edit <INTERFACE>","  set allowaccess ping https ssh"," next","end"], "Cisco": ["no ip http server"], "Juniper": ["delete system services web-management http"]},
         rollback={"Fortinet": ["config system interface"," edit <INTERFACE>","  set allowaccess ping https ssh http"," next","end"], "Cisco": ["ip http server"], "Juniper": ["set system services web-management http"]}),
    dict(id="AG-04", name="Remote syslog configured", attr="remote_logging", sev="Medium",
         ok=lambda v: v is True, nist="AU-2", certin=CERTIN + ", item (iv): enable logs of ICT systems and retain them securely for a rolling 180 days (remote syslog supports this)",
         why="No remote log server found; local buffer alone is not enough for retention.",
         fix={"Fortinet": ["config log syslogd setting"," set status enable"," set server <SYSLOG_IP>","end"], "Cisco": ["logging host <SYSLOG_IP>"], "Juniper": ["set system syslog host <SYSLOG_IP> any notice"]},
         rollback={"Fortinet": ["config log syslogd setting"," set status disable","end"], "Cisco": ["no logging host <SYSLOG_IP>"], "Juniper": ["delete system syslog host <SYSLOG_IP>"]}),
    dict(id="AG-05", name="Strong privileged password hashing", attr="privileged_password", sev="High",
         ok=lambda v: v == "strong", nist="IA-5", certin=None,
         why="Privileged credential storage is '{v}' (plaintext / reversible / weak hash / missing).",
         fix={"Fortinet": ["config system admin"," edit <USER>","  set password <NEW_PASSWORD>  (stored as SHA-256)"," next","end"], "Cisco": ["enable algorithm-type scrypt secret <NEW_PASSWORD>"],
              "Juniper": ["set system login user <USER> authentication plain-text-password  (stored as SHA-512)"]},
         rollback={"Fortinet": ["(restore previous password manually)"], "Cisco": ["(restore previous secret manually)"], "Juniper": ["(restore previous password manually)"]}),
    dict(id="AG-06", name="No default SNMP community", attr="snmp_default_community", sev="High",
         ok=lambda v: v is False, nist="IA-5", certin=None,
         why="SNMP community 'public'/'private' is a well-known default.",
         fix={"Fortinet": ["config system snmp community"," delete <ID>","end"], "Cisco": ["no snmp-server community <COMMUNITY>"], "Juniper": ["delete snmp community <COMMUNITY>"]},
         rollback={"Fortinet": ["(re-create the community with a non-default name)"], "Cisco": ["snmp-server community <COMMUNITY> RO"], "Juniper": ["set snmp community <COMMUNITY> authorization read-only"]}),
    dict(id="AG-07", name="NTP time synchronisation", attr="ntp_configured", sev="Low",
         ok=lambda v: v is True, nist="AU-8", certin=CERTIN + ", item (i): synchronise ICT system clocks with the NTP servers of NIC or NPL",
         why="No NTP server configured; log timestamps are unreliable.",
         fix={"Fortinet": ["config system ntp"," set ntpsync enable"," set type custom"," config ntpserver","  edit 1","   set server <NTP_IP>","  next"," end","end"], "Cisco": ["ntp server <NTP_IP>"], "Juniper": ["set system ntp server <NTP_IP>"]},
         rollback={"Fortinet": ["config system ntp"," set ntpsync disable","end"], "Cisco": ["no ntp server <NTP_IP>"], "Juniper": ["delete system ntp server <NTP_IP>"]}),
    dict(id="AG-08", name="Login banner present", attr="login_banner", sev="Low",
         ok=lambda v: v is True, nist="AC-8", certin=None,
         why="No legal/warning banner configured.",
         fix={"Fortinet": ["config system global"," set pre-login-banner enable","end"], "Cisco": ["banner login ^Authorized access only^"], "Juniper": ['set system login message "Authorized access only"']},
         rollback={"Fortinet": ["config system global"," set pre-login-banner disable","end"], "Cisco": ["no banner login"], "Juniper": ["delete system login message"]}),
]

WEIGHT = {"High": 20, "Medium": 10, "Low": 5}


def evaluate(model, vendor):
    results = []
    for r in RULES:
        a = model[r["attr"]]
        passed = r["ok"](a["value"])
        review = (not passed) and r.get("review", lambda v: False)(a["value"])
        status = "COMPLIANT" if passed else "NEEDS REVIEW" if review else "NON-COMPLIANT"
        results.append(dict(
            id=r["id"], name=r["name"], status=status,
            severity=r["sev"], value=a["value"], evidence=a["evidence"],
            why="Meets control." if passed else (r["review_why"] if review else r["why"].format(v=a["value"])),
            nist=r["nist"], certin=r["certin"], cis=VERIFY,
            remediation=[] if passed else r["fix"][vendor],
            rollback=[] if passed else r["rollback"][vendor]))
    return results


def score(results):
    # Only confirmed violations lower the score. NEEDS REVIEW items are shown but never change it.
    return max(0, 100 - sum(WEIGHT[x["severity"]] for x in results if x["status"] == "NON-COMPLIANT"))


def overall_risk(results):
    bad = {x["severity"] for x in results if x["status"] == "NON-COMPLIANT"}
    return "HIGH" if "High" in bad else "MEDIUM" if "Medium" in bad else "LOW" if bad else "SECURE"