import streamlit as st


# ==================================================
# PAGE CONFIG
# ==================================================

st.set_page_config(
    page_title="AegisNet AI",
    page_icon="🛡️",
    layout="wide"
)


# ==================================================
# CUSTOM UI
# ==================================================

st.markdown("""
<style>

.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
}

.main-title {
    font-size: 3rem;
    font-weight: 800;
}

.subtitle {
    font-size: 1.25rem;
    opacity: 0.8;
}

.capability-box {
    padding: 15px;
    border-radius: 10px;
    margin-bottom: 10px;
}

</style>
""", unsafe_allow_html=True)


# ==================================================
# SIDEBAR
# ==================================================

with st.sidebar:

    st.title("🛡️ AegisNet AI")

    st.markdown("---")

    st.subheader("System Capabilities")

    st.write("🔍 Vendor Detection")
    st.write("🧠 Security Intent Normalization")
    st.write("⚖️ Compliance Auditing")
    st.write("📊 Security Scoring")
    st.write("🧠 Risk Prioritization")
    st.write("🏛️ Compliance Mapping")
    st.write("🔧 Automated Remediation")
    st.write("📥 Downloadable Reports")

    st.markdown("---")

    st.caption(
        "SIH 2026 • Network Security Compliance Auditor"
    )


# ==================================================
# TITLE
# ==================================================

st.title("🛡️ AegisNet AI")

st.subheader(
    "AI-Driven Multi-Vendor Network Security Compliance Auditor"
)

st.write("""
Upload a network device configuration to automatically detect the vendor,
extract vendor-specific security controls, convert them into a vendor-neutral
security representation, perform a unified security compliance audit,
prioritize security risks, map findings to security best practices,
and generate vendor-specific remediation commands.
""")

st.markdown("---")


# ==================================================
# VENDOR DETECTION
# ==================================================

def detect_vendor(config):

    config_lower = config.lower()

    cisco_score = 0
    juniper_score = 0

    # Cisco indicators

    cisco_keywords = [

        "hostname",

        "ip ssh",

        "ip http",

        "service password-encryption",

        "enable secret",

        "logging buffered"

    ]


    # Juniper indicators

    juniper_keywords = [

        "set system",

        "set services",

        "set system services ssh",

        "set system services web-management",

        "set system login",

        "set system syslog"

    ]


    for keyword in cisco_keywords:

        if keyword in config_lower:

            cisco_score += 1


    for keyword in juniper_keywords:

        if keyword in config_lower:

            juniper_score += 1


    if cisco_score > juniper_score and cisco_score > 0:

        return "Cisco", cisco_score


    elif juniper_score > cisco_score and juniper_score > 0:

        return "Juniper", juniper_score


    else:

        return "Unknown", 0


# ==================================================
# SECURITY CONTROL EXTRACTION
# ==================================================

def extract_security_controls(config, vendor):

    config_lower = config.lower()


    controls = {

        "SSH Version": "Not Detected",

        "HTTP Server": "Not Detected",

        "Password Encryption": "Not Detected",

        "Logging": "Not Detected"

    }


    # ----------------------------------------------
    # CISCO
    # ----------------------------------------------

    if vendor == "Cisco":


        # SSH

        if "ip ssh version 2" in config_lower:

            controls["SSH Version"] = "Version 2"


        elif "ip ssh version 1" in config_lower:

            controls["SSH Version"] = "Version 1"


        # HTTP

        if "no ip http server" in config_lower:

            controls["HTTP Server"] = "Disabled"


        elif "ip http server" in config_lower:

            controls["HTTP Server"] = "Enabled"


        # PASSWORD ENCRYPTION

        if (

            "service password-encryption" in config_lower

            or "enable secret" in config_lower

        ):

            controls["Password Encryption"] = "Enabled"


        # LOGGING

        if "logging" in config_lower:

            controls["Logging"] = "Enabled"



    # ----------------------------------------------
    # JUNIPER
    # ----------------------------------------------

    elif vendor == "Juniper":


        # SSH

        if (

            "ssh protocol-version v2" in config_lower

            or "ssh protocol-version 2" in config_lower

            or "set system services ssh" in config_lower

        ):

            controls["SSH Version"] = "Version 2"


        # HTTP

        if (

            "web-management http" in config_lower

            or "set system services web-management http"
            in config_lower

        ):

            controls["HTTP Server"] = "Enabled"


        # Password Encryption

        if (

            "authentication encrypted-password"
            in config_lower

            or "encrypted-password"
            in config_lower

        ):

            controls["Password Encryption"] = "Enabled"


        # Logging

        if (

            "syslog" in config_lower

            or "set system syslog"
            in config_lower

        ):

            controls["Logging"] = "Enabled"


    return controls


# ==================================================
# COMPLIANCE AUDIT
# ==================================================

def audit_controls(controls):

    results = []


    # ----------------------------------------------
    # SSH VERSION
    # ----------------------------------------------

    ssh_value = controls["SSH Version"]


    if ssh_value == "Version 2":

        results.append({

            "control": "SSH Version",

            "status": "COMPLIANT",

            "risk": "Low",

            "why":
            "Secure SSH Version 2 is enabled.",

            "recommendation":
            "No action required."

        })


    else:

        results.append({

            "control": "SSH Version",

            "status": "NON-COMPLIANT",

            "risk": "High",

            "why":
            "Secure SSH configuration is missing "
            "or an insecure SSH version is used.",

            "recommendation":
            "Configure SSH Version 2."

        })


    # ----------------------------------------------
    # HTTP SERVER
    # ----------------------------------------------

    http_value = controls["HTTP Server"]


    if http_value == "Disabled":

        results.append({

            "control": "HTTP Server",

            "status": "COMPLIANT",

            "risk": "Low",

            "why":
            "Insecure HTTP management service is disabled.",

            "recommendation":
            "No action required."

        })


    else:

        results.append({

            "control": "HTTP Server",

            "status": "NON-COMPLIANT",

            "risk": "Medium",

            "why":
            "HTTP management may expose "
            "insecure communication.",

            "recommendation":
            "Disable the HTTP server if it "
            "is not required."

        })


    # ----------------------------------------------
    # PASSWORD ENCRYPTION
    # ----------------------------------------------

    password_value = controls["Password Encryption"]


    if password_value == "Enabled":

        results.append({

            "control": "Password Encryption",

            "status": "COMPLIANT",

            "risk": "Low",

            "why":
            "Password protection is configured.",

            "recommendation":
            "No action required."

        })


    else:

        results.append({

            "control": "Password Encryption",

            "status": "NON-COMPLIANT",

            "risk": "Medium",

            "why":
            "Password encryption is not detected.",

            "recommendation":
            "Enable secure password encryption."

        })


    # ----------------------------------------------
    # LOGGING
    # ----------------------------------------------

    logging_value = controls["Logging"]


    if logging_value == "Enabled":

        results.append({

            "control": "Logging",

            "status": "COMPLIANT",

            "risk": "Low",

            "why":
            "Security logging is enabled.",

            "recommendation":
            "No action required."

        })


    else:

        results.append({

            "control": "Logging",

            "status": "NON-COMPLIANT",

            "risk": "Medium",

            "why":
            "Security logging is not detected.",

            "recommendation":
            "Enable security logging."

        })


    return results


# ==================================================
# SECURITY SCORE
# ==================================================

def calculate_security_score(results):

    score = 100


    for result in results:


        if result["status"] == "NON-COMPLIANT":


            if result["risk"] == "High":

                score -= 30


            elif result["risk"] == "Medium":

                score -= 15


            elif result["risk"] == "Low":

                score -= 5


    return max(score, 0)


# ==================================================
# OVERALL RISK
# ==================================================

def get_overall_risk(results):

    high_risk = sum(

        1 for r in results

        if r["status"] == "NON-COMPLIANT"

        and r["risk"] == "High"

    )


    medium_risk = sum(

        1 for r in results

        if r["status"] == "NON-COMPLIANT"

        and r["risk"] == "Medium"

    )


    if high_risk > 0:

        return "MEDIUM", "🟠"


    elif medium_risk > 0:

        return "LOW", "🟡"


    else:

        return "SECURE", "🟢"


# ==================================================
# RISK PRIORITIZATION
# ==================================================

def prioritize_risks(results):

    priority_list = []


    for result in results:


        if result["status"] == "NON-COMPLIANT":


            if result["risk"] == "High":

                priority_score = 85

                priority_level = "CRITICAL"

                icon = "🔴"


            elif result["risk"] == "Medium":

                priority_score = 55

                priority_level = "MEDIUM"

                icon = "🟡"


            else:

                priority_score = 25

                priority_level = "LOW"

                icon = "🟢"


            priority_list.append({

                "control":
                result["control"],

                "risk":
                result["risk"],

                "priority_score":
                priority_score,

                "priority_level":
                priority_level,

                "recommendation":
                result["recommendation"],

                "icon":
                icon

            })


    priority_list.sort(

        key=lambda x: x["priority_score"],

        reverse=True

    )


    return priority_list


# ==================================================
# COMPLIANCE FRAMEWORK MAPPING
# ==================================================

def get_compliance_mapping(audit_results):


    framework_mapping = {


        "SSH Version": {

            "best_practice":
            "Secure Remote Administrative Access",

            "nist":
            "NIST SP 800-53 AC-17",

            "cis":
            "CIS Secure Configuration Best Practices"

        },


        "HTTP Server": {

            "best_practice":
            "Disable Unnecessary Management Services",

            "nist":
            "NIST SP 800-53 CM-7",

            "cis":
            "CIS Secure Configuration Best Practices"

        },


        "Password Encryption": {

            "best_practice":
            "Secure Credential Protection",

            "nist":
            "NIST SP 800-53 IA-5",

            "cis":
            "CIS Credential Protection Practices"

        },


        "Logging": {

            "best_practice":
            "Security Event Logging and Monitoring",

            "nist":
            "NIST SP 800-53 AU-2",

            "cis":
            "CIS Security Logging Practices"

        }

    }


    mapping_results = []


    for result in audit_results:


        control = result["control"]


        mapping_results.append({

            "control":
            control,

            "status":
            result["status"],

            "best_practice":
            framework_mapping[control]["best_practice"],

            "nist":
            framework_mapping[control]["nist"],

            "cis":
            framework_mapping[control]["cis"]

        })


    return mapping_results


# ==================================================
# AUTOMATED REMEDIATION
# ==================================================

def generate_remediation(results, vendor):

    remediation_commands = []


    for result in results:


        if result["status"] == "NON-COMPLIANT":


            control = result["control"]


            # --------------------------------------
            # CISCO
            # --------------------------------------

            if vendor == "Cisco":


                if control == "SSH Version":

                    remediation_commands.append(
                        "ip ssh version 2"
                    )


                elif control == "HTTP Server":

                    remediation_commands.append(
                        "no ip http server"
                    )


                elif control == "Password Encryption":

                    remediation_commands.append(
                        "service password-encryption"
                    )


                elif control == "Logging":

                    remediation_commands.append(
                        "logging buffered 4096"
                    )


            # --------------------------------------
            # JUNIPER
            # --------------------------------------

            elif vendor == "Juniper":


                if control == "SSH Version":

                    remediation_commands.append(
                        "set system services ssh"
                    )


                elif control == "HTTP Server":

                    remediation_commands.append(
                        "delete system services "
                        "web-management http"
                    )


                elif control == "Password Encryption":

                    remediation_commands.append(
                        "set system login password "
                        "format sha512"
                    )


                elif control == "Logging":

                    remediation_commands.append(
                        "set system syslog file "
                        "messages any notice"
                    )


    return remediation_commands


# ==================================================
# FILE UPLOAD
# ==================================================

uploaded_file = st.file_uploader(

    "📁 Upload Network Configuration",

    type=["txt", "cfg", "conf"]

)


# ==================================================
# MAIN APPLICATION
# ==================================================

if uploaded_file is not None:


    config = uploaded_file.read().decode(

        "utf-8",

        errors="ignore"

    )


    st.success(

        f"Configuration '{uploaded_file.name}' "
        "uploaded successfully!"

    )


    # ----------------------------------------------
    # ANALYSIS
    # ----------------------------------------------

    vendor, detection_score = detect_vendor(config)


    controls = extract_security_controls(

        config,

        vendor

    )


    audit_results = audit_controls(

        controls

    )


    security_score = calculate_security_score(

        audit_results

    )


    priority_list = prioritize_risks(

        audit_results

    )


    compliance_mapping = get_compliance_mapping(

        audit_results

    )


    remediation_commands = generate_remediation(

        audit_results,

        vendor

    )


    overall_risk, risk_icon = get_overall_risk(

        audit_results

    )


    # ----------------------------------------------
    # COUNTS
    # ----------------------------------------------

    compliant_count = sum(

        1 for r in audit_results

        if r["status"] == "COMPLIANT"

    )


    non_compliant_count = sum(

        1 for r in audit_results

        if r["status"] == "NON-COMPLIANT"

    )


    high_risk_count = sum(

        1 for r in audit_results

        if r["status"] == "NON-COMPLIANT"

        and r["risk"] == "High"

    )


    medium_risk_count = sum(

        1 for r in audit_results

        if r["status"] == "NON-COMPLIANT"

        and r["risk"] == "Medium"

    )


    # ==================================================
    # SECURITY OVERVIEW
    # ==================================================

    st.markdown("---")

    st.subheader("🛡️ Security Overview")


    col1, col2, col3, col4, col5 = st.columns(5)


    with col1:

        st.metric(

            "Security Score",

            f"{security_score}/100"

        )


    with col2:

        st.metric(

            "Compliant",

            compliant_count

        )


    with col3:

        st.metric(

            "Non-Compliant",

            non_compliant_count

        )


    with col4:

        st.metric(

            "High Risk",

            high_risk_count

        )


    with col5:

        st.metric(

            "Medium Risk",

            medium_risk_count

        )


    st.markdown(

        f"### {risk_icon} Overall Risk Level: {overall_risk}"

    )


    # ==================================================
    # CONFIGURATION ANALYSIS
    # ==================================================

    st.markdown("---")

    st.subheader("🔍 Configuration Analysis")


    col1, col2, col3 = st.columns(3)


    with col1:

        st.write("**Detected Vendor**")

        st.write(vendor)


    with col2:

        st.write("**Detection Score**")

        st.code(str(detection_score))


    with col3:

        st.write("**Configuration Size**")

        st.write(

            f"{len(config)} chars"

        )


    # ==================================================
    # VENDOR NEUTRAL SECURITY INTENT
    # ==================================================

    st.markdown("---")

    st.subheader(

        "🧠 Vendor-Neutral Security Intent"

    )


    st.write("""

AegisNet converts vendor-specific configuration commands
into a common vendor-neutral security representation.

This enables the same compliance engine to analyze
different network vendors.

""")


    for control, value in controls.items():


        col1, col2 = st.columns(2)


        with col1:

            st.write(

                f"**{control}**"

            )


        with col2:

            st.write(value)


    # ==================================================
    # SECURITY COMPLIANCE AUDIT
    # ==================================================

    st.markdown("---")

    st.subheader(

        "⚖️ Security Compliance Audit"

    )


    for result in audit_results:


        if result["status"] == "COMPLIANT":


            st.success(

                f"✅ {result['control']} "
                "— COMPLIANT"

            )


        else:


            st.error(

                f"❌ {result['control']} "
                "— NON-COMPLIANT"

            )


        st.write(

            f"**Risk Level:** "
            f"{result['risk']}"

        )


        st.write(

            f"**Status:** "
            f"{result['status']}"

        )


        st.write(

            f"**Why:** "
            f"{result['why']}"

        )


        st.write(

            f"**Recommendation:** "
            f"{result['recommendation']}"

        )


        st.markdown("---")


    # ==================================================
    # COMPLIANCE FRAMEWORK MAPPING
    # ==================================================

    st.subheader(

        "🏛️ Compliance Framework Mapping"

    )


    st.write("""

AegisNet maps vendor-neutral security controls
to recognized security best practices and
compliance framework concepts.

The prototype currently demonstrates mappings
based on NIST security control concepts and
CIS secure configuration best practices.

""")


    for item in compliance_mapping:


        if item["status"] == "COMPLIANT":

            status_icon = "✅"

        else:

            status_icon = "❌"


        with st.expander(

            f"{status_icon} "
            f"{item['control']}"

        ):


            st.write(

                f"**Compliance Status:** "
                f"{item['status']}"

            )


            st.write(

                f"**Security Best Practice:** "
                f"{item['best_practice']}"

            )


            st.write(

                f"**NIST Reference:** "
                f"{item['nist']}"

            )


            st.write(

                f"**CIS Alignment:** "
                f"{item['cis']}"

            )


    # ==================================================
    # INTELLIGENT RISK PRIORITIZATION
    # ==================================================

    st.markdown("---")

    st.subheader(

        "🧠 Intelligent Risk Prioritization"

    )


    st.write("""

AegisNet prioritizes non-compliant controls
based on security severity.

Higher-risk issues are ranked first to help
administrators focus on the most important
security problems.

""")


    if len(priority_list) == 0:


        st.success(

            "No non-compliant controls detected."

        )


    else:


        for index, risk in enumerate(

            priority_list,

            start=1

        ):


            st.markdown(

                f"""
### {risk['icon']} Priority #{index}:
{risk['control']} — {risk['priority_level']}

**Priority Score:**
{risk['priority_score']}/100

**Security Risk:**
{risk['risk']}

**Recommended Action:**
{risk['recommendation']}
"""

            )


            st.markdown("---")


    # ==================================================
    # AUTOMATED REMEDIATION
    # ==================================================

    st.subheader(

        "🔧 Automated Security Remediation"

    )


    st.write("""

Based on the detected vendor and security findings,
AegisNet generates vendor-specific configuration
commands to remediate non-compliant controls.

""")


    if vendor == "Unknown":


        st.warning(

            "Vendor could not be identified. "
            "Automated remediation is unavailable."

        )


    elif len(remediation_commands) == 0:


        st.success(

            "No remediation required. "
            "All analyzed controls are compliant."

        )


    else:


        st.warning(

            f"Recommended {vendor} "
            "Security Configuration"

        )


        remediation_text = f"""! ===========================================
! AEGISNET AI SECURITY REMEDIATION
! ===========================================
! Vendor: {vendor}
! Generated Automatically
! ===========================================

"""


        for command in remediation_commands:


            remediation_text += (

                command + "\n"

            )


        st.code(

            remediation_text,

            language="text"

        )


        st.info("""

⚠️ IMPORTANT: Review and validate all
generated commands before applying them
to a production network device.

""")


        st.download_button(

            label=
            "⬇️ Download Remediation Configuration",

            data=remediation_text,

            file_name=
            "aegisnet_remediation.txt",

            mime=
            "text/plain"

        )


    # ==================================================
    # SECURITY AUDIT REPORT
    # ==================================================

    st.markdown("---")

    st.subheader(

        "📊 AI Security Audit Report"

    )


    st.write("""

Generate a complete structured report containing
vendor analysis, normalized security controls,
compliance findings, risk priorities,
compliance framework mapping,
and remediation actions.

""")


    report = f"""
==================================================
              AEGISNET AI
          NETWORK SECURITY AUDIT REPORT
==================================================

SIH 2026
AI-Driven Multi-Vendor Network Security
Compliance Auditor

==================================================
CONFIGURATION ANALYSIS
==================================================

Detected Vendor:
{vendor}

Vendor Detection Score:
{detection_score}

Configuration Size:
{len(config)} characters


==================================================
SECURITY OVERVIEW
==================================================

Security Score:
{security_score}/100

Overall Risk Level:
{overall_risk}

Compliant Controls:
{compliant_count}

Non-Compliant Controls:
{non_compliant_count}

High Risk Issues:
{high_risk_count}

Medium Risk Issues:
{medium_risk_count}


==================================================
VENDOR-NEUTRAL SECURITY INTENT
==================================================

"""


    for control, value in controls.items():

        report += (

            f"{control}: {value}\n"

        )


    report += """

==================================================
SECURITY COMPLIANCE AUDIT
==================================================

"""


    for result in audit_results:


        report += f"""
Control:
{result['control']}

Status:
{result['status']}

Risk Level:
{result['risk']}

Reason:
{result['why']}

Recommendation:
{result['recommendation']}

--------------------------------------------------

"""


    report += """

==================================================
COMPLIANCE FRAMEWORK MAPPING
==================================================

"""


    for item in compliance_mapping:


        report += f"""
Security Control:
{item['control']}

Compliance Status:
{item['status']}

Security Best Practice:
{item['best_practice']}

NIST Reference:
{item['nist']}

CIS Alignment:
{item['cis']}

--------------------------------------------------

"""


    report += """

==================================================
INTELLIGENT RISK PRIORITIZATION
==================================================

"""


    if len(priority_list) == 0:


        report += (

            "No non-compliant controls detected.\n"

        )


    else:


        for index, risk in enumerate(

            priority_list,

            start=1

        ):


            report += f"""
Priority #{index}

Control:
{risk['control']}

Priority Level:
{risk['priority_level']}

Priority Score:
{risk['priority_score']}/100

Security Risk:
{risk['risk']}

Recommended Action:
{risk['recommendation']}

--------------------------------------------------

"""


    report += """

==================================================
AUTOMATED REMEDIATION
==================================================

"""


    if len(remediation_commands) == 0:


        report += (

            "No remediation required.\n"

        )


    else:


        for command in remediation_commands:


            report += (

                command + "\n"

            )


    report += """

==================================================
END OF AEGISNET AI SECURITY REPORT
==================================================
"""


    st.download_button(

        label=
        "📥 Download Full Security Audit Report",

        data=
        report,

        file_name=
        "aegisnet_security_report.txt",

        mime=
        "text/plain"

    )


    # ==================================================
    # VIEW CONFIGURATION
    # ==================================================

    st.markdown("---")


    with st.expander(

        "📄 View Uploaded Configuration"

    ):


        st.code(

            config,

            language="text"

        )


# ==================================================
# HOME SCREEN
# ==================================================

else:


    st.markdown("---")

    st.subheader(

        "🚀 How AegisNet AI Works"

    )


    col1, col2, col3, col4 = st.columns(4)


    with col1:

        st.markdown("""

### 1️⃣ Upload

Upload a Cisco or Juniper
network configuration.

""")


    with col2:

        st.markdown("""

### 2️⃣ Analyze

Automatically detect the vendor
and extract security controls.

""")


    with col3:

        st.markdown("""

### 3️⃣ Audit

Normalize security intent and
perform compliance analysis.

""")


    with col4:

        st.markdown("""

### 4️⃣ Remediate

Prioritize risks and generate
vendor-specific remediation.

""")


    st.markdown("---")


    st.subheader(

        "🔄 AegisNet AI Security Intelligence Pipeline"

    )


    st.code("""

Upload Network Configuration
            ↓
Automatic Vendor Detection
            ↓
Vendor-Specific Security Parsing
            ↓
Vendor-Neutral Security Intent
            ↓
Unified Compliance Audit
            ↓
Security Score Generation
            ↓
Compliance Framework Mapping
            ↓
Intelligent Risk Prioritization
            ↓
Automated Vendor-Specific Remediation
            ↓
Downloadable Security Audit Report

""")