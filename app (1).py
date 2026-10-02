import json
import streamlit as st
from adapters import detect_vendor, PARSERS
from engine import evaluate, score, overall_risk

st.set_page_config(page_title="AegisNet AI", page_icon="🛡️", layout="wide")
st.title("🛡️ AegisNet AI")
st.subheader("AI-Driven Multi-Vendor Network Security Compliance Auditor")
st.caption("Many vendor syntaxes → one Common Security Model → one deterministic, auditable verdict.")

up = st.file_uploader("📁 Upload network configuration", type=["txt", "cfg", "conf"])

if up is None:
    st.info("Upload a Cisco (IOS) or Juniper (set or curly-brace) configuration to begin.")
    st.stop()

text = up.read().decode("utf-8", errors="ignore")
vendor, conf = detect_vendor(text)
if vendor == "Unknown":
    st.error("Vendor not recognised. Audit stopped (no guessing).")
    st.stop()

model = PARSERS[vendor](text)
results = evaluate(model, vendor)
sc, risk = score(results), overall_risk(results)
bad = [r for r in results if r["status"] != "COMPLIANT"]

st.markdown("---")
c = st.columns(5)
c[0].metric("Security Score", f"{sc}/100")
c[1].metric("Compliant", len(results) - len(bad))
c[2].metric("Non-Compliant", len(bad))
c[3].metric("High", sum(r["severity"] == "High" for r in bad))
c[4].metric("Overall Risk", risk)
st.write(f"**Detected vendor:** {vendor} (indicator lines: {conf}) • **Controls checked:** {len(results)}")

st.subheader("🧠 Common Security Model (vendor-neutral)")
st.dataframe([{"attribute": k, "value": str(v["value"]),
               "evidence": "; ".join(f"L{e['line']}: {e['text']}" for e in v["evidence"]) or "—"}
              for k, v in model.items()], use_container_width=True)

st.subheader("⚖️ Findings (sorted by severity)")
order = {"High": 0, "Medium": 1, "Low": 2}
for r in sorted(results, key=lambda x: (x["status"] == "COMPLIANT", order[x["severity"]])):
    ok = r["status"] == "COMPLIANT"
    with st.expander(f"{'✅' if ok else '❌'} {r['id']} {r['name']} — {r['severity']}", expanded=not ok):
        st.write(f"**Why:** {r['why']}")
        st.write("**Evidence:** " + ("; ".join(f"line {e['line']}: `{e['text']}`" for e in r["evidence"])
                                      or "no matching line (setting absent)"))
        st.write(f"**NIST SP 800-53:** {r['nist']}")
        if r["certin"]:
            st.write(f"**CERT-In:** {r['certin']}")
        st.write(f"**CIS:** {r['cis']}")
        if not ok:
            st.code("\n".join(r["remediation"]), language="text")
            st.caption("Rollback:")
            st.code("\n".join(r["rollback"]), language="text")

if bad:
    fix = "\n".join(f"! {r['id']} {r['name']}\n" + "\n".join(r["remediation"]) for r in bad)
    st.subheader("🔧 Remediation (review before applying)")
    st.code(fix, language="text")
    st.download_button("⬇️ Download remediation", fix, "aegisnet_remediation.txt")

st.download_button("📥 Download JSON report",
                   json.dumps({"vendor": vendor, "score": sc, "risk": risk, "model": model, "findings": results},
                              indent=2, default=str), "aegisnet_report.json", "application/json")
