import json
from pathlib import Path
import streamlit as st
from adapters import detect_vendor, PARSERS
from engine import evaluate, score, overall_risk

st.set_page_config(page_title="AegisNet AI", page_icon="🛡️", layout="wide")
st.title("🛡️ AegisNet AI")
st.subheader("AI-Driven Multi-Vendor Network Security Compliance Auditor")
st.caption("Many vendor syntaxes → one Common Security Model → one deterministic, auditable verdict.")

BASE = Path(__file__).parent
SAMPLES = {
    "Cisco — weak": "samples/cisco_test.txt",
    "Cisco — hardened": "samples/cisco_hardened.txt",
    "Juniper (set) — weak": "samples/juniper_set_test.txt",
    "Juniper (curly) — partial": "samples/juniper_curly_test.cfg",
}
SAMPLES = {k: v for k, v in SAMPLES.items() if (BASE / v).exists()}


def _reset_prev():
    st.session_state["prev_score"] = None


def _load_sample():
    path = SAMPLES.get(st.session_state.get("sample_choice"))
    st.session_state["editor"] = (BASE / path).read_text(encoding="utf-8", errors="ignore") if path else ""
    st.session_state["prev_score"] = None


mode = st.radio("Input", ["Upload file", "Paste / edit config"], horizontal=True, on_change=_reset_prev)
if mode == "Upload file":
    up = st.file_uploader("📁 Upload network configuration", type=["txt", "cfg", "conf"])
    text = up.read().decode("utf-8", errors="ignore") if up is not None else ""
else:
    st.session_state.setdefault("editor", "")
    st.selectbox("Load a sample (optional)", ["(blank)"] + list(SAMPLES), key="sample_choice", on_change=_load_sample)
    text = st.text_area("Configuration. Edit it, then press Ctrl+Enter (or click outside the box) to re-audit.",
                        key="editor", height=280)
    st.caption("On the hosted demo, use sample or sanitised configs only.")

if not text.strip():
    st.info("Upload or paste a Cisco (IOS) or Juniper (set or curly-brace) configuration to begin.")
    st.stop()
vendor, conf = detect_vendor(text)
if vendor == "Unknown":
    st.error("Vendor not recognised. Audit stopped (no guessing).")
    st.stop()

model = PARSERS[vendor](text)
results = evaluate(model, vendor)
sc, risk = score(results), overall_risk(results)
bad = [r for r in results if r["status"] == "NON-COMPLIANT"]
review = [r for r in results if r["status"] == "NEEDS REVIEW"]
good = [r for r in results if r["status"] == "COMPLIANT"]

st.markdown("---")
delta = None
if mode == "Paste / edit config":
    prev = st.session_state.get("prev_score")
    if prev is not None and prev != sc:
        delta = sc - prev
    st.session_state["prev_score"] = sc
c = st.columns(6)
c[0].metric("Security Score", f"{sc}/100", delta=delta)
c[1].metric("Compliant", len(good))
c[2].metric("Non-Compliant", len(bad))
c[3].metric("Needs Review", len(review))
c[4].metric("High", sum(r["severity"] == "High" for r in bad))
c[5].metric("Overall Risk", risk)
st.write(f"**Detected vendor:** {vendor} (indicator lines: {conf}) • **Controls checked:** {len(results)}")

st.subheader("🧠 Common Security Model (vendor-neutral)")
st.dataframe([{"attribute": k, "value": str(v["value"]),
               "evidence": "; ".join(f"L{e['line']}: {e['text']}" for e in v["evidence"]) or "—"}
              for k, v in model.items()], use_container_width=True)

st.subheader(f"⚖️ Findings ({len(bad)} non-compliant, sorted by severity)")
order = {"High": 0, "Medium": 1, "Low": 2}
if not bad:
    st.success("No non-compliant controls detected.")
for r in sorted(bad, key=lambda x: order[x["severity"]]):
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

if review:
    st.subheader(f"🔎 Needs Review ({len(review)})")
    st.caption("The setting could not be confirmed from the config. These items are not counted in the score.")
    for r in review:
        with st.expander(f"🔎 {r['id']} {r['name']} — {r['severity']}", expanded=True):
            st.write(f"**Why:** {r['why']}")
            st.write(f"**NIST SP 800-53:** {r['nist']}")
            st.write("**Suggested explicit setting:**")
            st.code("\n".join(r["remediation"]), language="text")

st.subheader(f"✅ Compliant Controls ({len(good)})")
for r in good:
    with st.expander(f"✅ {r['id']} {r['name']} — {r['severity']}"):
        st.write(f"**Why:** {r['why']}")
        st.write("**Evidence:** " + ("; ".join(f"line {e['line']}: `{e['text']}`" for e in r["evidence"])
                                      or "no matching line (setting absent)"))
        st.write(f"**NIST SP 800-53:** {r['nist']}")

if bad:
    fix = "\n".join(f"! {r['id']} {r['name']}\n" + "\n".join(r["remediation"]) for r in bad)
    st.subheader("🔧 Remediation (review before applying)")
    st.code(fix, language="text")
    st.download_button("⬇️ Download remediation", fix, "aegisnet_remediation.txt")

st.download_button("📥 Download JSON report",
                   json.dumps({"vendor": vendor, "score": sc, "risk": risk,
                               "summary": {"total_controls": len(results), "non_compliant": len(bad),
                                           "needs_review": len(review), "compliant": len(good)},
                               "model": model, "findings": results},
                              indent=2, default=str), "aegisnet_report.json", "application/json")