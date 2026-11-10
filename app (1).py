import json
from pathlib import Path
import streamlit as st
from adapters import detect_vendor, PARSERS
from engine import evaluate, score, overall_risk
from fleet import audit_fleet
import hashlib
import ai

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
    "Fortinet — weak": "samples/fortinet_weak.conf",
    "Fortinet — hardened": "samples/fortinet_hardened.conf",
    "Palo Alto (AI demo, no adapter)": "samples/paloalto_demo.conf",
}
SAMPLES = {k: v for k, v in SAMPLES.items() if (BASE / v).exists()}


def _reset_prev():
    st.session_state["prev_score"] = None


def _load_sample():
    path = SAMPLES.get(st.session_state.get("sample_choice"))
    st.session_state["editor"] = (BASE / path).read_text(encoding="utf-8", errors="ignore") if path else ""
    st.session_state["prev_score"] = None


FLEET = "Fleet audit (multiple files)"
mode = st.radio("Input", ["Upload file", "Paste / edit config", FLEET], horizontal=True, on_change=_reset_prev)


def run_fleet():
    st.caption("Upload several device configs (any mix of Cisco, Juniper, Fortinet) or load the built-in demo fleet.")
    files = st.file_uploader("📁 Upload configs", type=["txt", "cfg", "conf"], accept_multiple_files=True, key="fleet_files")
    demo = st.checkbox("Use the demo fleet (all sample configs)")
    items = [(f.name, f.read().decode("utf-8", errors="ignore")) for f in files]
    if demo:
        items += [(Path(p).name, (BASE / p).read_text(encoding="utf-8", errors="ignore")) for p in SAMPLES.values()]
        unk = BASE / "samples/unknown.txt"
        if unk.exists():
            items.append((unk.name, unk.read_text(encoding="utf-8", errors="ignore")))
    if not items:
        st.info("Upload two or more configs, or tick the demo fleet, to see a fleet-wide score.")
        return
    rows, summ = audit_fleet(items)
    c = st.columns(4)
    c[0].metric("Devices audited", f"{summ['devices_audited']}/{summ['devices_total']}")
    c[1].metric("Fleet average score", "-" if summ["average_score"] is None else f"{summ['average_score']}/100")
    c[2].metric("Worst device", summ["worst_device"] or "-")
    c[3].metric("Vendors", ", ".join(f"{k} {v}" for k, v in summ["by_vendor"].items()) or "-")
    st.subheader("🏢 Fleet scoreboard (lowest score first)")
    st.dataframe([{"device": r["device"], "vendor": r["vendor"], "result": r["status"] if r["status"] != "Audited" else "Audited",
                   "score": r.get("score"), "risk": r.get("risk"), "non-compliant": r.get("non_compliant"),
                   "high": r.get("high"), "needs review": r.get("needs_review"), "failed controls": r.get("failed_controls")}
                  for r in rows], use_container_width=True)
    if summ["top_failing_controls"]:
        st.subheader("🔁 Most common failures across the fleet")
        st.dataframe([{"control": k, "devices failing": v} for k, v in summ["top_failing_controls"]], use_container_width=True)
    st.download_button("📥 Download fleet JSON report",
                       json.dumps({"summary": summ, "devices": [{k: v for k, v in r.items()} for r in rows]},
                                  indent=2, default=str), "aegisnet_fleet_report.json", "application/json")
    st.caption("To see evidence and fixes for one device, switch to Paste / edit config and load it.")


if mode == FLEET:
    run_fleet()
    st.stop()

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
    st.info("Upload or paste a Cisco (IOS), Juniper (set or curly-brace) or Fortinet (FortiOS) configuration to begin. Other vendors can be tried with the AI interpretation.")
    st.stop()
vendor, conf = detect_vendor(text)
KEY = ai.get_key(st)
text_id = hashlib.sha256(text.encode()).hexdigest()[:16]
ai_mode, ai_info = False, None
if vendor == "Unknown":
    st.error("Vendor not recognised by the built-in adapters. The rule-based audit stopped (no guessing).")
    if not KEY:
        st.info("Optional: add GEMINI_API_KEY in Streamlit Secrets to let the AI try to interpret an unfamiliar vendor.")
        st.stop()
    cache = st.session_state.setdefault("ai_interp", {})
    if st.button("🤖 Try AI interpretation (experimental)"):
        with st.spinner("AI is mapping the config onto the common security model..."):
            m, i, err = ai.interpret(KEY, text)
        if err:
            st.error(f"AI unavailable: {err}")
            st.stop()
        cache[text_id] = (m, i)
    if text_id not in cache:
        st.stop()
    model, ai_info = cache[text_id]
    vendor, ai_mode = "AI-inferred", True
else:
    model = PARSERS[vendor](text)
results = evaluate(model, vendor)
if ai_mode:
    results = ai.apply_review(results, ai_info)
    st.warning("🤖 AI-inferred result. Every setting below was checked against a real line in your config; anything the AI "
               "could not prove, or was unsure about, is under Needs Review and is not scored. The score is indicative only. "
               "The rule engine, not the AI, decides compliance.")
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

if KEY:
    st.subheader("🤖 AI explanation")
    ex = st.session_state.setdefault("ai_explain", {})
    if st.button("Explain these findings with AI"):
        with st.spinner("AI is writing the explanation..."):
            txt, err = ai.explain(KEY, vendor, sc, risk, results)
        if err:
            st.error(f"AI unavailable: {err}")
        else:
            ex[text_id] = txt
    if text_id in ex:
        st.info(ex[text_id])
        st.caption("AI wrote this explanation from the audit results only. It cannot change any score or verdict.")
else:
    st.caption("🤖 AI explanation is available when GEMINI_API_KEY is set in Streamlit Secrets.")

if bad:
    fix ="\n".join(f"! {r['id']} {r['name']}\n" + "\n".join(r["remediation"]) for r in bad)
    st.subheader("🔧 Remediation (review before applying)")
    st.code(fix, language="text")
    st.download_button("⬇️ Download remediation", fix, "aegisnet_remediation.txt")

st.download_button("📥 Download JSON report",
                   json.dumps({"vendor": vendor, "score": sc, "risk": risk,
                               "summary": {"total_controls": len(results), "non_compliant": len(bad),
                                           "needs_review": len(review), "compliant": len(good)},
                               "model": model, "findings": results},
                              indent=2, default=str), "aegisnet_report.json", "application/json")
