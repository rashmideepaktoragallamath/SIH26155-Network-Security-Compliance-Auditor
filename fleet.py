"""Fleet audit: run the same deterministic audit over many device configs and summarise."""
from adapters import detect_vendor, PARSERS
from engine import evaluate, score, overall_risk


def audit_one(name, text):
    """Audit one config. Returns a summary row plus the full results, or an error row."""
    if not text.strip():
        return {"device": name, "vendor": "-", "status": "Skipped (empty file)"}
    vendor, _ = detect_vendor(text)
    if vendor == "Unknown":
        return {"device": name, "vendor": "Unknown", "status": "Vendor not recognised"}
    results = evaluate(PARSERS[vendor](text), vendor)
    bad = [r for r in results if r["status"] == "NON-COMPLIANT"]
    return {
        "device": name, "vendor": vendor, "status": "Audited",
        "score": score(results), "risk": overall_risk(results),
        "non_compliant": len(bad),
        "high": sum(r["severity"] == "High" for r in bad),
        "needs_review": sum(r["status"] == "NEEDS REVIEW" for r in results),
        "failed_controls": ", ".join(r["id"] for r in bad) or "-",
        "results": results,
    }


def audit_fleet(items):
    """items: list of (name, text). Returns (rows, summary)."""
    rows = [audit_one(n, t) for n, t in items]
    ok = [r for r in rows if r["status"] == "Audited"]
    summary = {
        "devices_total": len(rows), "devices_audited": len(ok),
        "average_score": round(sum(r["score"] for r in ok) / len(ok), 1) if ok else None,
        "worst_device": min(ok, key=lambda r: r["score"])["device"] if ok else None,
        "by_vendor": {v: sum(r["vendor"] == v for r in ok) for v in sorted({r["vendor"] for r in ok})},
    }
    # most common failing controls across the fleet
    counts = {}
    for r in ok:
        for x in r["results"]:
            if x["status"] == "NON-COMPLIANT":
                key = f'{x["id"]} {x["name"]}'
                counts[key] = counts.get(key, 0) + 1
    summary["top_failing_controls"] = sorted(counts.items(), key=lambda kv: -kv[1])
    return sorted(rows, key=lambda r: r.get("score", 1000)), summary
