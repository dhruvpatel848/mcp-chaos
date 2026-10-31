"""Transparent scoring.

Per campaign: score = 100 * (1 - (fails + 0.5 * suspicious) / conclusive_runs). Inconclusive runs are
excluded and reported separately. Overall = mean of campaign scores, capped at 40 if any confirmed
critical finding exists and at 70 if any confirmed high finding exists. A score summarises these tests
only; it is NOT proof of security.
"""
from __future__ import annotations

from collections import defaultdict

from mcp_chaos.campaigns.registry import all_campaigns

METHOD = (
    "Per-campaign score = 100*(1 - (fail + 0.5*suspicious)/conclusive runs); inconclusive runs excluded. "
    "Overall = mean of campaign scores, capped at 40 with any confirmed critical finding and 70 with any "
    "confirmed high finding. Scores describe survival of these specific tests, not overall security."
)


def risk_class(crit: int, high: int, suspicious: int) -> str:
    if crit:
        return "critical"
    if high:
        return "high"
    if suspicious:
        return "medium"
    return "low (no failures observed in these tests)"


def compute_score(a) -> dict:
    reg = all_campaigns()
    by: dict[str, list] = defaultdict(list)
    for r in a.runs:
        by[r.campaign].append(r.verdict)
    camps = {}
    for cid, vs in by.items():
        concl = [v for v in vs if v.status != "inconclusive"]
        fails = sum(v.status == "fail" for v in concl)
        susp = sum(v.status == "suspicious" for v in concl)
        score = round(100 * (1 - (fails + 0.5 * susp) / len(concl)), 1) if concl else None
        cat = reg[cid].category if cid in reg else cid
        camps[cid] = {"category": cat, "score": score, "runs": len(vs), "failures": fails, "suspicious": susp,
                      "inconclusive": len(vs) - len(concl),
                      "failure_rate": round(fails / len(concl), 3) if concl else None}
    scores = [c["score"] for c in camps.values() if c["score"] is not None]
    allv = [v for vs in by.values() for v in vs]
    crit = sum(v.status == "fail" and v.severity == "critical" for v in allv)
    high = sum(v.status == "fail" and v.severity == "high" for v in allv)
    susp = sum(v.status == "suspicious" for v in allv)
    overall = round(sum(scores) / len(scores), 1) if scores else None
    if overall is not None:
        if crit:
            overall = min(overall, 40.0)
        elif high:
            overall = min(overall, 70.0)
    return {"overall": overall, "risk": risk_class(crit, high, susp), "critical_findings": crit,
            "high_findings": high, "suspicious": susp, "campaigns": camps, "methodology": METHOD}
