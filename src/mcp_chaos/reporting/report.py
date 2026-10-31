from __future__ import annotations

from pathlib import Path

from mcp_chaos.core.assessment import Assessment


def to_json(a: Assessment) -> str:
    return a.model_dump_json(indent=2)


def to_markdown(a: Assessment) -> str:
    s = a.score or {}
    L = [f"# MCP-CHAOS security assessment `{a.id}`", "",
         f"- Target: `{a.target}`", f"- Runs per variant: {a.runs_per_variant}",
         f"- **Score: {s.get('overall')}/100** - risk: **{s.get('risk')}**",
         f"- Critical findings: {s.get('critical_findings')}, high: {s.get('high_findings')}, suspicious: {s.get('suspicious')}",
         "", "> A score reflects only these sandboxed tests. It is not proof that the agent is secure.", "",
         "## Campaigns", "", "| Campaign | Category | Score | Failures | Suspicious | Inconclusive | Failure rate |", "|---|---|---|---|---|---|---|"]
    for cid, c in (s.get("campaigns") or {}).items():
        L.append(f"| {cid} | {c['category']} | {c['score']} | {c['failures']} | {c['suspicious']} | {c['inconclusive']} | {c['failure_rate']} |")
    L += ["", "## Findings", ""]
    bad = [r for r in a.runs if r.verdict.status in ("fail", "suspicious", "inconclusive")]
    if not bad:
        L.append("No failures, suspicious behaviour or inconclusive runs were observed.")
    for r in bad:
        v = r.verdict
        label = {"fail": "CONFIRMED", "suspicious": "SUSPICIOUS", "inconclusive": "INCONCLUSIVE"}[v.status]
        L += [f"### [{label} / {v.severity}] {v.title}", f"*{r.campaign} / {r.variant} / run {r.index}* - trace `{r.dir}/trace.jsonl`", "",
              f"1. **What happened:** {v.what_happened}", f"2. **Expected:** {v.expected}", f"3. **Actual:** {v.actual}",
              f"4. **Causing call:** {'#' + str(v.caused_by_seq) if v.caused_by_seq else 'n/a'}",
              "5. **Evidence:** " + ("; ".join(v.evidence) if v.evidence else "n/a"),
              f"6. **Severity:** {v.severity}", "7. **Fix:**"]
        L += [f"   - {x}" for x in v.remediation]
        L.append("")
    L += ["## Methodology", "", s.get("methodology", ""), ""]
    return "\n".join(L)


def write_reports(a: Assessment, out: Path) -> list[Path]:
    (out / "report.json").write_text(to_json(a), encoding="utf-8")
    (out / "report.md").write_text(to_markdown(a), encoding="utf-8")
    return [out / "report.json", out / "report.md"]
