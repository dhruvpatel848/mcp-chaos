"""MCP-CHAOS as an MCP server (stdio). Assessments are always sandboxed and target local agents only."""
from __future__ import annotations

import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_chaos.adapters.target import TargetError, resolve_target
from mcp_chaos.campaigns.registry import all_campaigns, resolve
from mcp_chaos.core.assessment import Assessment, run_assessment
from mcp_chaos.policies import policy as pol
from mcp_chaos.recorder.trace import load_trace
from mcp_chaos.reporting.report import to_markdown, write_reports

RUNS_ROOT = Path("runs")


def _dir(assessment_id: str) -> Path:
    """Assessment ids are folder names under ./runs; path traversal is rejected."""
    if not assessment_id or Path(assessment_id).name != assessment_id:
        raise ValueError("assessment_id must be a plain folder name under ./runs")
    d = RUNS_ROOT / assessment_id
    if not d.is_dir():
        raise ValueError(f"unknown assessment: {assessment_id}")
    return d


def build() -> FastMCP:
    mcp = FastMCP("mcp-chaos")
    jobs: dict[str, dict[str, Any]] = {}

    @mcp.tool()
    def chaos_list_campaigns() -> list[dict]:
        """List available sandboxed attack campaigns with their variants."""
        return [{"id": c.id, "name": c.name, "category": c.category, "threat": c.threat, "variants": c.variants}
                for c in all_campaigns().values()]

    @mcp.tool()
    def chaos_start_assessment(target: str, mode: str = "all", runs: int = 1, timeout: int = 120) -> dict:
        """Start a sandboxed assessment of a LOCAL agent (demo:vulnerable, demo:secure, ./agent.py, or a local command).
        Returns an assessment_id; poll chaos_get_assessment_status. Only test agents you own."""
        runs = max(1, min(runs, 10))
        timeout = max(5, min(timeout, 600))
        try:
            resolve_target(target)
            camps = resolve(mode)
        except (TargetError, KeyError) as exc:
            return {"error": str(exc)}
        aid = datetime.now().strftime("%Y-%m-%d-%H%M%S")
        out = RUNS_ROOT / aid
        jobs[aid] = {"state": "running", "error": None}

        def work() -> None:
            try:
                run_assessment(target, camps, out, runs=runs, timeout=timeout)
                write_reports(Assessment.load(out), out)
                jobs[aid]["state"] = "done"
            except Exception as exc:
                jobs[aid].update(state="error", error=f"{type(exc).__name__}: {exc}")

        threading.Thread(target=work, daemon=True).start()
        return {"assessment_id": aid, "state": "running"}

    @mcp.tool()
    def chaos_get_assessment_status(assessment_id: str) -> dict:
        """Status of an assessment: running, done or error, with completed run count."""
        d = _dir(assessment_id) if (RUNS_ROOT / assessment_id).exists() else None
        job = jobs.get(assessment_id, {"state": "done" if d and (d / "assessment.json").exists() else "unknown", "error": None})
        completed = len(list((d / "runs").glob("*/verdict.json"))) if d and (d / "runs").exists() else 0
        return {"assessment_id": assessment_id, **job, "completed_runs": completed}

    @mcp.tool()
    def chaos_get_trace(assessment_id: str, run: str) -> list[dict]:
        """Return the recorded tool-call trace of one run (folder name like data-exfil--plain-document--1)."""
        if Path(run).name != run:
            raise ValueError("run must be a plain folder name")
        return [e.model_dump() for e in load_trace(_dir(assessment_id) / "runs" / run / "trace.jsonl")]

    @mcp.tool()
    def chaos_analyze_results(assessment_id: str) -> dict:
        """Findings with evidence and remediation, grouped by status. Confirmed vs suspicious vs inconclusive."""
        a = Assessment.load(_dir(assessment_id))
        return {"findings": [{"run": r.dir, **r.verdict.model_dump()} for r in a.runs if r.verdict.status != "pass"],
                "passed_runs": sum(r.verdict.status == "pass" for r in a.runs)}

    @mcp.tool()
    def chaos_generate_policy(assessment_id: str) -> dict:
        """Generate an mcp-guard.yaml from confirmed failures. Human review required before deployment."""
        d = _dir(assessment_id)
        a = Assessment.load(d)
        p = pol.generate(a, d)
        path = d / "mcp-guard.yaml"
        if p.rules:
            path.write_text(pol.dump_policy(p), encoding="utf-8")
        return {"path": str(path) if p.rules else None, "rules": [r.id for r in p.rules],
                "policy_test": pol.test_policy(p, a, d), "review_required": True}

    @mcp.tool()
    def chaos_validate_policy(policy_path: str) -> dict:
        """Validate an mcp-guard.yaml: schema, duplicate ids, conflicts."""
        _, errors, warnings = pol.validate(Path(policy_path))
        return {"valid": not errors, "errors": errors, "warnings": warnings}

    @mcp.tool()
    def chaos_replay_attack(assessment_id: str, run: str) -> dict:
        """Step-by-step replay summary of one recorded run (same data as chaos_get_trace, condensed)."""
        ev = load_trace(_dir(assessment_id) / "runs" / run / "trace.jsonl")
        return {"steps": [{"seq": e.seq, "tool": e.tool, "args": e.arguments, "risk": e.risk, "tags": e.tags} for e in ev]}

    @mcp.tool()
    def chaos_generate_report(assessment_id: str) -> dict:
        """Write report.json and report.md for an assessment and return the markdown."""
        d = _dir(assessment_id)
        a = Assessment.load(d)
        write_reports(a, d)
        return {"markdown": to_markdown(a), "files": [str(d / "report.json"), str(d / "report.md")]}

    @mcp.tool()
    def chaos_get_security_score(assessment_id: str) -> dict:
        """Overall and per-campaign score with methodology. A score is not proof of security."""
        return Assessment.load(_dir(assessment_id)).score or {}

    return mcp
