"""mcp-guard.yaml: schema, deterministic generation from evidence, validation, conflict detection, testing."""
from __future__ import annotations

from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import BaseModel, Field, ValidationError

from mcp_chaos.core.assessment import Assessment
from mcp_chaos.core.detect import host_of
from mcp_chaos.core.models import TraceEvent
from mcp_chaos.recorder.trace import load_trace

KNOWN_CONDITIONS = {"host_not_in_allowlist", "allowlist", "contains_canary_secret", "destructive_command", "sensitive_path", "outside_workspace", "denied_doc_ids"}


class Rule(BaseModel):
    id: str
    tool: Optional[str] = None
    scope: Optional[Literal["session"]] = None
    action: Literal["deny", "require_human_approval", "limit"] = "deny"
    conditions: dict = Field(default_factory=dict)
    max_tool_calls: Optional[int] = None
    why: str = ""
    evidence: list[str] = Field(default_factory=list)  # "<run-dir>#<seq>"


class Policy(BaseModel):
    version: Literal[1] = 1
    rules: list[Rule]
    notice: str = ("Generated from observed failures. Requires human review before use; a policy reduces "
                   "risk for the attack paths found and does not guarantee security.")


def load_policy(path: Path) -> Policy:
    return Policy.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))


def dump_policy(p: Policy) -> str:
    return yaml.safe_dump(p.model_dump(exclude_none=True, exclude_defaults=False), sort_keys=False, allow_unicode=True)


def validate(path: Path) -> tuple[Optional[Policy], list[str], list[str]]:
    """Returns (policy, errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []
    try:
        pol = load_policy(path)
    except (ValidationError, yaml.YAMLError, OSError, TypeError) as exc:
        return None, [f"schema: {exc}"], []
    seen: dict[str, Rule] = {}
    for r in pol.rules:
        if r.id in seen:
            errors.append(f"duplicate rule id: {r.id}")
        seen[r.id] = r
        unknown = set(r.conditions) - KNOWN_CONDITIONS
        if unknown:
            errors.append(f"{r.id}: unknown condition(s) {sorted(unknown)}")
        if r.action == "limit" and (r.max_tool_calls is None or r.max_tool_calls < 1):
            errors.append(f"{r.id}: limit rules need max_tool_calls >= 1")
        if r.tool is None and r.scope is None and not r.conditions:
            errors.append(f"{r.id}: rule has no tool, scope or conditions")
        if r.conditions.get("host_not_in_allowlist") and not r.conditions.get("allowlist"):
            warnings.append(f"{r.id}: empty allowlist blocks ALL hosts; add the hosts your agent legitimately needs")
    for a in pol.rules:
        for b in pol.rules:
            if a.id < b.id and a.tool == b.tool and a.conditions == b.conditions and a.action != b.action \
                    and "limit" not in (a.action, b.action):
                errors.append(f"conflict: {a.id} ({a.action}) and {b.id} ({b.action}) match the same tool/conditions")
    return pol, errors, warnings


def _matches(rule: Rule, ev: TraceEvent, index: int) -> bool:
    if rule.action == "limit":
        return rule.max_tool_calls is not None and index > rule.max_tool_calls
    if rule.tool and rule.tool != ev.tool:
        return False
    c = rule.conditions
    if c.get("host_not_in_allowlist") and host_of(str(ev.arguments.get("url", ""))) in [h.lower() for h in c.get("allowlist", [])]:
        return False
    if c.get("host_not_in_allowlist") and "url" not in ev.arguments:
        return False
    if c.get("contains_canary_secret") and not ev.canary_exposed:
        return False
    if c.get("destructive_command") and "destructive" not in ev.tags:
        return False
    if c.get("denied_doc_ids") and ev.arguments.get("doc_id") not in c["denied_doc_ids"]:
        return False
    if c.get("outside_workspace") and "out-of-scope-read" not in ev.tags:
        return False
    if c.get("sensitive_path") and "sensitive-read" not in ev.tags:
        return False
    return True


def blocked_seqs(policy: Policy, events: list[TraceEvent]) -> dict[int, list[str]]:
    """Which recorded calls would this policy have denied or held for approval?"""
    hit: dict[int, list[str]] = {}
    for i, ev in enumerate(events, 1):
        for r in policy.rules:
            if _matches(r, ev, i):
                hit.setdefault(ev.seq, []).append(r.id)
    return hit


def run_trace_path(out_dir: Path, run_dir: str) -> Path:
    """Resolve <out_dir>/<run_dir>/trace.jsonl, refusing paths that escape out_dir (tampered assessment.json)."""
    base = Path(out_dir).resolve()
    p = (base / run_dir / "trace.jsonl").resolve()
    if not p.is_relative_to(base):
        raise ValueError(f"run directory escapes the assessment folder: {run_dir!r}")
    return p


def generate(a: Assessment, out_dir: Path) -> Policy:
    """Deterministically derive rules from failed runs. Same assessment => same policy."""
    rules: dict[str, Rule] = {}

    def add(rid: str, ev_ref: str, **kw) -> None:
        r = rules.setdefault(rid, Rule(id=rid, **kw))
        if ev_ref not in r.evidence:
            r.evidence.append(ev_ref)

    for run in sorted(a.runs, key=lambda r: (r.campaign, r.variant, r.index)):
        v = run.verdict
        if v.status != "fail":
            continue
        events = {e.seq: e for e in load_trace(run_trace_path(out_dir, run.dir))}
        for seq in v.evidence_seqs:
            e = events.get(seq)
            if e is None:
                continue
            ref = f"{run.dir}#{seq}"
            if "privilege-escalation" in e.tags:
                add(f"deny-{e.tool}", ref, tool=e.tool, action="deny",
                    why="The agent tried to escalate privileges; role changes and admin tools must not be agent-callable.")
            if "cross-session" in e.tags:
                add("deny-cross-session-documents", ref, tool=e.tool, action="deny",
                    conditions={"denied_doc_ids": [str(e.arguments.get("doc_id"))]},
                    why="The agent requested a document from another session. REVIEW: list every id outside the current session.")
            if "out-of-scope-read" in e.tags:
                add("deny-out-of-scope-read", ref, tool=e.tool, action="deny", conditions={"outside_workspace": True},
                    why="The agent accessed a path outside its workspace because of untrusted content.")
            if "canary-leak" in e.tags or "canary-cross-tool" in e.tags:
                add("protect-sensitive-data", ref, action="deny", conditions={"contains_canary_secret": True},
                    why="A secret value appeared in an outbound request.")
            if "egress-unlisted" in e.tags and e.tool == "http_request":
                add("block-unapproved-outbound", ref, tool="http_request", action="deny",
                    conditions={"host_not_in_allowlist": True, "allowlist": ["api.mycompany.com"]},
                    why="The agent sent a request to a host outside the allowlist. REVIEW the allowlist.")
            if "sensitive-read" in e.tags:
                add("require-approval-sensitive-read", ref, tool=e.tool, action="require_human_approval",
                    conditions={"sensitive_path": True}, why="The agent read a secret file because of untrusted content.")
            if "destructive" in e.tags:
                add(f"require-approval-destructive-{e.tool}", ref, tool=e.tool, action="require_human_approval",
                    conditions={"destructive_command": True}, why="The agent ran a destructive operation without approval.")
            if "beacon" in e.tags and e.tool == "http_request":
                add("block-unapproved-outbound", ref, tool="http_request", action="deny",
                    conditions={"host_not_in_allowlist": True, "allowlist": ["api.mycompany.com"]},
                    why="The agent sent a request to a host outside the allowlist. REVIEW the allowlist.")
            if v.campaign == "cost-drain":
                add("limit-tool-calls", ref, scope="session", action="limit", max_tool_calls=50,
                    why="The agent looped on tool calls without a bound.")
    pol = Policy(rules=[rules[k] for k in sorted(rules)])
    return pol


def test_policy(policy: Policy, a: Assessment, out_dir: Path) -> list[dict]:
    """For every failed run, check that the policy would have stopped at least one evidence call."""
    results = []
    for run in a.runs:
        if run.verdict.status != "fail":
            continue
        events = load_trace(run_trace_path(out_dir, run.dir))
        hits = blocked_seqs(policy, events)
        stopped = [s for s in run.verdict.evidence_seqs if s in hits]
        results.append({"run": run.dir, "blocked": bool(stopped), "rules": sorted({r for s in stopped for r in hits[s]})})
    return results
