"""Runtime policy evaluation (no trace needed) used by the guard proxy.

Unlike the trace tester, it cannot know the run's canary, so `contains_canary_secret` matches
secret-shaped strings (API-key prefixes) in raw or decoded form.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from mcp_chaos.core.detect import DESTRUCTIVE_SHELL, DESTRUCTIVE_SQL, SENSITIVE_PATH, _variants, host_of

from .policy import Policy, Rule

SECRET_SHAPE = re.compile(r"(sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|xox[bp]-[A-Za-z0-9-]{20,})")


@dataclass
class Decision:
    action: str  # allow | deny | require_human_approval
    rule_id: Optional[str] = None
    reason: str = ""


def _has_secret(args: dict) -> bool:
    text = str(args)
    return any(SECRET_SHAPE.search(v) for v in _variants(text))


def _rule_hits(rule: Rule, tool: str, args: dict) -> bool:
    if rule.tool and rule.tool != tool:
        return False
    c = rule.conditions
    if c.get("host_not_in_allowlist"):
        if "url" not in args or host_of(str(args["url"])) in [h.lower() for h in c.get("allowlist", [])]:
            return False
    if c.get("contains_canary_secret") and not _has_secret(args):
        return False
    if c.get("destructive_command"):
        cmd, sql = str(args.get("command", "")), str(args.get("sql", ""))
        if not (DESTRUCTIVE_SHELL.search(cmd) or DESTRUCTIVE_SQL.search(sql)):
            return False
    if c.get("denied_doc_ids") and args.get("doc_id") not in c["denied_doc_ids"]:
        return False
    if c.get("sensitive_path") and not SENSITIVE_PATH.search(str(args.get("path", ""))):
        return False
    if c.get("outside_workspace") and (not args.get("path") or str(args["path"]).startswith("/workspace")):
        return False
    return True


class Enforcer:
    def __init__(self, policy: Policy):
        self.policy = policy
        self.calls = 0

    def decide(self, tool: str, args: dict) -> Decision:
        self.calls += 1
        verdict = Decision("allow")
        for r in self.policy.rules:
            if r.action == "limit":
                if r.max_tool_calls is not None and self.calls > r.max_tool_calls:
                    return Decision("deny", r.id, f"session tool-call limit {r.max_tool_calls} exceeded")
                continue
            if _rule_hits(r, tool, args):
                if r.action == "deny":
                    return Decision("deny", r.id, r.why or "denied by policy")
                verdict = Decision("require_human_approval", r.id, r.why or "human approval required")
        return verdict
