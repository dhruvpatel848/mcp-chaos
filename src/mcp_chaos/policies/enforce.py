"""Runtime policy evaluation (no trace needed) used by the guard proxy.

Fail-closed by design: arguments that cannot be understood (wrong shape, oversized, a host rule with no
recognisable URL) are denied, never allowed. Unlike the trace tester it cannot know a run's canary, so
`contains_canary_secret` matches secret-shaped strings (API-key prefixes) in raw or decoded form.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterator, Optional

from mcp_chaos.core.detect import (
    DESTRUCTIVE_SHELL,
    DESTRUCTIVE_SQL,
    SENSITIVE_PATH,
    _variants,
    host_of,
    in_workspace,
)

from .policy import Policy, Rule

SECRET_SHAPE = re.compile(r"(sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|xox[bp]-[A-Za-z0-9-]{20,})")
MAX_ARG_BYTES = 262_144  # larger payloads are refused: they defeat bounded decoding and have no legitimate use here
MAX_DEPTH = 20
URL_KEYS = {"url", "uri", "endpoint", "host", "hostname", "address", "href", "target", "link", "base_url"}


@dataclass
class Decision:
    action: str  # allow | deny | require_human_approval
    rule_id: Optional[str] = None
    reason: str = ""


def _walk(obj: Any, depth: int = 0) -> Iterator[tuple[str, Any]]:
    """Yield (key, value) for every entry of nested dicts/lists; list items get an empty key."""
    if depth > MAX_DEPTH:
        raise ValueError("arguments nested too deeply")
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k), v
            yield from _walk(v, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield "", v
            yield from _walk(v, depth + 1)


def _strings(args: Any) -> Iterator[str]:
    """Every string in the arguments, plus the space-joined form of string lists (argv-style commands)."""
    for _, v in _walk(args):
        if isinstance(v, str):
            yield v
        elif isinstance(v, (list, tuple)) and v and all(isinstance(x, str) for x in v):
            yield " ".join(v)
    if isinstance(args, str):
        yield args


def _urls(args: Any) -> tuple[list[Any], bool]:
    """Values stored under URL-like keys, and whether any such key was found."""
    found = [v for k, v in _walk(args) if k.lower() in URL_KEYS]
    return found, bool(found)


def _has_secret(args: Any) -> bool:
    text = str(args)
    return any(SECRET_SHAPE.search(v) for v in _variants(text))


def _rule_hits(rule: Rule, tool: str, args: dict) -> bool:
    if rule.tool and rule.tool != tool:
        return False
    c = rule.conditions
    if c.get("host_not_in_allowlist"):
        allow = {h.lower() for h in c.get("allowlist", [])}
        urls, found = _urls(args)
        # fail closed: no recognisable URL, or any URL whose host is ambiguous/unlisted, means the rule applies
        if found and all(host_of(u) in allow for u in urls):
            return False
    if c.get("contains_canary_secret") and not _has_secret(args):
        return False
    if c.get("destructive_command"):
        if not any(DESTRUCTIVE_SHELL.search(s) or DESTRUCTIVE_SQL.search(s) for s in _strings(args)):
            return False
    if c.get("denied_doc_ids") and args.get("doc_id") not in c["denied_doc_ids"]:
        return False
    if c.get("sensitive_path") and not any(SENSITIVE_PATH.search(str(v)) for k, v in _walk(args) if k.lower() in ("path", "file", "filename")):
        return False
    if c.get("outside_workspace"):
        paths = [v for k, v in _walk(args) if k.lower() in ("path", "file", "filename")]
        if not paths or all(in_workspace(p) for p in paths):
            return False
    return True


class Enforcer:
    def __init__(self, policy: Policy):
        self.policy = policy
        self.calls = 0

    def decide(self, tool: Any, args: Any) -> Decision:
        self.calls += 1
        if not isinstance(tool, str) or not tool:
            return Decision("deny", "guard-malformed", "tool name must be a non-empty string")
        if not isinstance(args, dict):
            return Decision("deny", "guard-malformed", "tool arguments must be a JSON object")
        try:
            if len(json.dumps(args, default=str)) > MAX_ARG_BYTES:
                return Decision("deny", "guard-limits", f"arguments larger than {MAX_ARG_BYTES} bytes are refused")
        except (TypeError, ValueError):
            return Decision("deny", "guard-malformed", "arguments are not serialisable")
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
