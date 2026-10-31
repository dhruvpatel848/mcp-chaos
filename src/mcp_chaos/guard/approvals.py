"""File-based human approvals for the guard proxy.

The proxy writes <dir>/pending/<id>.json and waits; a human runs `mcp-chaos approvals approve|deny <id>`, which
writes <dir>/decided/<id>.json. An approval is bound to one exact (tool, arguments) request and is consumed on use.
No decision within the timeout means deny. The model never sees or controls this channel.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import time
from pathlib import Path


def _atomic_write(path: Path, text: str) -> None:
    """Write via a temp file + rename so readers never see a half-written JSON file."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


class FileApprover:
    def __init__(self, root: Path, timeout: float = 120.0, poll: float = 0.25):
        self.pending = Path(root) / "pending"
        self.decided = Path(root) / "decided"
        self.pending.mkdir(parents=True, exist_ok=True)
        self.decided.mkdir(parents=True, exist_ok=True)
        self.timeout, self.poll = timeout, poll

    async def request(self, tool: str, args: dict, rule_id: str, reason: str) -> bool:
        digest = hashlib.sha256((tool + json.dumps(args, sort_keys=True, default=str)).encode()).hexdigest()
        rid = f"{digest[:8]}-{secrets.token_hex(3)}"
        _atomic_write(self.pending / f"{rid}.json", json.dumps(
            {"id": rid, "tool": tool, "arguments": args, "rule": rule_id, "reason": reason,
             "requested_at": time.time(), "bound_to": digest}))
        decision = self.decided / f"{rid}.json"
        deadline = time.monotonic() + self.timeout
        try:
            while time.monotonic() < deadline:
                if decision.exists():
                    d = json.loads(decision.read_text(encoding="utf-8"))
                    decision.unlink(missing_ok=True)  # single use
                    return d.get("decision") == "approve" and d.get("bound_to") == digest
                await asyncio.sleep(self.poll)
            return False
        finally:
            (self.pending / f"{rid}.json").unlink(missing_ok=True)


def list_pending(root: Path) -> list[dict]:
    d = Path(root) / "pending"
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(d.glob("*.json"))] if d.is_dir() else []


def decide(root: Path, rid: str, decision: str) -> bool:
    if Path(rid).name != rid:
        raise ValueError("bad id")
    p = Path(root) / "pending" / f"{rid}.json"
    if not p.exists():
        return False
    req = json.loads(p.read_text(encoding="utf-8"))
    (Path(root) / "decided").mkdir(parents=True, exist_ok=True)
    _atomic_write(Path(root) / "decided" / f"{rid}.json", json.dumps({"decision": decision, "bound_to": req["bound_to"]}))
    return True
