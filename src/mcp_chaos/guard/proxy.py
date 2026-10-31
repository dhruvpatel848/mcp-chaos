"""mcp-guard: an MCP stdio proxy that enforces an mcp-guard.yaml policy in front of any MCP server.

  mcp-chaos guard --policy mcp-guard.yaml -- python -m some_mcp_server
Client <-stdio-> guard <-stdio-> upstream server. Denied calls return an MCP error and never reach upstream.
Fail-closed: any error while evaluating policy or obtaining an approval blocks the call.
`require_human_approval` rules wait for a human when --approvals-dir is set, otherwise they are blocked.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import mcp.types as types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from mcp_chaos.guard.approvals import FileApprover
from mcp_chaos.policies.enforce import Decision, Enforcer
from mcp_chaos.policies.policy import validate


def _log(msg: str) -> None:
    print(f"[mcp-guard] {msg}", file=sys.stderr)


async def guarded_call(enforcer: Any, approver: Any, upstream: Any, name: Any, arguments: Any) -> Any:
    """Decide, optionally wait for a human, then forward. Raises ValueError for every blocked or failed call."""
    try:
        d: Decision = enforcer.decide(name, arguments)
    except Exception as exc:  # fail closed: a broken policy engine must never mean "allow"
        _log(f"policy evaluation error ({type(exc).__name__}); blocking {name!r}")
        raise ValueError("BLOCKED (fail-closed): policy evaluation failed") from None
    if d.action == "require_human_approval" and approver is not None:
        _log(f"waiting for human approval: {name} rule={d.rule_id}")
        try:
            approved = await approver.request(name, arguments, d.rule_id or "", d.reason)
        except Exception as exc:  # fail closed
            _log(f"approver error ({type(exc).__name__}); blocking {name!r}")
            raise ValueError("BLOCKED (fail-closed): approval mechanism failed") from None
        if not approved:
            raise ValueError(f"DENIED: human approval for rule '{d.rule_id}' was refused or timed out")
        d = Decision("allow", d.rule_id, "approved by human")
    if d.action != "allow":
        _log(f"{d.action} {name} rule={d.rule_id}")
        label = "BLOCKED" if d.action == "deny" else "BLOCKED pending human approval"
        raise ValueError(f"{label} by mcp-guard rule '{d.rule_id}': {d.reason}")
    res = await upstream.call_tool(name, arguments)
    if res.isError:
        raise ValueError("".join(getattr(c, "text", "") for c in res.content))
    if res.structuredContent is not None:  # tools with an outputSchema must return structured output too
        return (res.content, res.structuredContent)
    return res.content


async def serve(policy_path: Path, upstream_cmd: list[str], approvals_dir: Path | None = None, approval_timeout: float = 120.0) -> None:
    pol, errors, _ = validate(policy_path)
    if errors or pol is None:
        raise SystemExit("invalid policy: " + "; ".join(errors))
    enforcer = Enforcer(pol)
    approver = FileApprover(approvals_dir, approval_timeout) if approvals_dir else None
    server = Server("mcp-chaos-guard")
    async with stdio_client(StdioServerParameters(command=upstream_cmd[0], args=upstream_cmd[1:])) as (r, w):
        async with ClientSession(r, w) as up:
            await up.initialize()

            @server.list_tools()
            async def list_tools() -> list[types.Tool]:
                return (await up.list_tools()).tools

            @server.call_tool(validate_input=False)
            async def call_tool(name: str, arguments: dict | None):
                return await guarded_call(enforcer, approver, up, name, arguments if arguments is not None else {})

            async with stdio_server() as (rs, ws):
                await server.run(rs, ws, server.create_initialization_options())
