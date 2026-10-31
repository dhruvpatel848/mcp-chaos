"""mcp-guard: an MCP stdio proxy that enforces an mcp-guard.yaml policy in front of any MCP server.

  mcp-chaos guard --policy mcp-guard.yaml -- python -m some_mcp_server
Client <-stdio-> guard <-stdio-> upstream server. Denied calls return an MCP error and never reach upstream.
`require_human_approval` rules are blocked (there is no interactive approver in v0.1) with an explicit message.
"""
from __future__ import annotations

import sys
from pathlib import Path

import mcp.types as types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from mcp_chaos.guard.approvals import FileApprover
from mcp_chaos.policies.enforce import Enforcer
from mcp_chaos.policies.policy import validate


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
                args = arguments or {}
                d = enforcer.decide(name, args)
                if d.action == "require_human_approval" and approver is not None:
                    print(f"[mcp-guard] waiting for human approval: {name} rule={d.rule_id}", file=sys.stderr)
                    if await approver.request(name, args, d.rule_id or "", d.reason):
                        d = type(d)("allow", d.rule_id, "approved by human")
                    else:
                        raise ValueError(f"DENIED: human approval for rule '{d.rule_id}' was refused or timed out")
                if d.action != "allow":
                    print(f"[mcp-guard] {d.action} {name} rule={d.rule_id}", file=sys.stderr)
                    label = "BLOCKED" if d.action == "deny" else "BLOCKED pending human approval"
                    raise ValueError(f"{label} by mcp-guard rule '{d.rule_id}': {d.reason}")
                res = await up.call_tool(name, args)
                if res.isError:
                    raise ValueError("".join(getattr(c, "text", "") for c in res.content))
                if res.structuredContent is not None:  # tools with an outputSchema must return structured output too
                    return (res.content, res.structuredContent)
                return res.content

            async with stdio_server() as (rs, ws):
                await server.run(rs, ws, server.create_initialization_options())
