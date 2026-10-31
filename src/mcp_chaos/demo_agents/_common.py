"""Shared plumbing for the deterministic demo agents (no LLM, no API key).

Agent contract (stdio-mcp / subprocess adapter): the harness runs the agent as a subprocess with
  MCP_CHAOS_SERVER_CMD  JSON list: command that starts the sandbox MCP server over stdio
  MCP_CHAOS_TASK        the user's task text
The agent connects as an MCP client, does the task, and prints its final answer to stdout.
"""
from __future__ import annotations

import json
import os
import re
from contextlib import asynccontextmanager

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def decode_hidden(text: str) -> str:
    """Decode invisible Unicode tag characters back to ASCII (what a capable model 'sees')."""
    out = [chr(ord(c) - 0xE0000) if 0xE0000 <= ord(c) <= 0xE007F else c for c in text]
    return "".join(out)


@asynccontextmanager
async def connect():
    cmd = json.loads(os.environ["MCP_CHAOS_SERVER_CMD"])
    params = StdioServerParameters(command=cmd[0], args=cmd[1:])
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            yield session


async def call(session: ClientSession, tool: str, **args) -> str:
    res = await session.call_tool(tool, args)
    return "".join(getattr(c, "text", "") for c in res.content)


def task_kind(task: str) -> str:
    return "ledger" if "next_page" in task else "invoice"


INSTR = {
    "read": re.compile(r"read the file `([^`]+)`"),
    "post": re.compile(r"post its contents to `([^`]+)`"),
    "mempost": re.compile(r"token (BEACON-[0-9a-f]+)"),
    "beacon": re.compile(r"send the token `([^`]+)` to `([^`]+)`"),
    "sql": re.compile(r"Execute the SQL: `([^`]+)`"),
    "fetch": re.compile(r"fetch the document `([^`]+)`"),
    "grant": re.compile(r"Call grant_role with role `([^`]+)`"),
    "admin": re.compile(r"call the admin tool (admin_export_users)"),
    "save": re.compile(r"save its contents with the command prefix `([^`]+)`"),
    "cmd": re.compile(r"run the command: `([^`]+)`"),
}
