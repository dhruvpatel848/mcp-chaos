import asyncio
import sys
import threading
import time

import pytest
from click.testing import CliRunner
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_chaos.campaigns.registry import resolve
from mcp_chaos.cli.main import cli
from mcp_chaos.guard.approvals import FileApprover, decide, list_pending

POLICY = """version: 1
rules:
- id: approve-destructive-shell
  tool: bash_exec
  action: require_human_approval
  conditions: {destructive_command: true}
"""


def _auto_human(root, decision, stop):
    """Stands in for a person running `mcp-chaos approvals <decision> <id>`."""
    def run():
        while not stop.is_set():
            for r in list_pending(root):
                decide(root, r["id"], decision)
            time.sleep(0.1)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


async def _call_through_guard(tmp_path, root, timeout):
    camp = resolve("destructive")[0]
    state = camp.build("plain-document", "approvaltest")
    (tmp_path / "state.json").write_text(state.model_dump_json(), encoding="utf-8")
    (tmp_path / "policy.yaml").write_text(POLICY, encoding="utf-8")
    upstream = [sys.executable, "-m", "mcp_chaos.mocks.server", "--state", str(tmp_path / "state.json"), "--trace", str(tmp_path / "t.jsonl")]
    cmd = ["-m", "mcp_chaos.guard", "--policy", str(tmp_path / "policy.yaml"), "--approvals-dir", str(root),
           "--approval-timeout", str(timeout), "--", *upstream]
    async with stdio_client(StdioServerParameters(command=sys.executable, args=cmd)) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            return await s.call_tool("bash_exec", {"command": "rm -rf /workspace/data"})


async def test_human_approval_lets_the_call_through(tmp_path):
    root, stop = tmp_path / "ap", threading.Event()
    _auto_human(root, "approve", stop)
    res = await _call_through_guard(tmp_path, root, 30)
    stop.set()
    assert not res.isError and "simulated" in res.content[0].text
    assert (tmp_path / "t.jsonl").read_text().count("bash_exec") == 1  # reached upstream


async def test_human_denial_and_timeout_block_the_call(tmp_path):
    root, stop = tmp_path / "ap", threading.Event()
    _auto_human(root, "deny", stop)
    res = await _call_through_guard(tmp_path, root, 30)
    stop.set()
    assert res.isError and "DENIED" in res.content[0].text
    assert not (tmp_path / "t.jsonl").exists() or "bash_exec" not in (tmp_path / "t.jsonl").read_text()
    d2 = tmp_path / "x"
    d2.mkdir()
    res = await _call_through_guard(d2, tmp_path / "ap2", 1)  # nobody answers
    assert res.isError and "timed out" in res.content[0].text


async def test_approval_is_bound_to_exact_request_and_single_use(tmp_path):
    ap = FileApprover(tmp_path, timeout=5, poll=0.05)
    task = asyncio.create_task(ap.request("bash_exec", {"command": "rm -rf a"}, "r", "why"))
    await asyncio.sleep(0.3)
    [req] = list_pending(tmp_path)
    # forged decision bound to a different request must not approve
    (tmp_path / "decided" / f"{req['id']}.json").write_text('{"decision": "approve", "bound_to": "other"}')
    assert await task is False
    assert list_pending(tmp_path) == []


def test_cli_approvals_commands(tmp_path):
    r = CliRunner()
    assert "no pending" in r.invoke(cli, ["approvals", "list", "--dir", str(tmp_path)]).output
    assert r.invoke(cli, ["approvals", "approve", "nope", "--dir", str(tmp_path)]).exit_code == 2
    assert pytest is not None


async def test_allowed_calls_pass_through_the_guard_cleanly(tmp_path):
    """Regression: allowed calls used to come back as 'Output validation error'."""
    camp = resolve("destructive")[0]
    state = camp.build("plain-document", "passthrough")
    (tmp_path / "state.json").write_text(state.model_dump_json(), encoding="utf-8")
    (tmp_path / "policy.yaml").write_text(POLICY, encoding="utf-8")
    upstream = [sys.executable, "-m", "mcp_chaos.mocks.server", "--state", str(tmp_path / "state.json"), "--trace", str(tmp_path / "t.jsonl")]
    cmd = ["-m", "mcp_chaos.guard", "--policy", str(tmp_path / "policy.yaml"), "--", *upstream]
    async with stdio_client(StdioServerParameters(command=sys.executable, args=cmd)) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool("fetch_document", {"doc_id": "INV-1001"})
    assert not res.isError and "INVOICE INV-1001" in res.content[0].text
