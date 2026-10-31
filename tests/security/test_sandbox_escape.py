"""Regression tests for sandbox-boundary findings from the source audit."""
import json
import os
import sys
from pathlib import Path

import pytest

from mcp_chaos.adapters.target import TargetError, resolve_restricted
from mcp_chaos.campaigns.registry import resolve
from mcp_chaos.mocks.server import Sandbox
from mcp_chaos.policies.policy import run_trace_path


def _sandbox(tmp_path):
    st = resolve("destructive")[0].build("plain-document", "audit")
    return Sandbox(st, tmp_path / "t.jsonl")


@pytest.mark.parametrize("sql", [
    "ATTACH DATABASE 'escaped.db' AS e",
    "attach 'escaped.db' as e",
    "VACUUM INTO 'escaped.db'",
    "PRAGMA journal_mode=WAL",
    "DETACH DATABASE main",
    "SELECT load_extension('x')",
    "/* c */ ATTACH DATABASE 'escaped.db' AS e",
])
def test_db_tool_cannot_touch_host(sql, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sb = _sandbox(tmp_path)
    try:
        r = sb.db.execute(sql)
        r.fetchall()
    except Exception:
        pass
    assert not list(tmp_path.glob("*.db")), "sandbox DB tool created a file on the host"


def test_db_tool_still_works_for_normal_and_destructive_statements(tmp_path):
    from mcp_chaos.mocks.server import _ALLOWED_SQL
    sb = _sandbox(tmp_path)
    assert sb.db.execute("SELECT count(*) FROM customers").fetchone()[0] == 2
    assert all(_ALLOWED_SQL.match(s) for s in ["select 1", "DROP TABLE customers", "  delete from customers", "WITH a AS (SELECT 1) SELECT * FROM a"])
    sb.db.execute("DROP TABLE customers")  # the destructive campaign must still be able to run it


def test_db_query_tool_path_rejects_attach_end_to_end(tmp_path, monkeypatch):
    """Through the real tool function (statement allowlist), not just the authorizer."""
    monkeypatch.chdir(tmp_path)
    from mcp_chaos.mocks.server import build_server
    import asyncio
    sb = _sandbox(tmp_path)
    srv = build_server(sb)
    out = asyncio.run(srv.call_tool("db_query", {"sql": "ATTACH DATABASE 'escaped.db' AS e"}))
    assert "not permitted" in json.dumps(out, default=str)
    assert not list(tmp_path.glob("*.db"))


@pytest.mark.parametrize("target", [
    "python -c \"import os\"", "cmd /c calc", "/bin/sh -c id", "curl http://x", "node agent.js", "python -m http.server",
    "bash", "../../etc/passwd", "python " + sys.executable,
])
def test_restricted_targets_refuse_arbitrary_commands(target, tmp_path):
    with pytest.raises(TargetError):
        resolve_restricted(target, roots=[str(tmp_path)])


def test_restricted_targets_allow_demo_and_scripts_under_allowed_roots(tmp_path):
    assert resolve_restricted("demo:secure", roots=[str(tmp_path)])
    script = tmp_path / "agent.py"
    script.write_text("print(1)")
    argv = resolve_restricted(f'python "{script}" --provider gemini', roots=[str(tmp_path)])
    assert argv[-2:] == [str(script.resolve()), "--provider"] or "--provider" in argv
    assert resolve_restricted(str(script), roots=[str(tmp_path)])


def test_restricted_targets_refuse_scripts_outside_roots(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    script = other / "evil.py"
    script.write_text("print(1)")
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    with pytest.raises(TargetError):
        resolve_restricted(str(script), roots=[str(allowed)])
    link_dir = allowed
    try:  # a symlink inside the allowed dir pointing outside must not bypass the check
        (link_dir / "link.py").symlink_to(script)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(TargetError):
        resolve_restricted(str(link_dir / "link.py"), roots=[str(allowed)])


def test_mcp_server_and_dashboard_use_restricted_targets(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from fastapi.testclient import TestClient
    from mcp_chaos.dashboard.app import create_app
    c = TestClient(create_app(tmp_path / "runs"))
    h = {"X-Chaos-Token": c.app.state.token}
    r = c.post("/api/assessments", json={"target": 'python -c "print(1)"'}, headers=h)
    assert r.status_code == 400
    from mcp_chaos.mcp_server.server import build
    import asyncio
    out = asyncio.run(build().call_tool("chaos_start_assessment", {"target": "bash -c id"}))
    assert "error" in json.dumps(out, default=str)


def test_tampered_assessment_cannot_point_outside_its_folder(tmp_path):
    (tmp_path / "a").mkdir()
    with pytest.raises(ValueError):
        run_trace_path(tmp_path / "a", "../../" + os.path.basename(tmp_path))
    assert run_trace_path(tmp_path / "a", "runs/x--y--1").name == "trace.jsonl"
    assert Path(run_trace_path(tmp_path / "a", "runs/x")).is_relative_to((tmp_path / "a").resolve())
