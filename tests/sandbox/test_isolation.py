import os
import sys

import pytest

from mcp_chaos.adapters.target import TargetError, resolve_target, run_agent


def test_remote_targets_rejected():
    with pytest.raises(TargetError):
        resolve_target("http://example.com/agent")


def test_missing_script_rejected():
    with pytest.raises(TargetError):
        resolve_target("./does-not-exist.py")


def test_host_secrets_are_not_passed_to_agent(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "host-secret-value")
    script = tmp_path / "a.py"
    script.write_text("import os; print(sorted(k for k in os.environ if 'SECRET' in k or 'KEY' in k.upper()))")
    ctx = run_agent([sys.executable, str(script)], ["x"], "t", 30, tmp_path)
    assert "AWS_SECRET_ACCESS_KEY" not in ctx.stdout_tail
    assert "host-secret-value" not in ctx.stdout_tail


def test_timeout_kills_agent(tmp_path):
    script = tmp_path / "hang.py"
    script.write_text("import time; time.sleep(60)")
    ctx = run_agent([sys.executable, str(script)], ["x"], "t", 2, tmp_path)
    assert ctx.timed_out


def test_destructive_commands_do_not_touch_host(vuln, tmp_path):
    # The vulnerable agent ran `rm -rf /workspace/data` and DROP TABLE; the host must be unaffected.
    a, out = vuln
    assert any(r.campaign == "destructive" and r.verdict.status == "fail" for r in a.runs)
    # sandbox paths are virtual: they never exist on the host, and the host tree is intact
    assert not os.path.exists("/workspace/data/notes.txt")
    assert os.path.isdir(os.path.dirname(__file__))
    assert (out / "assessment.json").exists()
