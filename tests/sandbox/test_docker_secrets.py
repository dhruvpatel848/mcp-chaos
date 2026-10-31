"""Secrets given to the Docker sandbox must reach the agent but not be inspectable on the container."""
import json
import subprocess
import threading
import time

import pytest

from mcp_chaos.adapters.target import docker_available, run_agent_docker

pytestmark = pytest.mark.skipif(not docker_available(), reason="docker daemon or mcp-chaos:local image unavailable")

SECRET = "sk-test-SECRET-9f8e7d6c5b4a3210"
AGENT = '''
import os, sys, time
print("SEEN=" + os.environ.get("MY_API_KEY", "MISSING"))
print("ARGV=" + " ".join(sys.argv[1:]))
print("STDIN_CLOSED=" + str(sys.stdin.read() == ""))
if os.environ.get("MCP_CHAOS_TASK") == "linger":
    time.sleep(10)
'''


def _run(tmp_path, monkeypatch, task="t", extra=""):
    monkeypatch.setenv("MY_API_KEY", SECRET)
    agent = tmp_path / "agents" / "a.py"
    agent.parent.mkdir(exist_ok=True)
    agent.write_text(AGENT)
    rdir = tmp_path / "run"
    rdir.mkdir(exist_ok=True)
    (rdir / "state.json").write_text("{}")
    return run_agent_docker(f'python {agent} --flag{extra}', rdir / "state.json", rdir / "t.jsonl", task, 60, rdir, pass_env=("MY_API_KEY",))


def test_agent_receives_the_secret_and_its_argv_is_intact(tmp_path, monkeypatch):
    ctx = _run(tmp_path, monkeypatch)
    assert f"SEEN={SECRET}" in ctx.stdout_tail, ctx.stderr_tail[-300:]
    assert "ARGV=--flag" in ctx.stdout_tail
    assert "STDIN_CLOSED=True" in ctx.stdout_tail  # the agent cannot read anything further from stdin


def test_secret_is_not_visible_through_docker_inspect_or_process_list(tmp_path, monkeypatch):
    box = {}

    def go():
        box["ctx"] = _run(tmp_path, monkeypatch, task="linger")

    t = threading.Thread(target=go)
    t.start()
    names = ""
    for _ in range(60):  # wait for the container to exist
        names = subprocess.run(["docker", "ps", "--filter", "name=mcp-chaos-", "--format", "{{.Names}}"],
                               capture_output=True, text=True).stdout.split()
        names = [n for n in names if "proxy" not in n]
        if names:
            break
        time.sleep(0.5)
    assert names, "container never started"
    time.sleep(2)  # let the loader run and the agent start lingering
    inspect = subprocess.run(["docker", "inspect", names[0]], capture_output=True, text=True).stdout
    top = subprocess.run(["docker", "top", names[0]], capture_output=True, text=True).stdout
    host_ps = subprocess.run(["powershell", "-NoProfile", "-Command", "Get-CimInstance Win32_Process | Select -Expand CommandLine"],
                             capture_output=True, text=True).stdout if __import__("os").name == "nt" else \
        subprocess.run(["ps", "-eo", "args"], capture_output=True, text=True).stdout
    t.join(timeout=60)
    assert SECRET not in inspect, "secret is visible via docker inspect"
    assert SECRET not in top and SECRET not in host_ps, "secret is visible in a process command line"
    assert json.loads(inspect)[0]["Config"]["Env"], "sanity: inspect output was read"
    assert f"SEEN={SECRET}" in box["ctx"].stdout_tail
