import json
import sys

import pytest

from mcp_chaos.adapters.target import docker_available, run_agent, run_agent_docker

PROBE = r'''
import json, socket, os
out = {}
def tcp(host, port):
    try:
        socket.create_connection((host, port), timeout=3).close(); return "open"
    except Exception as e:
        return "blocked:" + type(e).__name__
out["tcp_ip"] = tcp("1.1.1.1", 53)
try:
    socket.gethostbyname("example.com"); out["dns"] = "open"
except Exception as e:
    out["dns"] = "blocked:" + type(e).__name__
try:
    open("/etc/chaos-write-test", "w").write("x"); out["rootfs_write"] = "allowed"
except Exception as e:
    out["rootfs_write"] = "blocked:" + type(e).__name__
out["secret_env"] = [k for k in os.environ if "SECRET" in k or k.endswith("_API_KEY")]
print("PROBE=" + json.dumps(out))
'''

pytestmark = pytest.mark.skipif(not docker_available(), reason="docker daemon or mcp-chaos:local image unavailable")


def _probe(stdout: str) -> dict:
    return json.loads(stdout.split("PROBE=", 1)[1].splitlines()[0])


def test_container_has_no_network_no_dns_readonly_root(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "host-secret")
    agent = tmp_path / "agents" / "probe.py"
    agent.parent.mkdir()
    agent.write_text(PROBE)
    rdir = tmp_path / "run"
    rdir.mkdir()
    (rdir / "state.json").write_text("{}")
    ctx = run_agent_docker(str(agent), rdir / "state.json", rdir / "trace.jsonl", "t", 60, rdir)
    res = _probe(ctx.stdout_tail)
    assert res["tcp_ip"].startswith("blocked"), res
    assert res["dns"].startswith("blocked"), res
    assert res["rootfs_write"].startswith("blocked"), res
    assert res["secret_env"] == []


def test_process_mode_is_not_network_isolated_documented_contrast(tmp_path):
    """Documents the difference: the default process sandbox does NOT block sockets (this test needs no internet:
    it only asserts the probe ran; 'open' or 'blocked' depends on the host's connectivity)."""
    agent = tmp_path / "probe.py"
    agent.write_text(PROBE)
    ctx = run_agent([sys.executable, str(agent)], ["x"], "t", 60, tmp_path)
    assert "tcp_ip" in _probe(ctx.stdout_tail)
