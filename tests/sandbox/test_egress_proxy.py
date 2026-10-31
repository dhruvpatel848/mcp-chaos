import json

import pytest

from mcp_chaos.adapters.target import docker_available, run_agent_docker
from mcp_chaos.sandbox.egress_proxy import validate_allowlist

PROBE = r'''
import json, os, socket, urllib.parse
out = {}
proxy = urllib.parse.urlparse(os.environ["HTTPS_PROXY"])
def connect(host, port=443):
    s = socket.create_connection((proxy.hostname, proxy.port), timeout=10)
    s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    line = s.recv(200).split(b"\r\n")[0].decode(); s.close(); return line
out["allowed_host"] = connect("example.com")
out["other_host"] = connect("www.wikipedia.org")
out["allowed_host_wrong_port"] = connect("example.com", 80)
try:
    socket.create_connection(("1.1.1.1", 443), timeout=3).close(); out["direct_ip"] = "open"
except Exception as e:
    out["direct_ip"] = "blocked:" + type(e).__name__
try:
    socket.create_connection(("example.com", 443), timeout=3).close(); out["direct_host"] = "open"
except Exception as e:
    out["direct_host"] = "blocked:" + type(e).__name__
print("PROBE=" + json.dumps(out))
'''


@pytest.mark.parametrize("bad", ["*", "*.example.com", "1.1.1.1", "example.com:443", "localhost", "http://example.com", ""])
def test_allowlist_rejects_wildcards_ips_ports(bad):
    with pytest.raises(ValueError):
        validate_allowlist([bad])


def test_allowlist_accepts_plain_hostnames():
    assert validate_allowlist(["Generativelanguage.googleapis.com"]) == ["generativelanguage.googleapis.com"]


@pytest.mark.skipif(not docker_available(), reason="docker daemon or mcp-chaos:local image unavailable")
def test_only_allowlisted_host_reachable_via_proxy_everything_else_blocked(tmp_path):
    agent = tmp_path / "agents" / "probe.py"
    agent.parent.mkdir()
    agent.write_text(PROBE)
    rdir = tmp_path / "run"
    rdir.mkdir()
    (rdir / "state.json").write_text("{}")
    ctx = run_agent_docker(f"python {agent}", rdir / "state.json", rdir / "t.jsonl", "t", 90, rdir, allow_hosts=("example.com",))
    res = json.loads(ctx.stdout_tail.split("PROBE=", 1)[1].splitlines()[0])
    assert " 200 " in res["allowed_host"], (res, ctx.stderr_tail[-300:])
    assert " 403 " in res["other_host"] and " 403 " in res["allowed_host_wrong_port"], res
    assert res["direct_ip"].startswith("blocked") and res["direct_host"].startswith("blocked"), res
