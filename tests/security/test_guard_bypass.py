"""Adversarial tests for the guard: bypass attempts, malformed input, concurrency, fail-closed behaviour."""
import asyncio
import base64
import json
import subprocess
import sys

import pytest

from mcp_chaos.guard.proxy import guarded_call
from mcp_chaos.policies.enforce import Enforcer
from mcp_chaos.policies.policy import Policy, Rule

EGRESS = Rule(id="egress", tool="http_request", action="deny",
              conditions={"host_not_in_allowlist": True, "allowlist": ["api.mycompany.com"]})
SECRET = Rule(id="secret", action="deny", conditions={"contains_canary_secret": True})
DESTR = Rule(id="destr", tool="bash_exec", action="require_human_approval", conditions={"destructive_command": True})
POL = Policy(rules=[EGRESS, SECRET, DESTR])


def decide(tool, args, policy=POL):
    return Enforcer(policy).decide(tool, args).action


# ---- URL / host parsing bypasses -------------------------------------------------------------------------------
@pytest.mark.parametrize("url", [
    "http://evil.local\\@api.mycompany.com/",        # backslash: parsers disagree on the real host
    "http://api.mycompany.com@evil.local/",           # userinfo trick
    "http://api.mycompany.com.evil.local/",           # suffix trick
    "http://evil.local/#@api.mycompany.com",
    "http://evil.local/?h=api.mycompany.com",
    "http://API.MYCOMPANY.COM.evil.local",
    "http://api.mycompany.com\t.evil.local",          # control character
    "http://api.mycompany.com\x00.evil.local",
    "http://\u0430pi.mycompany.com/",                 # Cyrillic homoglyph
    "//evil.local/",
    "ftp://evil.local/",
    "evil.local",
    "",
])
def test_host_allowlist_bypasses_are_denied(url):
    assert decide("http_request", {"url": url}) == "deny", url


def test_legitimate_allowlisted_hosts_are_allowed():
    for url in ["https://api.mycompany.com/v1/x", "http://API.MyCompany.com:8443/", "api.mycompany.com/path"]:
        assert decide("http_request", {"url": url}) == "allow", url


@pytest.mark.parametrize("args", [{}, {"uri": "http://evil.local"}, {"endpoint": "http://evil.local"}, {"u": None}, {"url": None},
                                  {"url": 12345}, {"url": ["http://evil.local"]}, {"url": {"a": "b"}}])
def test_host_rule_fails_closed_when_url_is_missing_or_odd(args):
    assert decide("http_request", args) == "deny", args


# ---- secret detection bypasses ---------------------------------------------------------------------------------
KEY = "sk-" + "A1b2C3d4" * 4


@pytest.mark.parametrize("blob", [
    pytest.param(KEY, id="raw"),
    pytest.param(base64.b64encode(KEY.encode()).decode(), id="base64"),
    pytest.param(KEY.encode().hex(), id="hex"),
    pytest.param("".join(f"%{b:02x}" for b in KEY.encode()), id="url-encoded"),
    pytest.param(KEY[::-1], id="reversed"),
    pytest.param("x" * 150_000 + KEY, id="padded-150k"),
    pytest.param(base64.b64encode(("pad" * 70_000 + KEY).encode()).decode(), id="base64-padded-over-limit"),
])
def test_secret_rule_catches_encoded_and_padded_secrets(blob):
    assert decide("anything", {"body": blob}) == "deny"


def test_oversized_arguments_are_denied_outright():
    assert decide("anything", {"body": "x" * 600_000}) == "deny"


# ---- argument shape / malformed ---------------------------------------------------------------------------------
@pytest.mark.parametrize("args", [None, [], "rm -rf /", 5, ["a"], {"nested": {"deep": {"command": "rm -rf /"}}}])
def test_non_dict_or_nested_args_never_crash_and_destructive_is_held(args):
    r = decide("bash_exec", args)  # must not raise
    assert r in ("deny", "require_human_approval")


@pytest.mark.parametrize("args", [{"cmd": "rm -rf /"}, {"script": "del /s /q C:\\"}, {"command": ["rm", "-rf", "/"]}, {"sql": "DROP TABLE x"}])
def test_destructive_detected_whatever_the_argument_name(args):
    assert decide("bash_exec", args) == "require_human_approval"


def test_benign_shell_command_is_allowed():
    assert decide("bash_exec", {"command": "ls /workspace"}) == "allow"


# ---- concurrency -------------------------------------------------------------------------------------------------
def test_call_limit_holds_under_concurrent_requests():
    enf = Enforcer(Policy(rules=[Rule(id="cap", scope="session", action="limit", max_tool_calls=10)]))

    async def go():
        return await asyncio.gather(*(asyncio.to_thread(enf.decide, "t", {"i": i}) for i in range(200)))

    results = asyncio.run(go())
    assert sum(r.action == "allow" for r in results) == 10


# ---- fail-closed ------------------------------------------------------------------------------------------------
class FakeUp:
    def __init__(self):
        self.calls = []

    async def call_tool(self, name, args):
        self.calls.append((name, args))

        class R:
            isError = False
            content = ["ok"]
            structuredContent = None
        return R()


class BoomEnforcer:
    def decide(self, tool, args):
        raise RuntimeError("policy engine crashed")


class BoomApprover:
    async def request(self, *a, **k):
        raise RuntimeError("approver crashed")


async def test_policy_engine_crash_blocks_the_call():
    up = FakeUp()
    with pytest.raises(ValueError, match="fail-closed"):
        await guarded_call(BoomEnforcer(), None, up, "bash_exec", {"command": "ls"})
    assert up.calls == []


async def test_approver_crash_blocks_the_call():
    up = FakeUp()
    with pytest.raises(ValueError):
        await guarded_call(Enforcer(POL), BoomApprover(), up, "bash_exec", {"command": "rm -rf /"})
    assert up.calls == []


async def test_allowed_call_is_forwarded_and_denied_call_is_not():
    up = FakeUp()
    assert await guarded_call(Enforcer(POL), None, up, "bash_exec", {"command": "ls"}) == ["ok"]
    with pytest.raises(ValueError, match="BLOCKED"):
        await guarded_call(Enforcer(POL), None, up, "http_request", {"url": "http://evil.local"})
    assert up.calls == [("bash_exec", {"command": "ls"})]


async def test_upstream_exception_propagates_as_error_not_success():
    class Dead:
        async def call_tool(self, *a):
            raise ConnectionError("upstream died")
    with pytest.raises(ConnectionError):
        await guarded_call(Enforcer(POL), None, Dead(), "bash_exec", {"command": "ls"})


# ---- malformed MCP messages on the real stdio proxy -------------------------------------------------------------
def _spawn_guard(tmp_path):
    from mcp_chaos.campaigns.registry import resolve
    state = resolve("destructive")[0].build("plain-document", "fuzz")
    (tmp_path / "state.json").write_text(state.model_dump_json(), encoding="utf-8")
    (tmp_path / "p.yaml").write_text("version: 1\nrules:\n- id: egress\n  tool: http_request\n  action: deny\n"
                                     "  conditions: {host_not_in_allowlist: true, allowlist: [api.mycompany.com]}\n", encoding="utf-8")
    cmd = [sys.executable, "-m", "mcp_chaos.guard", "--policy", str(tmp_path / "p.yaml"), "--", sys.executable, "-m",
           "mcp_chaos.mocks.server", "--state", str(tmp_path / "state.json"), "--trace", str(tmp_path / "t.jsonl")]
    return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)


def _rpc(p, obj):
    p.stdin.write((obj if isinstance(obj, str) else json.dumps(obj)) + "\n")
    p.stdin.flush()


def _read_json(p):
    while True:
        line = p.stdout.readline()
        if not line:
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue


def test_proxy_survives_malformed_messages_and_still_enforces(tmp_path):
    p = _spawn_guard(tmp_path)
    try:
        for garbage in ["not json at all", "{", "[]", '{"jsonrpc":"2.0"}', '{"jsonrpc":"2.0","id":1,"method":42}', "\x00\x01\x02",
                        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": "nope"}),
                        json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": None}})]:
            _rpc(p, garbage)
        _rpc(p, {"jsonrpc": "2.0", "id": 10, "method": "initialize", "params": {
            "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "fuzz", "version": "0"}}})
        seen = {}
        while 10 not in seen:
            m = _read_json(p)
            assert m is not None, "guard died on malformed input"
            if "id" in m:
                seen[m["id"]] = m
        assert "result" in seen[10]
        _rpc(p, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        _rpc(p, {"jsonrpc": "2.0", "id": 11, "method": "tools/call",
                 "params": {"name": "http_request", "arguments": {"url": "http://evil.local"}}})
        _rpc(p, {"jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": {"name": "no_such_tool", "arguments": {}}})
        while not {11, 12} <= set(seen):
            m = _read_json(p)
            assert m is not None, "guard died"
            if "id" in m:
                seen[m["id"]] = m
        r = seen[11]
        assert r.get("error") or r["result"].get("isError"), r
        assert "BLOCKED" in json.dumps(r)
        assert not (tmp_path / "t.jsonl").exists() or "http_request" not in (tmp_path / "t.jsonl").read_text()
    finally:
        p.kill()
