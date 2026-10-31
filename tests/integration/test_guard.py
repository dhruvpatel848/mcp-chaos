from click.testing import CliRunner

from mcp_chaos.campaigns.registry import resolve
from mcp_chaos.cli.main import cli
from mcp_chaos.core.assessment import run_assessment
from mcp_chaos.policies import policy as pol
from mcp_chaos.policies.enforce import Enforcer
from mcp_chaos.recorder.trace import load_trace


def test_runtime_enforcer_agrees_with_trace_tester(vuln, tmp_path):
    a, out = vuln
    p = pol.generate(a, out)
    for run in a.runs:
        if run.verdict.status != "fail":
            continue
        enf = Enforcer(p)
        blocked = {e.seq for e in load_trace(out / run.dir / "trace.jsonl")
                   if enf.decide(e.tool, e.arguments).action != "allow"}
        assert blocked & set(run.verdict.evidence_seqs), run.dir


def test_generated_policy_stops_the_attack_end_to_end(vuln, tmp_path):
    """Re-run the same vulnerable agent through the guard proxy with the policy generated from its own failures."""
    a, out = vuln
    pf = tmp_path / "mcp-guard.yaml"
    pf.write_text(pol.dump_policy(pol.generate(a, out)), encoding="utf-8")
    camps = resolve("data-exfil,destructive,poisoned-content,file-access,cross-tool-leak,approval-bypass")
    b = run_assessment("demo:vulnerable", camps, tmp_path / "g", timeout=120, guard=pf)
    bad = [(r.campaign, r.variant, r.verdict.status) for r in b.runs if r.verdict.status == "fail"]
    assert not bad, bad
    assert all(r.verdict.status == "pass" for r in b.runs), [(r.campaign, r.variant, r.verdict.status) for r in b.runs]
    assert all(r.tool_calls >= 1 for r in b.runs)
    # blocked calls never reached the sandbox: no canary ever left, no destructive call executed
    for r in b.runs:
        ev = load_trace(tmp_path / "g" / r.dir / "trace.jsonl")
        assert not any(e.canary_exposed or "destructive" in e.tags for e in ev)


def test_cli_attack_with_guard_and_guard_command_registered(vuln, tmp_path):
    _, out = vuln
    assert CliRunner().invoke(cli, ["guard", "--help"]).exit_code == 0
    assert "--guard" in CliRunner().invoke(cli, ["attack", "--help"]).output
