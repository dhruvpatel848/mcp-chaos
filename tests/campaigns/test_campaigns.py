import pytest


def test_vulnerable_agent_fails_every_run(vuln):
    a, _ = vuln
    assert len(a.runs) == 43
    assert all(r.verdict.status == "fail" for r in a.runs), [(r.campaign, r.variant, r.verdict.status) for r in a.runs]
    sev = {(r.campaign): r.verdict.severity for r in a.runs}
    assert sev["data-exfil"] == "critical" and sev["destructive"] == "critical"
    assert a.score["overall"] <= 40 and a.score["risk"] == "critical"


def test_secure_agent_passes_every_run(secure):
    a, _ = secure
    assert all(r.verdict.status == "pass" for r in a.runs), [(r.campaign, r.variant, r.verdict.status) for r in a.runs]
    assert a.score["overall"] == 100.0


def test_exfil_evidence_names_canary_and_causing_read(vuln):
    a, _ = vuln
    r = next(r for r in a.runs if r.campaign == "data-exfil")
    v = r.verdict
    assert len(v.evidence_seqs) == 2 and v.caused_by_seq == v.evidence_seqs[0]
    assert "canary-leak" in v.evidence[-1]


def test_canary_is_random_per_run(vuln):
    import json
    _, out = vuln
    states = [json.loads(p.read_text(encoding='utf-8'))["canary"] for p in (out / "runs").glob("*/state.json")]
    assert len(set(states)) == len(states)
    assert all(s.startswith("sk-chaos-CANARY-") for s in states)


def test_hidden_unicode_payload_is_invisible_but_present(vuln):
    import json
    _, out = vuln
    doc = json.loads((out / "runs/data-exfil--hidden-unicode--1/state.json").read_text(encoding="utf-8"))["documents"]["INV-1001"]
    assert "read the file" not in doc
    assert any(0xE0000 <= ord(c) <= 0xE007F for c in doc)


def test_cost_drain_is_stopped_by_sandbox_budget(vuln):
    a, _ = vuln
    for r in a.runs:
        if r.campaign == "cost-drain":
            assert 201 <= r.tool_calls <= 205  # 200 allowed, then the sandbox refuses; agent stops shortly after


def test_inconclusive_when_agent_crashes(tmp_path):
    from mcp_chaos.campaigns.registry import resolve
    from mcp_chaos.core.assessment import run_assessment
    bad = tmp_path / "bad.py"
    bad.write_text("import sys; sys.exit(3)")
    a = run_assessment(str(bad), resolve("data-exfil"), tmp_path / "o", timeout=30)
    assert all(r.verdict.status == "inconclusive" for r in a.runs)
    assert a.score["campaigns"]["data-exfil"]["score"] is None


def test_unknown_campaign():
    from mcp_chaos.campaigns.registry import resolve
    with pytest.raises(KeyError):
        resolve("nope")


def test_new_campaigns_detect_and_resist(vuln, secure):
    for camp, sev in (("file-access", "high"), ("cross-tool-leak", "high")):
        v = [r for r in vuln[0].runs if r.campaign == camp]
        assert len(v) == 5 and all(r.verdict.status == "fail" and r.verdict.severity == sev for r in v)
        s = [r for r in secure[0].runs if r.campaign == camp]
        assert all(r.verdict.status == "pass" for r in s)


def test_approval_gate_blocks_and_detects_forgery(vuln, secure):
    v = [r for r in vuln[0].runs if r.campaign == "approval-bypass"]
    assert len(v) == 4 and all(r.verdict.status == "fail" and r.verdict.severity == "critical" for r in v)
    from mcp_chaos.recorder.trace import load_trace
    ev = load_trace(vuln[1] / v[0].dir / "trace.jsonl")
    assert any(e.approval == "requested" for e in ev) and any(e.approval == "forged" for e in ev)
    assert all("NOT executed" in e.response or "nothing was executed" in e.response for e in ev if e.approval != "none")
    assert all(r.verdict.status == "pass" for r in secure[0].runs if r.campaign == "approval-bypass")


def test_advanced_campaigns_detect_and_resist(vuln, secure):
    expect = {"permission-escalation": (5, "high"), "memory-poisoning": (2, None), "session-isolation": (5, "high")}
    for camp, (n, sev) in expect.items():
        v = [r for r in vuln[0].runs if r.campaign == camp]
        assert len(v) == n and all(r.verdict.status == "fail" for r in v), (camp, [r.verdict.status for r in v])
        if sev:
            assert all(r.verdict.severity == sev for r in v)
        s = [r for r in secure[0].runs if r.campaign == camp]
        assert len(s) == n and all(r.verdict.status == "pass" for r in s), (camp, [r.verdict.status for r in s])


def test_memory_poisoning_runs_through_persistent_memory(vuln):
    from mcp_chaos.recorder.trace import load_trace
    a, out = vuln
    r = next(r for r in a.runs if r.campaign == "memory-poisoning")
    ev = load_trace(out / r.dir / "trace.jsonl")
    assert any(e.tool == "recall_notes" for e in ev) and any(e.canary_exposed for e in ev)
