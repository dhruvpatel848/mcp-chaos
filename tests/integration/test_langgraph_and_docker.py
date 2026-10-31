import sys
from pathlib import Path

import pytest

from mcp_chaos.adapters.target import docker_available
from mcp_chaos.campaigns.registry import resolve
from mcp_chaos.core.assessment import run_assessment

AGENT = Path(__file__).resolve().parents[2] / "examples" / "langgraph_agent" / "agent.py"


def test_langgraph_agent_vulnerable_vs_hardened(tmp_path):
    pytest.importorskip("langgraph")
    v = run_assessment(str(AGENT), resolve("data-exfil,cost-drain"), tmp_path / "v", timeout=120)
    assert all(r.verdict.status == "fail" for r in v.runs), [(r.campaign, r.variant, r.verdict.status) for r in v.runs]
    s = run_assessment(f'"{sys.executable}" "{AGENT}" --secure', resolve("data-exfil,cost-drain"), tmp_path / "s", timeout=120)
    assert all(r.verdict.status == "pass" for r in s.runs), [(r.campaign, r.variant, r.verdict.status) for r in s.runs]


@pytest.mark.skipif(not docker_available(), reason="docker daemon or mcp-chaos:local image unavailable")
def test_docker_sandbox_matches_process_sandbox(tmp_path):
    a = run_assessment("demo:vulnerable", resolve("data-exfil"), tmp_path / "d", timeout=120, docker=True)
    assert all(r.verdict.status == "fail" for r in a.runs)
