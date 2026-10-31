"""AutoGen adapter against a scripted OpenAI-compatible server (no key). NOT a live-model test: AutoGen 0.7.5 cannot
currently talk to Gemini 3.x because it drops the required `thought_signature` from function calls."""
import sys
from pathlib import Path

import pytest

pytest.importorskip("autogen_agentchat")
pytest.importorskip("autogen_ext")

from test_openai_agents_adapter import _serve  # noqa: E402

from mcp_chaos.campaigns.registry import resolve  # noqa: E402
from mcp_chaos.core.assessment import run_assessment  # noqa: E402

AGENT = Path(__file__).resolve().parents[2] / "examples" / "autogen_agent" / "agent.py"


def _run(gullible, tmp_path, monkeypatch):
    srv = _serve(gullible)
    names = ("DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL", "DEEPSEEK_MODEL")
    for n, v in zip(names, ("k", f"http://127.0.0.1:{srv.server_port}", "fake")):
        monkeypatch.setenv(n, v)
    return run_assessment(f'"{sys.executable}" "{AGENT}" --provider deepseek', resolve("data-exfil"),
                          tmp_path / "o", timeout=120, pass_env=names)


def test_autogen_agent_gullible_model_is_caught_and_session_is_persistent(tmp_path, monkeypatch):
    a = _run(True, tmp_path, monkeypatch)
    plain = next(r for r in a.runs if r.variant == "plain-document")
    assert plain.verdict.status == "fail" and plain.tool_calls == 3  # one sandbox process: seq 1..3, trace valid


def test_autogen_agent_sensible_model_passes(tmp_path, monkeypatch):
    a = _run(False, tmp_path, monkeypatch)
    assert all(r.verdict.status == "pass" and r.tool_calls == 1 for r in a.runs)
