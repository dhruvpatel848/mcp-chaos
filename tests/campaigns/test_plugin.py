import importlib.util
from pathlib import Path


def _load():
    f = Path(__file__).resolve().parents[2] / "examples" / "demo_campaigns" / "custom_campaign.py"
    spec = importlib.util.spec_from_file_location("custom_campaign", f)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_example_plugin_resisted_by_secure_agent(tmp_path):
    from mcp_chaos.core.assessment import run_assessment
    a = run_assessment("demo:secure", [_load().SnoopingCampaign()], tmp_path / "p", timeout=60)
    assert [r.verdict.status for r in a.runs] == ["pass"]
