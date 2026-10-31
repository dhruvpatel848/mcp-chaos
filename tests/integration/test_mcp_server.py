import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _payload(res):
    if res.structuredContent is not None:
        sc = res.structuredContent
        return sc.get("result", sc) if isinstance(sc, dict) else sc
    return json.loads(res.content[0].text)


async def test_mcp_server_end_to_end(tmp_path):
    params = StdioServerParameters(command=sys.executable, args=["-m", "mcp_chaos.cli.main", "serve-mcp"], cwd=str(tmp_path))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            names = {t.name for t in (await s.list_tools()).tools}
            assert names == {"chaos_list_campaigns", "chaos_start_assessment", "chaos_get_assessment_status", "chaos_get_trace",
                             "chaos_analyze_results", "chaos_generate_policy", "chaos_validate_policy", "chaos_replay_attack",
                             "chaos_generate_report", "chaos_get_security_score"}
            bad = _payload(await s.call_tool("chaos_start_assessment", {"target": "http://evil"}))
            assert "error" in bad
            started = _payload(await s.call_tool("chaos_start_assessment", {"target": "demo:vulnerable", "mode": "data-exfil"}))
            aid = started["assessment_id"]
            for _ in range(120):
                st = _payload(await s.call_tool("chaos_get_assessment_status", {"assessment_id": aid}))
                if st["state"] != "running":
                    break
                await asyncio.sleep(1)
            assert st["state"] == "done", st
            score = _payload(await s.call_tool("chaos_get_security_score", {"assessment_id": aid}))
            assert score["overall"] <= 40
            pol = _payload(await s.call_tool("chaos_generate_policy", {"assessment_id": aid}))
            assert pol["review_required"] and "protect-sensitive-data" in pol["rules"]
            v = _payload(await s.call_tool("chaos_validate_policy", {"policy_path": str(tmp_path / "runs" / aid / "mcp-guard.yaml")}))
            assert v["valid"]
            trav = await s.call_tool("chaos_get_security_score", {"assessment_id": "../x"})
            assert trav.isError
