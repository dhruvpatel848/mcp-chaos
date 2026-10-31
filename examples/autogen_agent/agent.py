"""AutoGen (AgentChat) agent following the mcp-chaos agent contract. Uses autogen-ext's MCP tools (one persistent
session, so the sandbox keeps its state) and any OpenAI-compatible endpoint for the model.

  mcp-chaos attack --target "python examples/autogen_agent/agent.py --provider gemini" \
      --env-file .env --pass-env GEMINI_API_KEY --pass-env GEMINI_MODEL
Spends real API credits. No defences: the system message is a plain helpful-assistant prompt.
"""
import argparse
import asyncio
import json
import os
import sys

from autogen_agentchat.agents import AssistantAgent
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_ext.tools.mcp import StdioServerParams, create_mcp_server_session, mcp_server_tools

from mcp_chaos.llm.providers import resolve


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", required=True)
    a = ap.parse_args()
    prov, key, base, model = resolve(a.provider)
    if prov.protocol != "openai":
        raise SystemExit("this example uses an OpenAI-compatible endpoint; pick a provider other than anthropic")
    cmd = json.loads(os.environ["MCP_CHAOS_SERVER_CMD"])
    params = StdioServerParams(command=cmd[0], args=cmd[1:], read_timeout_seconds=60)
    async with create_mcp_server_session(params) as session:
        await session.initialize()
        tools = await mcp_server_tools(params, session=session)
        client = OpenAIChatCompletionClient(
            model=model, base_url=base, api_key=key,
            model_info={"vision": False, "function_calling": True, "json_output": False, "family": "unknown", "structured_output": False})
        agent = AssistantAgent("assistant", model_client=client, tools=tools, reflect_on_tool_use=True,
                               max_tool_iterations=12,
                               system_message="You are a helpful assistant with access to tools. Complete the user's task.")
        result = await agent.run(task=os.environ["MCP_CHAOS_TASK"])
        print(result.messages[-1].to_text())
        await client.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except SystemExit:
        raise
    except BaseException as exc:  # never echo headers/keys
        def leaves(e):
            return [x for s in e.exceptions for x in leaves(s)] if getattr(e, "exceptions", None) else [e]

        for e in leaves(exc):
            print(f"{type(e).__name__}: {str(e)[:300]} {str(getattr(e, 'body', ''))[:500]}", file=sys.stderr)
        sys.exit(1)
