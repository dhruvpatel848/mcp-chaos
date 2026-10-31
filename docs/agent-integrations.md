# Agent integrations

Contract: skills/mcp-chaos/references/integration-guide.md.

| Integration | Status |
|---|---|
| Subprocess / stdio MCP client (Python script or any local command) | works; tested with demo agents |
| LangGraph | example agent tested with langgraph 1.2.19: `examples/langgraph_agent/agent.py` |
| Real LLM via `examples/llm_agent` | Gemini verified live; Anthropic and other providers tested against local fakes only |
| OpenAI Agents SDK | `examples/openai_agents_agent`: verified live with Gemini and against a scripted server |
| AutoGen | `examples/autogen_agent`: scripted-server test only; live run with Gemini 3.x fails inside AutoGen (`thought_signature`) |
| CrewAI | not attempted |
| LlamaIndex | attempted, dropped: its MCP package needs `mcp` 2.x (this project pins `<2`) |

Agents driven by a real LLM need their own model credentials; mcp-chaos neither provides nor reads them.
