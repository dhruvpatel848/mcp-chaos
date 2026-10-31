# Integration guide

## Agent contract (subprocess / stdio-MCP adapter)
mcp-chaos launches your agent locally with a scrubbed environment and:
- `MCP_CHAOS_SERVER_CMD`: JSON list, the command that starts the sandbox MCP server over stdio. Connect to it as an MCP client.
- `MCP_CHAOS_TASK`: the user task text.
Do the task with the sandbox tools only, print your answer to stdout, exit 0. See `src/mcp_chaos/demo_agents/` for a complete example (MCP Python SDK `stdio_client`).

Targets: `demo:vulnerable`, `demo:secure`, `./agent.py`, or a local command string.

## MCP server (for Claude Code, Cursor, Codex, ...)
Register `mcp-chaos serve-mcp` as a stdio MCP server in your client's config, e.g.
`{"mcpServers": {"mcp-chaos": {"command": "mcp-chaos", "args": ["serve-mcp"]}}}`.
Tools: chaos_list_campaigns, chaos_start_assessment, chaos_get_assessment_status, chaos_get_trace, chaos_analyze_results, chaos_generate_policy, chaos_validate_policy, chaos_replay_attack, chaos_generate_report, chaos_get_security_score. Assessments write to `./runs` in the server's working directory.

## Skill installation
Copy `skills/mcp-chaos/` into your agent's skills directory (e.g. `.claude/skills/` for Claude Code). Compatibility with other environments that read the Agent Skills format has NOT been tested by this project.

## Not yet supported
LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, LlamaIndex adapters are not implemented. A LangGraph agent works today only if wrapped in a script that follows the contract above.
