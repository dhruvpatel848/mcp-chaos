# Roadmap

Done: sandbox (process and Docker with egress allowlist), 10 campaigns, encoded-canary detection, guard proxy with human approvals, traces/replay, verdicts, scoring, policy generator/validator, CLI, MCP server, skill, dashboard, real-LLM agent, LangGraph / OpenAI Agents SDK / AutoGen examples, plugin interface, dependency audit.

Next, in order:
1. Verify AutoGen live with a provider that works with it; CrewAI adapter; LlamaIndex once its MCP package supports `mcp<2` or this project moves to mcp 2.x.
2. Live-verify Anthropic and the other provider endpoints with their own keys; correct any wrong base URLs.
3. Docker mode on Linux hosts; secret delivery that does not appear in `docker inspect`.
4. Multi-agent campaigns; larger payload corpora and larger-sample measurements across models.
5. Dashboard auth for multi-user deployment; run queueing/concurrency and load tests.
6. PyPI release (trusted publishing), CI in the cloud, independent security review, demo video.
7. Decide the open question: publish the full payload corpus or gate the strongest variants.
