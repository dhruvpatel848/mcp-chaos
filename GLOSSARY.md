# Glossary

Terms used across the code, docs and reports.

| Term | Meaning |
| --- | --- |
| **Agent under test** | The local agent being attacked. Launched by mcp-chaos as a subprocess (or in a container); it only talks to the sandbox's fake tools. |
| **Sandbox** | The simulated world: mock MCP server, fake files, in-memory database, simulated shell, honeypot HTTP. Process mode isolates the *tool surface*; Docker mode also isolates the *process*. |
| **Campaign** | One kind of attack: a threat, a synthetic payload, a detection rule, pass/fail criteria, remediation. A plugin class under `campaigns/`. |
| **Variant** | A way of delivering the same payload: `plain-document`, `hidden-unicode`, `tool-description`, `authority-doc`, `task-aligned-doc`, `memory-*`. |
| **Payload** | The planted instruction. Always synthetic and generic. |
| **Canary** | A random fake secret (`sk-chaos-CANARY-...`) generated per run. If it appears in an outbound request or another tool's arguments, that is an exact-match leak. |
| **Beacon** | A random harmless token the payload asks the agent to send; seeing it in a call proves the agent obeyed the injected instruction. |
| **Trace** | `trace.jsonl`: every tool call with timestamp, arguments, response, duration, tags, risk, canary exposure and parent call. |
| **Tag** | A label added by detection to a call (`canary-leak`, `sensitive-read`, `destructive`, `egress-unlisted`, `out-of-scope-read`, `cross-session`, ...). Verdicts and policies are derived from tags. |
| **Verdict** | The judged result of one run. **pass**: resisted. **fail** (confirmed): the harmful effect is in the trace. **suspicious**: risky behaviour without the harmful outcome. **inconclusive**: the run crashed, timed out or made no calls; never counted as a pass. |
| **Evidence** | The specific trace calls that support a verdict, and the causing call. |
| **Assessment** | One invocation of `attack`: all selected campaigns x variants x repetitions, saved as `assessment.json` with a score. |
| **Score** | 0-100 per campaign and overall; capped when critical or high confirmed findings exist. Describes these tests only, never proves security. |
| **Policy (`mcp-guard.yaml`)** | Rules generated from confirmed failures: what to deny, what needs approval, what to limit. Each rule carries a `why` and the traces it came from. |
| **Guard** | `mcp-chaos guard`: an MCP stdio proxy that enforces a policy in front of any MCP server. Fail-closed. |
| **Approval** | A human decision on a held call. Single-use, bound to the exact tool and arguments, unguessable id, expires. |
| **Egress proxy** | The allowlist-only HTTPS CONNECT proxy that lets a Docker-sandboxed agent reach exactly the hosts you name and nothing else. |
| **Process sandbox / Docker sandbox** | The two isolation modes. Only Docker mode blocks an agent's own network access. |
| **Permissive profile** | A labelled stress configuration of the example LLM agent (an "unattended, follow instructions you find" system prompt). An upper bound for a badly configured deployment, not a default. |
| **Adapter / agent contract** | How any agent plugs in: it receives `MCP_CHAOS_SERVER_CMD` and `MCP_CHAOS_TASK`, connects to the sandbox as an MCP client, does the task, prints an answer. |
| **Fail closed** | When something cannot be understood or evaluated, deny instead of allow. |
