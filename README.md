# MCP-CHAOS

Open-source, sandboxed security testing for tool-connected (MCP) AI agents. It plants poisoned content in a world of fake tools, watches every tool call your agent makes, reports evidence-backed failures, writes a reviewable `mcp-guard.yaml` policy, and can enforce that policy in front of any MCP server.

> For testing **your own, local** agents only. A passing score means "survived these tests", not "secure". Read [docs/security-model.md](https://github.com/dhruvpatel848/mcp-chaos/blob/main/docs/security-model.md) and [docs/measured-results.md](https://github.com/dhruvpatel848/mcp-chaos/blob/main/docs/measured-results.md).

## Quickstart

```bash
pip install -e ".[dev,dashboard,langgraph]"   # from a clone; Python >= 3.10; use a virtualenv
mcp-chaos doctor
mcp-chaos attack --target demo:vulnerable      # fails with evidence (exit 1)
mcp-chaos attack --target demo:secure          # passes (exit 0)
mcp-chaos policy runs/<timestamp> --out mcp-guard.yaml
mcp-chaos attack --target demo:vulnerable --guard mcp-guard.yaml   # re-attack through the enforcer
mcp-chaos dashboard                            # http://127.0.0.1:8765
```

Your own agent: `mcp-chaos attack --target ./my_agent.py --runs 3` (contract: [docs/agent-integrations.md](https://github.com/dhruvpatel848/mcp-chaos/blob/main/docs/agent-integrations.md)).

## What works (each item is covered by tests; real-model items were also run live)
- **10 campaigns:** data exfiltration, indirect prompt injection, destructive actions, cost drain/loops, unauthorized file access, cross-tool leakage, human-approval bypass, permission escalation, memory poisoning, session isolation. Variants: plain, invisible Unicode, tool description, authority impersonation, policy-framed. Canary leaks are caught raw or encoded (base64, hex, URL, reversed, split, layered).
- **Verdicts and reports:** confirmed / suspicious / inconclusive, evidence, severity, remediation, scoring, JSON + Markdown reports, replay, CI exit codes (0/1/2), local dashboard.
- **Policy loop:** generate `mcp-guard.yaml` from failures, validate, self-test, enforce with `mcp-chaos guard` (MCP stdio proxy), optional human approvals (`--approvals-dir`, `mcp-chaos approvals approve <id>`, single-use, bound to the exact call, timeout = deny), re-attack with `--guard`.
- **Isolation:** `--sandbox docker` (no-network container, read-only root, dropped capabilities, resource limits) and `--allow-egress <host>` (allowlist-only HTTPS proxy; no wildcards or IPs). Verified on Docker Desktop 28.3.2 with probe agents: only the allowlisted host on 443 is reachable.
- **Real agents:** `examples/llm_agent` (Anthropic native; OpenAI-compatible for Gemini, OpenAI, xAI, Mistral, Groq, Together, OpenRouter, DeepSeek, Qwen, Kimi, GLM, ERNIE, MiniMax, Yi, custom). Keys reach the agent only via `--pass-env`.
- **Framework examples:** LangGraph, OpenAI Agents SDK (both also run live), AutoGen (scripted-model test only; see below).
- MCP server (`mcp-chaos serve-mcp`, 10 tools), Agent Skill (`skills/mcp-chaos/`), campaign plugin interface.

## Measured with a real model
Gemini 3.5 Flash-Lite, neutral prompt: 93/93 runs resisted. Under a permissive "unattended agent" prompt it failed `session-isolation` via a poisoned tool description in 7 of 7 attempts; the generated policy, enforced by the guard, stopped it in 20/20 re-runs. One model, small samples: details and caveats in [docs/measured-results.md](https://github.com/dhruvpatel848/mcp-chaos/blob/main/docs/measured-results.md).

## Known limitations (not done)
- **Only Gemini was tested against a live model.** Anthropic and the other OpenAI-compatible providers are tested against local scripted servers only, and their base URLs were written from memory: verify before relying on them.
- **Adapters:** AutoGen runs against scripted servers but not live (AutoGen 0.7.5 drops the `thought_signature` Gemini 3.x requires; it needs a different model/provider to verify). CrewAI was not attempted. LlamaIndex was attempted and dropped: its MCP package requires `mcp` 2.x, which conflicts with this project's `mcp<2`.
- **Docker mode:** verified on Docker Desktop (Windows) only, not on a Linux host; it supports demo agents and `python script.py [args]` only; API keys passed to a container are visible in `docker inspect`.
- **Guard:** pattern-based secret detection at runtime; stdio only (no network auth/TLS); approvals are file-based.
- **Not built:** multi-agent campaigns; load/concurrency testing; multi-user dashboard auth; PyPI release, demo video. Dependency scan done once ([docs/security-audit.md](https://github.com/dhruvpatel848/mcp-chaos/blob/main/docs/security-audit.md)); no independent security review.
- **Not proven at scale:** nothing here has been run beyond a single developer machine.

## Contributing: contributions are welcome

MCP-CHAOS is an open-source project built to be extended by the community, the way large open-source projects are: small, reviewable pull requests from anyone, a clear plugin interface, public issues and a public roadmap. You do not need to ask permission to start.

Good places to start (each has real, testable acceptance criteria):
- **Add a campaign.** Write a plugin with the documented interface ([docs/campaigns.md](https://github.com/dhruvpatel848/mcp-chaos/blob/main/docs/campaigns.md)); ship it with a vulnerable and a resisting outcome in tests. Wanted: multi-agent communication risks, insecure output handling, more session/tenant isolation cases.
- **Verify a provider live.** Only Gemini was exercised against a real service. Run `examples/llm_agent` with your own key for Anthropic, OpenAI, DeepSeek, Qwen, Kimi, GLM, ERNIE or others, fix any wrong base URL or model name, and send the result.
- **Add or finish a framework adapter.** CrewAI (not attempted), AutoGen live verification, LlamaIndex (blocked on `mcp` 2.x). Claim support only after a real run.
- **Better payloads and measurements.** Stronger or more varied (still synthetic) payloads, bigger `--runs` samples across models; add them to [docs/measured-results.md](https://github.com/dhruvpatel848/mcp-chaos/blob/main/docs/measured-results.md).
- **Harden the sandbox.** Linux Docker verification, secret delivery that avoids `docker inspect`, more isolation tests.
- **Docs, bug reports, and reviews** are equally valuable.

How: fork, branch, `pip install -e ".[dev,dashboard,langgraph]"`, make `pytest -q` and `ruff check src tests` pass, open a PR. Read [CONTRIBUTING.md](https://github.com/dhruvpatel848/mcp-chaos/blob/main/CONTRIBUTING.md) and the [Code of Conduct](https://github.com/dhruvpatel848/mcp-chaos/blob/main/CODE_OF_CONDUCT.md). Rules that never bend: payloads stay synthetic and generic, nothing may weaken the sandbox or enable real network egress by default, and no claim without a test. Report vulnerabilities privately via [SECURITY.md](https://github.com/dhruvpatel848/mcp-chaos/blob/main/SECURITY.md).

See [ROADMAP.md](https://github.com/dhruvpatel848/mcp-chaos/blob/main/ROADMAP.md). Licensed under Apache-2.0.
