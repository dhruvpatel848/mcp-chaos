# Changelog

## 0.1.0 (alpha, unreleased)
- Sandbox with a mock MCP server, JSONL traces, replay, verdicts (confirmed / suspicious / inconclusive), scoring, JSON and Markdown reports.
- 10 campaigns: data-exfil, poisoned-content, destructive, cost-drain, file-access, cross-tool-leak, approval-bypass, permission-escalation, memory-poisoning, session-isolation; 5 payload styles; encoded-canary detection.
- Policy loop: generate / validate / self-test `mcp-guard.yaml`; `mcp-chaos guard` enforcement proxy with optional human approvals; `attack --guard`.
- Isolation: process sandbox and `--sandbox docker` (no network, read-only root) with `--allow-egress` allowlist proxy.
- Real-LLM agent (Anthropic native, OpenAI-compatible for many providers incl. Gemini, DeepSeek, Qwen, Kimi, GLM, ERNIE); LangGraph, OpenAI Agents SDK and AutoGen examples.
- CLI, MCP server (10 tools), Agent Skill, local dashboard, campaign plugin interface, npm launcher.
- Known limitations: see README.
