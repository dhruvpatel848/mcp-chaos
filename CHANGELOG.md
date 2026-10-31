# Changelog

All notable changes are recorded here. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/) once 1.0 is reached (until then, minor versions may change behaviour).

## [Unreleased]

### Security
- Sandbox DB tool can no longer `ATTACH`/`VACUUM INTO`/`PRAGMA` (host file creation); statement allowlist plus SQLite authorizer.
- MCP server and dashboard only start `demo:*` targets or `.py` scripts under `MCP_CHAOS_ALLOWED_TARGET_DIRS`; arbitrary commands are refused.
- Guard is fail-closed: missing/odd URL arguments, non-object or oversized arguments, ambiguous URLs (backslash, userinfo, control characters, non-ASCII hosts), crashes in policy evaluation or the approver all block the call.
- Guard: destructive and secret checks scan every argument; workspace checks normalise paths.
- Approvals expire, ids are 64-bit random, decisions are bound to the exact call, corrupt decision files deny, ids are strictly validated.
- Docker mode delivers API keys over stdin instead of `docker run -e`.
- Run directories from `assessment.json` must stay inside the assessment folder.

### Fixed
- Guard returned an error for every allowed call to a tool with an `outputSchema`.
- A command-string target ending in `.py` with no arguments was misread as a script path; relative script paths resolved against the run folder; bare `python` resolved to the wrong interpreter.

### Added
- `tests/security/` with adversarial tests (sandbox escape, guard bypass, approvals).
- `AGENTS.md`, `CLAUDE.md`, `SCOPE.md`, `GLOSSARY.md`, `UPGRADING.md`, issue forms, `CODEOWNERS`.

## [0.1.0] - unreleased (alpha)

### Added
- Sandbox with a mock MCP server, JSONL traces, replay, verdicts (confirmed / suspicious / inconclusive), scoring, JSON and Markdown reports.
- 10 campaigns (data-exfil, poisoned-content, destructive, cost-drain, file-access, cross-tool-leak, approval-bypass, permission-escalation, memory-poisoning, session-isolation), 5 payload styles, encoded-canary detection.
- Policy loop: generate / validate / self-test `mcp-guard.yaml`; `mcp-chaos guard` enforcement proxy with optional human approvals; `attack --guard`.
- Isolation: process sandbox and `--sandbox docker` (no network, read-only root) with an `--allow-egress` allowlist proxy.
- Real-LLM agent (Anthropic native; OpenAI-compatible for many providers); LangGraph, OpenAI Agents SDK and AutoGen examples.
- CLI, MCP server (10 tools), Agent Skill, local dashboard, campaign plugin interface, npm launcher.

### Known limitations
See the README section "What is and is not done".

[Unreleased]: https://github.com/dhruvpatel848/mcp-chaos/compare/main...HEAD
