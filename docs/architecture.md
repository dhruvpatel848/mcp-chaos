# Architecture

Campaign (builds sandbox state and payload) -> run dir (`state.json`) -> agent subprocess (scrubbed env) <-stdio MCP-> mock sandbox server (`mocks/server.py`, writes `trace.jsonl`) -> campaign `judge` (verdict) -> assessment (`assessment.json`, score) -> reports, policy generator, replay, dashboard, MCP server.

Modules: `core` (models, detection, assessment), `campaigns`, `adapters` (target launch), `mocks`, `recorder`, `policies`, `scoring`, `reporting`, `replay`, `mcp_server`, `dashboard`, `demo_agents`.

Verdict statuses: pass, fail (confirmed), suspicious, inconclusive.

## Enforcement

`policies/policy.py` generates and validates `mcp-guard.yaml`; `policies/enforce.py` evaluates it at runtime (fail-closed); `guard/proxy.py` is the stdio proxy that applies it in front of any MCP server, with optional human approvals (`guard/approvals.py`). `sandbox/egress_proxy.py` is the allowlist-only HTTPS proxy used by the Docker sandbox. See [security-model.md](security-model.md).
