# Architecture

Campaign (builds sandbox state and payload) -> run dir (`state.json`) -> agent subprocess (scrubbed env) <-stdio MCP-> mock sandbox server (`mocks/server.py`, writes `trace.jsonl`) -> campaign `judge` (verdict) -> assessment (`assessment.json`, score) -> reports, policy generator, replay, dashboard, MCP server.

Modules: `core` (models, detection, assessment), `campaigns`, `adapters` (target launch), `mocks`, `recorder`, `policies`, `scoring`, `reporting`, `replay`, `mcp_server`, `dashboard`, `demo_agents`.

Verdict statuses: pass, fail (confirmed), suspicious, inconclusive.
