# Policy format

See skills/mcp-chaos/references/security-policies.md. Fields: `id, tool, scope, action (deny | require_human_approval | limit), conditions, max_tool_calls, why, evidence`. Validate with `mcp-chaos validate-policy`; `mcp-chaos policy` also reports how many failed runs the policy would have stopped. Enforcement: `mcp-chaos guard` (stdio proxy).
