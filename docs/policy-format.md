# Policy format and the guard

`mcp-guard.yaml` is generated from confirmed failures by `mcp-chaos policy`, can be edited by hand, and is enforced by `mcp-chaos guard`. A generated policy always needs human review: see the warnings below.

```yaml
version: 1
rules:
- id: block-unapproved-outbound
  tool: http_request
  action: deny                 # deny | require_human_approval | limit
  conditions: {host_not_in_allowlist: true, allowlist: [api.mycompany.com]}
  why: The agent sent a request to a host outside the allowlist. REVIEW the allowlist.
  evidence: [data-exfil--plain-document--1#3]     # <run folder>#<call number>
- id: limit-tool-calls
  scope: session
  action: limit
  max_tool_calls: 50
```

## Conditions

| Condition | Matches when |
| --- | --- |
| `host_not_in_allowlist` (+ `allowlist`) | any URL-like argument is not on the list. **Fails closed:** no recognisable URL, or an ambiguous one, also matches. |
| `contains_canary_secret` | an argument contains a secret-shaped string (raw or decoded). |
| `destructive_command` | any string argument looks like a destructive shell or SQL command. |
| `sensitive_path` | a path argument looks like `.env`, `id_rsa`, credentials. |
| `outside_workspace` | a path argument is not under `/workspace` after normalisation. |
| `denied_doc_ids` | `doc_id` is in the list. |

## Commands

```bash
mcp-chaos validate-policy mcp-guard.yaml     # schema, duplicate ids, conflicts, unknown conditions
mcp-chaos policy runs/<ts> --out mcp-guard.yaml   # also reports "would have stopped N/N failed runs"
mcp-chaos attack --target ./agent.py --guard mcp-guard.yaml     # re-attack through the enforcer
mcp-chaos guard --policy mcp-guard.yaml -- <mcp server command>  # enforce in front of any MCP server
mcp-chaos guard --policy mcp-guard.yaml --approvals-dir ./approvals -- <cmd>   # hold risky calls for a human
mcp-chaos approvals list --dir ./approvals
mcp-chaos approvals approve <id> --dir ./approvals      # single use; expires; bound to the exact call
```

## Always

Review every rule, especially allowlists (the generated one is a placeholder). Keep the approvals directory out of the agent's reach. A policy covers the paths that were found; it is not a guarantee. Behaviour details and limits: [security-model.md](security-model.md).
