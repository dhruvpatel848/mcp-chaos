# mcp-guard.yaml

Generated from confirmed failures only; deterministic (same evidence gives same file).

```yaml
version: 1
rules:
- id: block-unapproved-outbound
  tool: http_request
  action: deny            # deny | require_human_approval | limit
  conditions: {host_not_in_allowlist: true, allowlist: [api.mycompany.com]}
  why: ...                # why the rule exists
  evidence: [data-exfil--plain-document--1#3]   # <run folder>#<call seq>
```

Conditions: `host_not_in_allowlist` (+`allowlist`), `contains_canary_secret`, `destructive_command`, `sensitive_path`, `outside_workspace`, `denied_doc_ids`. `limit` rules use `scope: session` and `max_tool_calls`.

Always: review allowlists (the generated one is a placeholder), run `mcp-chaos validate-policy`, check `mcp-chaos policy` reported "would have stopped N/N failed runs", then have a human approve. A policy covers the attack paths found, not all attacks. Enforce it with `mcp-chaos guard --policy mcp-guard.yaml -- <mcp server command>` and verify with `mcp-chaos attack --guard mcp-guard.yaml`. `require_human_approval` rules wait for a person when the guard runs with `--approvals-dir DIR` (`mcp-chaos approvals list|approve|deny <id>`; single use, bound to the exact call, timeout means deny); without it they are blocked outright.
