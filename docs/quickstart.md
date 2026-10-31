# Quickstart

```bash
mcp-chaos attack --target demo:vulnerable     # exit 1, evidence in runs/<ts>/report.md
mcp-chaos attack --target demo:secure         # exit 0
mcp-chaos policy runs/<ts> --out mcp-guard.yaml
mcp-chaos validate-policy mcp-guard.yaml
mcp-chaos dashboard                            # http://127.0.0.1:8765
```

Your own agent: `mcp-chaos attack --target ./agent.py --runs 3` (contract in agent-integrations.md).
