# mcp-chaos (npm launcher)

`npx mcp-chaos ...` runs [MCP-CHAOS](https://pypi.org/project/mcp-chaos/), a sandboxed security testing tool for tool-connected (MCP) AI agents. **The tool itself is the Python package**; this npm package only locates Python and forwards your arguments.

Requires Python >= 3.10. It uses, in order: `$MCP_CHAOS_PYTHON`, a `python3`/`python`/`py -3` that already has `mcp-chaos` installed, `uvx`, then `pipx`. If none work it tells you to `pip install mcp-chaos`.

```bash
npx mcp-chaos attack --target demo:vulnerable
```

For testing your own, local agents only. A pass means "survived these tests", not "secure".
