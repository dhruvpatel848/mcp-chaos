# Dependency audit (2026-11-01)

Tool: `pip-audit` against the project virtualenv (96 packages, Python 3.10).

Runtime dependencies (`mcp`, `pydantic`, `PyYAML`, `click`, `rich`, `httpx`, `starlette`, `anyio`, ...): no known vulnerabilities reported.

Findings, all outside the shipped runtime:
- `setuptools` (venv-bundled 57.4.0): fixed by upgrading the venv; not a dependency of mcp-chaos.
- `pytest` 8.4.2 (2 advisories, fix in 9.0.3): dev-only. The project pins `pytest<9` because pytest 9.2.0 crashed at startup with the pytest-asyncio versions tried (`NodeId` attribute error). Revisit when pytest-asyncio supports it.
- `filelock` 4.1.0 (17 advisories, fix in 4.2.1, which the index did not offer for Python 3.10): required only by `pip-audit` itself, not by mcp-chaos.

Compatibility constraints found while auditing: `mcp` is pinned `<2` (LlamaIndex's MCP tool package pulled `mcp` 2.x, which conflicts, so a LlamaIndex adapter was not added); the OpenAI Agents SDK needs `openai>=3`.

This is a point-in-time scan of one environment, not an independent security review. Re-run on release and in CI before publishing.
