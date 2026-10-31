# AGENTS.md

Instructions for AI coding agents working in this repository. Humans: see [CONTRIBUTING.md](CONTRIBUTING.md).

## What this project is

MCP-CHAOS is a sandboxed security testing tool for tool-connected (MCP) AI agents. It attacks a *local, user-owned* agent inside a fake world, records every tool call, produces evidence-backed verdicts, and generates and enforces an `mcp-guard.yaml` policy. Read [docs/security-model.md](docs/security-model.md) before changing anything under `mocks/`, `adapters/`, `sandbox/` or `guard/`.

## Commands

```bash
python -m venv .venv && .venv/Scripts/pip install -e ".[dev,dashboard,langgraph]"   # POSIX: .venv/bin/pip
.venv/Scripts/python -m pytest -q          # full suite (~7 min; Docker tests skip without the mcp-chaos:local image)
.venv/Scripts/python -m pytest -q tests/security     # fast: adversarial / regression tests
.venv/Scripts/ruff check src tests examples
docker build -t mcp-chaos:local .          # needed for the Docker tests
```

Work only in the project virtualenv. Never `pip install` into the global interpreter.

## Where things live

| Path | Purpose |
|---|---|
| `src/mcp_chaos/campaigns/` | attack campaigns (plugin interface in `base.py`); register in `registry.py` |
| `src/mcp_chaos/mocks/server.py` | the sandbox MCP server (every tool is simulated) |
| `src/mcp_chaos/core/detect.py` | tagging and leak detection shared by sandbox and verdicts |
| `src/mcp_chaos/guard/` | enforcement proxy and human approvals |
| `src/mcp_chaos/policies/` | policy schema, generation, validation, runtime evaluation (`enforce.py`) |
| `src/mcp_chaos/adapters/target.py` | how agents are launched (process and Docker) |
| `tests/security/` | adversarial tests: sandbox escape, guard bypass, approvals |

## Rules that never bend

1. **Never weaken the sandbox.** No flag, env var or "just for tests" path may enable real network egress by default, give tools host access, or disable isolation. A new tool in `mocks/server.py` must be simulated, not real.
2. **Payloads are synthetic and generic.** No real credentials, no exploits tuned against named products or real services.
3. **No claim without a test.** Do not write "supports X" or "verified" in docs unless a test or a live run in this repo shows it. State limits plainly; keep `README.md` and `docs/security-model.md` consistent with reality.
4. **Fail closed.** In the guard and policy engine, anything unparseable, oversized or ambiguous means *deny*. Add a test for every bypass you fix.
5. **Never commit secrets.** `.env` is gitignored; do not print, log or echo key values. Check `git diff` before committing.
6. **A new campaign needs both outcomes in tests:** the vulnerable demo agent fails it, the secure demo agent passes it, with evidence rules documented in `skills/mcp-chaos/references/attack-campaigns.md`.
7. **Fix the cause, not the symptom.** Do not skip, loosen or delete a failing test to get green; tell the maintainer if a test is wrong.

## Conventions

- Python >= 3.10, type hints on new code, `ruff` clean (rules pinned in `pyproject.toml`).
- Match surrounding style and comment density. Prefer small, reviewable changes.
- Update `CHANGELOG.md` under *Unreleased* for user-visible changes.
- **Commits:** no `Co-Authored-By` trailers and no tool attribution lines. The maintainer asked for this explicitly.
- **Destructive git operations** (force-push, history rewrite) and **publishing** (PyPI, npm) need explicit maintainer approval each time.

## Git author

Commits in this repository use the maintainer's GitHub no-reply identity (already set in the local git config). Do not change it.
