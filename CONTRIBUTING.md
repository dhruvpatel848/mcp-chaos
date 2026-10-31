# Contributing to MCP-CHAOS

Thank you for helping. MCP-CHAOS is built to be extended by the community: small, reviewable pull requests from anyone, a documented plugin interface, and a public roadmap. You do not need permission to start; for anything large, open an issue first so we agree on the shape.

Please read [SCOPE.md](SCOPE.md) first: it says what fits and what does not, and [AGENTS.md](AGENTS.md) holds the rules every change (human or AI-assisted) must follow.

## Where each request goes

| You have | Go to |
| --- | --- |
| A bug (including a wrong result in a verdict or a policy) | [Bug report](https://github.com/dhruvpatel848/mcp-chaos/issues/new?template=bug_report.yml) |
| A sandbox escape, a guard bypass, or anything exploitable | **Not a public issue.** [Report it privately](https://github.com/dhruvpatel848/mcp-chaos/security/advisories/new), see [SECURITY.md](SECURITY.md) |
| A new attack campaign | [Campaign proposal](https://github.com/dhruvpatel848/mcp-chaos/issues/new?template=campaign_proposal.yml) |
| A feature or an improvement | [Feature request](https://github.com/dhruvpatel848/mcp-chaos/issues/new?template=feature_request.yml) |
| Results from testing a provider or framework you use | A pull request adding them to [docs/measured-results.md](docs/measured-results.md) or [docs/agent-integrations.md](docs/agent-integrations.md) |
| A small fix, a typo, a docs correction | Just open a pull request |

## What makes a good pull request

- **Bug fixes** with a test that fails before the fix.
- **New campaigns** that clear the bar in [SCOPE.md](SCOPE.md) and ship with both outcomes tested.
- **Adapters and provider verification**, with a real run behind every "works" claim.
- **Sandbox and guard hardening**, especially adversarial tests (bypass attempts, malformed input, races).
- **Documentation corrections**: wrong information, stale claims, broken links.

Large rewrites, new abstractions without a user, and features that only suit one workflow will be closed without a long explanation. Open an issue instead.

## The non-negotiable rules

These get a pull request rejected if missed.

1. **Never weaken the sandbox.** No option that enables real network egress by default or gives a tool host access. Anything that touches `mocks/`, `adapters/`, `sandbox/` or `guard/` is reviewed as security-sensitive.
2. **Payloads are synthetic and generic.** No real credentials, no attacks tuned against named products or services. We demonstrate a *class* of weakness.
3. **No claim without a test.** Do not write "supports X" or "verified on Y" unless a test or a recorded live run shows it. If something is unverified, say so.
4. **Fail closed.** In the guard and policy engine, unparseable, oversized or ambiguous input means deny. Every bypass fix needs a regression test in `tests/security/`.
5. **No secrets in the repo.** Check `git diff` before you commit.
6. **Do not weaken tests to get green.**

## Development setup

```bash
git clone https://github.com/dhruvpatel848/mcp-chaos && cd mcp-chaos
python -m venv .venv
.venv/Scripts/pip install -e ".[dev,dashboard,langgraph]"      # POSIX: .venv/bin/pip
.venv/Scripts/python -m pytest -q tests/security                # fast
.venv/Scripts/python -m pytest -q                               # full suite
.venv/Scripts/ruff check src tests examples
docker build -t mcp-chaos:local .                               # enables the Docker tests
```

The full suite runs real subprocesses and takes several minutes. No API key or paid service is needed for any test: model-facing tests use local scripted servers.

## Adding a campaign

1. Copy [`examples/demo_campaigns/custom_campaign.py`](examples/demo_campaigns/custom_campaign.py) and read [docs/campaigns.md](docs/campaigns.md) for the interface.
2. Define the threat, a synthetic payload, the detection rule (what is *evidence*), pass/fail/suspicious criteria, and remediation.
3. Make the vulnerable demo agent fail it and the secure demo agent pass it (extend `src/mcp_chaos/demo_agents/` only as needed), and add the evidence rule to `skills/mcp-chaos/references/attack-campaigns.md`.
4. Add tests under `tests/campaigns/`, and a policy rule if the failure is blockable.

## Testing your changes

Run `pytest -q` and `ruff check`. For anything that touches an agent or a provider, include in the PR description what you ran and what the output looked like (counts for runs, the verdict, the trace excerpt). Do not paste keys, tokens or full `.env` contents anywhere.

## Contributions written with AI

Agents are welcome to help, but you submit the work, so you own it:

- Read and run it yourself. A PR you have not run is not ready.
- Keep it small and focused: one concern per PR.
- Do not generate pull requests that add speculative abstractions, large rewrites, or unverified claims in the docs.
- Follow [AGENTS.md](AGENTS.md); it is written for your agent too.

## Commits and pull requests

- Small commits with a clear message (what and why). Conventional prefixes (`fix:`, `feat:`, `docs:`, `test:`, `ci:`, `security:`) are appreciated.
- Update [CHANGELOG.md](CHANGELOG.md) under *Unreleased* for user-visible changes.
- CI must pass (lint, tests on Ubuntu and Windows, Python 3.10 and 3.12).

## Conduct and security

Be kind and technical: [Code of Conduct](CODE_OF_CONDUCT.md). Vulnerabilities go through [SECURITY.md](SECURITY.md), never a public issue.
