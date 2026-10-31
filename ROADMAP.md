# Roadmap

Status key: `[x]` done and tested, `[~]` partly done (see note), `[ ]` not done. Priorities follow the order of the phases: engineering credibility first, features second.

## Phase 1: Security hardening (P0)

- [~] **Verify Docker isolation on native Linux.** Verified on Docker Desktop; a CI job now runs the Docker tests on Ubuntu runners. Pending first green run.
- [x] **Safer secret delivery.** API keys go to Docker-sandboxed agents over stdin, not `docker run -e`; tested against `docker inspect`, `docker top` and the host process list.
- [x] **Guard bypass and malformed-message tests.** `tests/security/test_guard_bypass.py`: URL parser tricks, missing/odd arguments, encodings, oversized payloads, non-object arguments, garbage JSON-RPC on the real proxy. Real bypasses found and fixed (see SECURITY.md).
- [x] **Approval replay, expiry and race tests.** `tests/security/test_approvals.py`.
- [x] **Fail-closed enforcement tests.** A crashing policy engine or approver blocks the call.
- [ ] **Independent security review.** Needs a third party. Until then the claim is "self-audited".

## Phase 2: Engineering quality (P1)

- [x] **CI passes** on Ubuntu and Windows, Python 3.10 and 3.12.
- [ ] **Strict type checking** (mypy).
- [ ] **Mutation testing**, starting with `core/detect.py` and `policies/enforce.py`.
- [~] **Dependency scanning in CI.** `pip-audit` job added; findings policy to be tuned.
- [~] **Reproducible integration tests.** Model-facing tests use local scripted servers (no keys, deterministic). Pinned lockfile not yet.
- [~] **Documentation consistency.** Reworked; keep README, `docs/security-model.md` and the skill references in sync with every change.

## Phase 3: Ecosystem (P2)

- [ ] **Live-test Anthropic and OpenAI** (needs keys; only Gemini has been run live).
- [ ] **Complete AutoGen live verification and a CrewAI adapter.**
- [ ] **MCP version strategy.** Currently pinned `mcp>=1.2,<2`. Decide between staying on 1.x, supporting both, or moving to 2.x (which unblocks LlamaIndex).
- [~] **Publish.** On TestPyPI; PyPI and npm after a go-ahead and tokens.
- [ ] **More community campaigns** (multi-agent, insecure output handling, more tenant-isolation cases).
- [ ] **Publish a benchmark dataset:** multiple providers, fixed prompts, stated sample sizes, reproducible.

## Phase 4: Enterprise readiness (P3)

- [ ] Multi-agent security testing
- [ ] Distributed campaign workers
- [ ] Multi-user dashboard authentication
- [ ] RBAC and audit logs
- [ ] Persistent findings database
- [ ] Enterprise policy management
- [ ] OpenTelemetry integration
- [ ] Network-based MCP guard with authentication and TLS

## Direction

```text
                 MCP-CHAOS
                     |
       +-------------+-------------+
       |             |             |
   Attack Engine  Agent Engine  MCP Guard
       |             |             |
       +-------------+-------------+
                     |
               Evidence Engine
                     |
              Policy Engine
                     |
             Security Dashboard
                     |
              Results Storage
                     |
             CI/CD Integration
```

The strongest idea here is the loop: observed agent failure -> reviewable policy -> enforcement -> verify by attacking again. Three things matter most: a sandbox that is demonstrably secure on Linux, a reproducible benchmark across providers, and a guard that holds up against adversarial input, bypass attempts and concurrency. A successful experiment is not proof that an agent is secure; the project says so everywhere on purpose.

Open question from the design: publish the full payload corpus, or gate the strongest variants?
