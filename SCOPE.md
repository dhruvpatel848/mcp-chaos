# Scope

MCP-CHAOS tests **what a tool-connected agent does**, inside a sandbox, for the person who owns that agent. This file is the bar every request is judged against. Questions and ideas are welcome; anything outside this scope is closed politely, not because it is a bad idea but because it belongs elsewhere.

## In scope

- **Campaigns** that demonstrate a *class* of weakness in agent behaviour (instruction following from untrusted content, secret leakage, destructive actions, privilege and tenant boundaries, memory, runaway loops, approval handling).
- **Evidence**: traces, exact-match canaries, verdicts that say what happened and why, scoring that is explained.
- **The policy loop**: generating a reviewable policy from observed failures, enforcing it (guard proxy, approvals), and verifying it by attacking again.
- **Sandbox integrity**: anything that makes the sandbox harder to escape or its claims easier to verify.
- **Adapters and provider/framework verification** backed by a real run.
- **Reproducible measurements** across models, with the prompt profile, sample size and date stated.

## The bar for a new campaign

A campaign proposal stays open only if it has **all** of:

1. **A threat model**: who attacks what, through which channel, to what end.
2. **A synthetic, generic payload.** Nothing tuned against a named product, nothing with real credentials.
3. **A detection rule** that produces evidence from the trace (not a guess from the model's words).
4. **Both outcomes demonstrable**: a vulnerable agent fails it and a resisting agent passes it.
5. **Safe execution**: it only touches simulated, disposable resources.

Size is irrelevant: a one-line campaign and a large one face the same bar. +1 reactions do not count towards it.

## Out of scope

- **Attacking systems you do not own.** There is no remote-target mode and there will not be one.
- **Exploits for named products or services**, working credentials, or anything that functions as a real attack tool outside the sandbox.
- **Model jailbreak or toxicity scanning** of chat output. Tools like Garak and PyRIT cover that; this project covers tool-call behaviour.
- **Options that disable or weaken the sandbox**, or enable real network egress by default.
- **Autonomous exploitation**: this tool tests and reports, it does not pursue.
- **A production runtime firewall** claiming complete protection. The guard enforces the generated policy for the paths found; it is not a guarantee.
- **Config switches for one person's workflow.** Keep those in your own config or a fork.

## Not yet built (contributions wanted)

Multi-agent campaigns, distributed workers, multi-user dashboard authentication, RBAC and audit logs, a persistent findings database, OpenTelemetry export, a network MCP guard with authentication and TLS, CrewAI and LlamaIndex adapters. See [ROADMAP.md](ROADMAP.md).
