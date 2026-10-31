---
name: mcp-chaos
description: Run sandboxed security assessments of a LOCAL tool-connected (MCP) AI agent with MCP-CHAOS, interpret the evidence-backed findings, and generate a reviewable mcp-guard.yaml policy. Use when the user wants to red-team, security-test, or harden their own agent for prompt injection, data exfiltration, destructive actions, or cost-drain loops.
---

# MCP-CHAOS skill

MCP-CHAOS attacks an agent **inside a sandbox of fake tools** (fake secrets, in-memory DB, simulated shell, honeypot HTTP) and records every tool call. This skill teaches you to drive it.

## Requirements (installing this skill does NOT install these)
- The CLI: `pip install mcp-chaos` (Python >= 3.10). Verify with `mcp-chaos doctor`.
- Optional: the MCP server (`mcp-chaos serve-mcp`) registered in your client, giving you tools `chaos_*`. See `references/integration-guide.md`.
- Permission to run local commands. The scripts in `scripts/` only call the CLI.

## Hard rules
1. Only assess agents the user owns and that run **locally**. Never point MCP-CHAOS at third-party systems; it has no remote mode and you must not try to work around that.
2. Never disable or bypass sandbox protections. There is no flag for it.
3. Never claim an agent is "secure". A pass means "survived these tests". Report variability when runs differ.
4. Generated policies need human review before deployment. Say so every time.

## Workflow
1. **Initialize.** Confirm the target (script or local command) and its owner. `mcp-chaos doctor`; optionally `mcp-chaos init`. The agent must follow the contract in `references/integration-guide.md`.
2. **Select campaigns.** `mcp-chaos list-campaigns`. Default `all`; start narrow (`--mode data-exfil`) for a first look. See `references/attack-campaigns.md`.
3. **Run.** `python scripts/run_scan.py --target ./agent.py --mode all --runs 3` (wraps `mcp-chaos attack --json`). Use `--runs 3` or more: agents are non-deterministic.
4. **Interpret.** `python scripts/analyze_report.py runs/<id>`. Distinguish **confirmed** (fail), **suspicious**, and **inconclusive** results; see `references/report-interpretation.md`. For each failure explain what happened, the causing tool call, the evidence, and the fix.
5. **Policy.** `mcp-chaos policy runs/<id> --out mcp-guard.yaml`, then `python scripts/validate_policy.py mcp-guard.yaml`. Walk the user through each rule's `why` and `evidence` and ask them to fix allowlists. See `references/security-policies.md`.
6. **Remediate and rerun.** Apply the suggested fixes in the agent (not only the policy), then rerun the failed campaign: `mcp-chaos attack --target ... --mode <campaign> --runs 3`.
7. **Final assessment.** Summarize: score and method, confirmed/suspicious/inconclusive counts, per-campaign failure rate, fixes applied, remaining risk, and the limitations (these four campaigns only; sandbox is process-level, not a container).

## Exit codes
`0` all passed, `1` at least one failure, `2` setup/tool error.
