# Security policy

MCP-CHAOS is a security tool that runs untrusted agent code in a sandbox, so the sandbox, the guard proxy and the approval mechanism are the parts that matter most. We take reports about them seriously.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x (alpha, `main`) | yes |

The project is alpha software maintained by one person. Fixes land on `main` first.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub:

**https://github.com/dhruvpatel848/mcp-chaos/security/advisories/new**

Include what you can: the version or commit, the platform (OS, Python, Docker version), the sandbox mode (`process`, `docker`, `docker + --allow-egress`), a minimal reproduction, and what you believe the impact is. A failing test in the style of `tests/security/` is the most useful report possible.

What to expect (best effort, solo maintainer): an acknowledgement within 7 days, an assessment within 14 days, and a fix or a clear mitigation for confirmed issues as quickly as the severity warrants. You will be credited in the advisory and the changelog unless you prefer otherwise. Please give us a reasonable chance to fix before disclosing publicly.

## What is in scope

- **Sandbox escape:** an agent under test, or a tool in the sandbox, reaching the host filesystem, network or processes beyond what the mode permits.
- **Guard bypass:** a tool call that a correctly written policy should block reaching the upstream server (URL/host parsing tricks, argument-shape tricks, encoding, size, concurrency, error handling that fails open).
- **Approval bypass:** forging, replaying, pre-approving or redirecting an approval.
- **Remote execution via MCP server or dashboard:** starting arbitrary commands or reading arbitrary files through the MCP tools or the web API.
- **Secret exposure:** API keys or tokens leaking into logs, traces, reports, run folders, `docker inspect` or process listings.
- **Supply chain:** a malicious or vulnerable dependency, a compromised release process.

## What is not a vulnerability

- **The tool finding weaknesses in your agent.** That is the product working.
- **The default process sandbox not blocking an agent's own network access.** This is documented: use `--sandbox docker` for untrusted agents. (An escape *from* the Docker sandbox is in scope.)
- **Findings that require the attacker to already control the machine, the `.env` file, or the approvals directory.** Keep the approvals directory out of the agent's reach.
- **Weaknesses of a model or provider** revealed by the payloads, and the bundled payloads themselves: they are deliberately synthetic and generic.

## Safe harbor

Testing against your own installation, in good faith, to find and report issues is welcome. Do not attack systems you do not own, and do not access data that is not yours.

## Hardening notes for operators

- Run untrusted agents with `--sandbox docker`; add `--allow-egress` only for the exact API host an agent needs.
- Never expose the dashboard beyond localhost. It binds to `127.0.0.1`, checks the `Host` header, and requires a per-process token for state-changing calls, but it has no user authentication.
- The MCP server and dashboard only start `demo:*` targets or `.py` scripts under `MCP_CHAOS_ALLOWED_TARGET_DIRS` (default: the working directory). Keep that directory free of untrusted scripts.
- Put the guard's `--approvals-dir` somewhere the agent under test cannot write.

## Self-audit history

No independent review has been done yet. A self-audit of the source on 2026-11-01 found and fixed the following; each has a regression test in `tests/security/`.

| Finding | Severity | Status |
| --- | --- | --- |
| The sandbox DB tool allowed SQLite `ATTACH DATABASE`, creating files on the host | High (sandbox escape) | Fixed: authorizer + statement allowlist |
| MCP server and dashboard accepted arbitrary command strings as targets (e.g. `python -c ...`) | High (remote execution if the caller is prompt-injected) | Fixed: demo targets or allowed-directory scripts only |
| Guard: a host rule with no recognisable URL argument allowed the call (fail-open) | High | Fixed: deny |
| Guard: `http://evil\@allowed.com` parsed as the allowed host | High | Fixed: ambiguous URLs are never allowlisted |
| Guard: arguments over 200 KB skipped encoded-secret scanning | Medium | Fixed: oversized arguments are refused |
| Guard: destructive-command check read only the `command` and `sql` argument names | Medium | Fixed: all strings are scanned |
| `/workspace/../etc/passwd` and `/workspace-evil/x` passed the workspace check | Medium | Fixed: paths are normalised |
| Approvals: a stale request from a crashed guard could be approved later | Medium | Fixed: requests expire |
| Docker mode passed API keys with `docker run -e` (visible via `docker inspect`) | Medium | Fixed: delivered over stdin |
| Guard returned errors for every *allowed* call (structured output) | Availability | Fixed |
| A tampered `assessment.json` could point run folders outside the assessment folder | Low | Fixed |

Dependency scan: [docs/security-audit.md](docs/security-audit.md).
