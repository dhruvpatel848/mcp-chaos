# Security model and known limitations

Read this before trusting any result or running an agent you do not fully control. Report problems privately per [SECURITY.md](../SECURITY.md).

## What the sandbox guarantees

- **Tool surface is simulated.** The agent only sees tools served by the mock MCP server. `http_request` never opens a socket (it records the call and returns a canned reply). `bash_exec` never executes anything (it edits a virtual filesystem). `db_query` runs against a disposable in-memory SQLite database whose authorizer and statement allowlist deny `ATTACH`, `DETACH`, `PRAGMA`, `VACUUM` and `load_extension`, so it cannot touch host files.
- **Everything is synthetic.** Secrets, documents, canaries and beacon tokens are generated per run and are fake.
- **Scrubbed environment.** The agent process gets only PATH/TEMP/HOME-style variables plus variables you explicitly name with `--pass-env`.
- **Local targets only.** mcp-chaos launches the agent itself; there is no remote-target mode and no flag that enables real network access or turns the sandbox off.
- **Remote starts are restricted.** The MCP server and dashboard only start `demo:*` targets or `.py` scripts under `MCP_CHAOS_ALLOWED_TARGET_DIRS` (default: the working directory); arbitrary commands are refused. The CLI accepts any local command because the user is already running it.
- **Limits.** A per-run timeout (the process tree is killed) and a hard tool-call cap enforced by the sandbox server.

## Isolation modes

| Mode | Blocks the agent's own network access? | Notes |
| --- | --- | --- |
| process (default) | **No.** | Isolates only the tool surface. Demonstrated by `tests/sandbox/test_docker_isolation.py`: the same probe reached the internet in process mode. A testing aid, not a security boundary. |
| `--sandbox docker` | Yes | `--network none`, read-only root, all capabilities dropped, `no-new-privileges`, 512 MB / 1 CPU / 256 pids. Probe-verified: TCP, DNS and root-filesystem writes blocked. Supports `demo:*` and `python script.py [args]` only. |
| `--sandbox docker --allow-egress <host>` | Only to the hosts you list | The agent sits on an internal network; its only exit is an allowlist-only HTTPS CONNECT proxy (plain hostnames, port 443, no wildcards or IPs). Probe-verified: allowed host 200, other hosts and ports 403, direct IP/DNS blocked. |

**Secrets in Docker mode** are written to the container's stdin and read by a loader before the agent starts, so they are not on the `docker run` command line, not in `docker inspect`, `docker top` or the host process list (tested). They do live in the agent's process environment, as any API key does.

**Verification status:** Docker isolation, egress proxy and secret delivery are verified on Docker Desktop (Linux containers); CI also runs them on native Ubuntu runners.

## The guard

`mcp-chaos guard` is fail-closed. The following are denied, never allowed: non-object or oversized (> 256 KB) arguments; a host rule whose call has no recognisable URL; URLs that parsers disagree about (backslashes, userinfo, control characters, non-ASCII hosts); paths outside the workspace after normalisation; an exception while evaluating the policy; an exception in the approver. Secret detection is pattern-based at runtime (it cannot know your real secrets) and covers common encodings.

Approvals are single-use, bound to the exact tool and arguments, have 64-bit random ids, expire, and treat unreadable decisions as denials. **Keep the approvals directory where the agent under test cannot write.** The guard speaks stdio only: no network listener, so no authentication or TLS is needed or provided yet.

## What it does not guarantee

- **A malicious agent can escape the process sandbox.** This is a testing tool for your own agents, not malware containment. Use Docker mode for anything untrusted.
- **Detection is bounded.** Canaries are caught raw and in common encodings (base64, hex, URL, reversed, split, layered); a novel transformation (encryption, steganography, paraphrase) evades it, though the preceding secret read is still flagged.
- **A generated policy covers the attack paths found**, not all attacks. A policy for an HTTP tool says nothing about a tool it never saw.
- **Scores describe these tests** (10 built-in campaigns, bundled payloads), not overall security. A model that resists them may fail others.
- **No independent review has been done.** See the self-audit history in [SECURITY.md](../SECURITY.md).
- **Real-model evidence is thin:** one model, small samples ([measured-results.md](measured-results.md)).

## Misuse guardrails

Local-only targets, generic payloads (no product-specific attacks), responsible-use docs, [SCOPE.md](../SCOPE.md). Open design question: publish the full payload corpus or gate the strongest variants.
