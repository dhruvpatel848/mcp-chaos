# Security model and known limitations

**What the sandbox guarantees (v0.1)**
- The agent only sees tools served by the mock MCP server. `http_request` never opens a socket; it records the call and returns a canned reply. `bash_exec` never executes anything; it edits a virtual filesystem. `db_query` runs against a disposable in-memory SQLite database.
- Secrets, documents, canaries and beacon tokens are generated per run and are fake. The agent process gets a scrubbed environment (no host env vars beyond PATH/TEMP/HOME-style variables).
- The agent is launched by mcp-chaos itself; remote targets are rejected. There is no flag that enables real network access or turns off the sandbox.
- Per-run timeout (process tree killed) and a hard tool-call cap enforced by the server.

**What it does NOT guarantee**
- The agent is an ordinary OS process. mcp-chaos does **not** block that process from opening its own sockets or touching host files outside the MCP tool surface (for example, an agent that calls a real LLM API directly). Infrastructure-level egress denial is available through `--sandbox docker` (`--network none`, read-only root, all capabilities dropped, no-new-privileges, 512 MB / 1 CPU / 256 pids). Verified on Docker Desktop 28.3.2 with a probe agent (tests/sandbox/test_docker_isolation.py): TCP, DNS and root-filesystem writes blocked, host secrets absent; in process mode the same probe reached the internet. Not yet verified on a Linux host (bind-mount ownership may differ). Treat the default process sandbox as a testing aid, not a security boundary. Real-LLM agents can run in Docker with `--allow-egress <provider host>`: the agent sits on an internal network whose only exit is an allowlist-only HTTPS CONNECT proxy (explicit hostnames, port 443 only; verified with a probe: allowed host 200, other hosts and ports 403, direct IP/DNS blocked). Keys are passed only through explicit `--pass-env`; note that environment variables given to a container are visible via `docker inspect` on that machine.
- A malicious agent can escape; this is a testing tool for your own agents, not malware containment.
- Detection works on synthetic canaries: exact match plus common encodings (base64, hex, URL, reversed, split, layered). A novel transformation (e.g. encryption, steganography, paraphrasing a secret) evades it; the read may still be flagged `sensitive-read`.
- Scores reflect the 7 built-in campaigns, not overall security.

**Misuse guardrails**: local-only targets, generic payloads (no product-specific attacks), responsible-use docs. Open question from the design doc (publish strongest payload variants or gate them) is unresolved.
