# Upgrading

MCP-CHAOS is alpha: minor versions can change behaviour. This file lists what you must do when you move between versions.

## To 0.1.0 (first release)

Nothing to migrate. For reference, behaviour that differs from earlier development snapshots:

- **Remote starts are restricted.** `chaos_start_assessment` (MCP) and `POST /api/assessments` (dashboard) accept only `demo:*` or a `.py` script under `MCP_CHAOS_ALLOWED_TARGET_DIRS` (default: the server's working directory). Arbitrary commands are refused. The CLI is unchanged and still accepts any local command.
- **Docker secrets.** `--pass-env` values reach a Docker-sandboxed agent over stdin, not `-e`, so they no longer appear in `docker inspect`. Agents read them from `os.environ` exactly as before; only `python script.py [args]` and `demo:*` targets work in Docker mode.
- **Guard is stricter.** Calls with non-object, oversized (> 256 KB) or ambiguous arguments are now denied, and host rules deny calls that carry no recognisable URL. If you wrote policies against an earlier snapshot, re-run `mcp-chaos validate-policy` and test with `mcp-chaos attack --guard`.
- **Approval ids** are now `<8 hex>-<16 hex>` and requests expire after `--approval-timeout`.
- **After changing code in a Docker setup,** rebuild the image: `docker build -t mcp-chaos:local .`

## Checking an upgrade

```bash
pip install -e ".[dev,dashboard,langgraph]"
mcp-chaos doctor
mcp-chaos attack --target demo:secure     # must exit 0
mcp-chaos attack --target demo:vulnerable # must exit 1
```
