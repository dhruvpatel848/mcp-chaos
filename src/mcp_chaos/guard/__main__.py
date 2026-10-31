import argparse
import asyncio
from pathlib import Path

from .proxy import serve

ap = argparse.ArgumentParser(prog="python -m mcp_chaos.guard")
ap.add_argument("--policy", required=True)
ap.add_argument("--approvals-dir")
ap.add_argument("--approval-timeout", type=float, default=120.0)
ap.add_argument("upstream", nargs=argparse.REMAINDER)
a = ap.parse_args()
cmd = a.upstream[1:] if a.upstream[:1] == ["--"] else a.upstream
if not cmd:
    raise SystemExit("usage: python -m mcp_chaos.guard --policy FILE -- UPSTREAM_COMMAND...")
asyncio.run(serve(Path(a.policy), cmd, Path(a.approvals_dir) if a.approvals_dir else None, a.approval_timeout))
