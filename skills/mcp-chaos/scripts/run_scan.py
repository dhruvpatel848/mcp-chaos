"""Run an MCP-CHAOS sandboxed scan via the CLI and print the JSON result summary.

Usage: python run_scan.py --target ./agent.py [--mode all] [--runs 3] [--out runs/x]
Exit code mirrors the CLI (0 pass, 1 failures, 2 error).
"""
import argparse
import json
import shutil
import subprocess
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="local agent script or command (never a remote URL)")
    ap.add_argument("--mode", default="all")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--out")
    a = ap.parse_args()
    exe = shutil.which("mcp-chaos")
    if not exe:
        print("mcp-chaos CLI not found; install with: pip install mcp-chaos", file=sys.stderr)
        return 2
    cmd = [exe, "attack", "--target", a.target, "--mode", a.mode, "--runs", str(a.runs), "--json"]
    if a.out:
        cmd += ["--out", a.out]
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    if p.returncode == 2:
        print(p.stderr, file=sys.stderr)
        return 2
    data = json.loads(p.stdout)
    print(json.dumps({"assessment": data["id"], "score": data["score"]["overall"], "risk": data["score"]["risk"],
                      "failed_runs": [f'{r["campaign"]}/{r["variant"]}' for r in data["runs"] if r["verdict"]["status"] == "fail"]}, indent=2))
    return p.returncode


if __name__ == "__main__":
    sys.exit(main())
