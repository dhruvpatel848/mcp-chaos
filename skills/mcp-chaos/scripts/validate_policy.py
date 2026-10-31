"""Validate an mcp-guard.yaml via the CLI. Usage: python validate_policy.py mcp-guard.yaml"""
import shutil
import subprocess
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    exe = shutil.which("mcp-chaos")
    if not exe:
        print("mcp-chaos CLI not found; install with: pip install mcp-chaos", file=sys.stderr)
        return 2
    p = subprocess.run([exe, "validate-policy", sys.argv[1]], text=True)
    return p.returncode


if __name__ == "__main__":
    sys.exit(main())
