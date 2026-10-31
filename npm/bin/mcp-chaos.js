#!/usr/bin/env node
// Thin launcher: runs the Python package `mcp-chaos`. It never downloads or executes anything other than that
// package, and passes all arguments through unchanged.
//
// Resolution order:
//   1. $MCP_CHAOS_PYTHON, if set (an interpreter that already has mcp-chaos installed)
//   2. python3 / python / py -3 on PATH, if `import mcp_chaos` works
//   3. uvx --from mcp-chaos mcp-chaos      (uv fetches the PyPI package into a cache)
//   4. pipx run --spec mcp-chaos mcp-chaos
"use strict";
const { spawnSync } = require("node:child_process");

const args = process.argv.slice(2);

function has(cmd, probe) {
  const r = spawnSync(cmd[0], [...cmd.slice(1), ...probe], { stdio: "ignore" });
  return !r.error && r.status === 0;
}

function run(cmd) {
  const r = spawnSync(cmd[0], [...cmd.slice(1), ...args], { stdio: "inherit" });
  if (r.error) {
    console.error(`mcp-chaos: failed to start ${cmd[0]}: ${r.error.message}`);
    process.exit(2);
  }
  process.exit(r.status === null ? 2 : r.status);
}

const MODULE = ["-m", "mcp_chaos.cli.main"];
const candidates = [];
if (process.env.MCP_CHAOS_PYTHON) candidates.push([process.env.MCP_CHAOS_PYTHON]);
candidates.push(["python3"], ["python"], ["py", "-3"]);

for (const py of candidates) {
  if (has(py, ["-c", "import mcp_chaos"])) run([...py, ...MODULE]);
}
if (has(["uvx"], ["--version"])) run(["uvx", "--from", "mcp-chaos", "mcp-chaos"]);
if (has(["pipx"], ["--version"])) run(["pipx", "run", "--spec", "mcp-chaos", "mcp-chaos"]);

console.error(
  "mcp-chaos needs Python >= 3.10 with the PyPI package installed.\n" +
    "  pip install mcp-chaos        (then re-run), or install uv/pipx so this launcher can fetch it.\n" +
    "  Or set MCP_CHAOS_PYTHON to an interpreter that has mcp-chaos installed."
);
process.exit(2);
