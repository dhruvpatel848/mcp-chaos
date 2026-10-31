"use strict";
const test = require("node:test");
const assert = require("node:assert");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const LAUNCHER = path.join(__dirname, "..", "bin", "mcp-chaos.js");
const PY = process.env.MCP_CHAOS_TEST_PYTHON; // an interpreter with mcp-chaos installed

test("forwards args and exit code to the Python tool", { skip: !PY }, () => {
  const r = spawnSync(process.execPath, [LAUNCHER, "list-campaigns", "--json"], {
    env: { ...process.env, MCP_CHAOS_PYTHON: PY }, encoding: "utf8",
  });
  assert.strictEqual(r.status, 0, r.stderr);
  const ids = JSON.parse(r.stdout).map((c) => c.id);
  assert.ok(ids.includes("data-exfil") && ids.includes("session-isolation"));
});

test("propagates a failing exit code (attack on vulnerable demo exits 1)", { skip: !PY }, () => {
  const r = spawnSync(process.execPath, [LAUNCHER, "attack", "--target", "demo:vulnerable", "--mode", "data-exfil", "--out", path.join(require("node:os").tmpdir(), "npm-launcher-test"), "--json"], {
    env: { ...process.env, MCP_CHAOS_PYTHON: PY }, encoding: "utf8",
  });
  assert.strictEqual(r.status, 1);
});

test("prints install guidance and exits 2 when nothing is available", () => {
  const r = spawnSync(process.execPath, [LAUNCHER, "--help"], {
    env: { PATH: "", MCP_CHAOS_PYTHON: "" }, encoding: "utf8",
  });
  assert.strictEqual(r.status, 2);
  assert.match(r.stderr, /pip install mcp-chaos/);
});
