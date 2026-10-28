import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// Exercise the real CLI with synthetic executable resolution and child-process
// boundaries. No test is started; only file arguments and runtime mode are recorded.
function run(mode, { platform = "win32", failAt = -1, signalled = false } = {}) {
  const directory = mkdtempSync(path.join(tmpdir(), "cipher-vault-test-runner-"));
  try {
    const record = path.join(directory, "calls.json"), hook = path.join(directory, "hook.cjs");
    writeFileSync(hook, `
const fs = require('node:fs'), child = require('node:child_process');
const Module = require('node:module'), load = Module._load;
Module._load = function(name, ...args) { return name === 'electron' ? ${JSON.stringify(path.join(directory, "synthetic-electron"))} : load.call(this, name, ...args); };
const calls = [], record = ${JSON.stringify(record)};
Object.defineProperty(process, 'platform', { value: ${JSON.stringify(platform)} });
child.spawnSync = (command, args, options) => {
  calls.push({ args, electronNode: options.env.ELECTRON_RUN_AS_NODE ?? null });
  fs.writeFileSync(record, JSON.stringify(calls));
  return calls.length === ${failAt + 1} ? { status: ${signalled ? "null" : "23"}, signal: ${signalled ? "'SIGTERM'" : "null"} } : { status: 0 };
};
require('node:module').syncBuiltinESMExports();
`);
    const result = spawnSync(process.execPath, ["--require", hook, fileURLToPath(new URL("../scripts/run-api-tests.mjs", import.meta.url)), ...mode], {
      encoding: "utf8", windowsHide: true, timeout: 15000, env: { ...process.env, ELECTRON_RUN_AS_NODE: "1" }
    });
    if (result.error) throw result.error;
    let calls = [];
    try { calls = JSON.parse(readFileSync(record, "utf8")); } catch (error) { if (error.code !== "ENOENT") throw error; }
    return { ...result, calls };
  } finally {
    assert.equal(path.dirname(directory), path.resolve(tmpdir()));
    assert.ok(path.basename(directory).startsWith("cipher-vault-test-runner-"));
    rmSync(directory, { recursive: true, force: true });
  }
}

test("Core CLI uses identical files for both runtimes on every OS and excludes Windows release tests", () => {
  for (const platform of ["win32", "linux", "darwin"]) {
    const result = run(["--core"], { platform });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.calls.length, 2);
    assert.deepEqual(result.calls.map(call => call.electronNode), ["1", null]);
    assert.deepEqual(result.calls[0].args, result.calls[1].args);
    assert.ok(result.calls[0].args.includes("tests/api-regression.test.mjs"));
    assert.ok(result.calls[0].args.includes("tests/crypto-compatibility.test.mjs"));
    assert.ok(!result.calls[0].args.includes("tests/windows-release.test.mjs"));
  }
});

test("default API CLI retains Windows release coverage and the dedicated release CLI selects only it", () => {
  const complete = run([]);
  assert.equal(complete.status, 0, complete.stderr); assert.equal(complete.calls.length, 3);
  assert.deepEqual(complete.calls[2], { args: ["--test", "tests/windows-release.test.mjs"], electronNode: null });
  const release = run(["--windows-release"]);
  assert.equal(release.status, 0, release.stderr); assert.deepEqual(release.calls, [complete.calls[2]]);
});

test("failed or signalled stages stop later runtime and release stages and preserve a nonzero exit", () => {
  for (const failAt of [0, 1, 2]) {
    const result = run([], { failAt });
    assert.equal(result.status, 23); assert.equal(result.calls.length, failAt + 1);
  }
  const result = run([], { failAt: 0, signalled: true });
  assert.equal(result.status, 1); assert.equal(result.calls.length, 1);
});

test("unknown arguments and Windows-only modes on other OSes fail before spawning any tests", () => {
  for (const mode of [["--unknown"], ["--core", "extra"]]) {
    const result = run(mode); assert.notEqual(result.status, 0); assert.deepEqual(result.calls, []);
  }
  for (const platform of ["linux", "darwin"]) for (const mode of [[], ["--windows-release"]]) {
    const result = run(mode, { platform });
    assert.notEqual(result.status, 0); assert.match(result.stderr, /use test:core/); assert.deepEqual(result.calls, []);
  }
});
