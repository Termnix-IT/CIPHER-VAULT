import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
const root = fs.mkdtempSync(path.join(fs.realpathSync(tmpdir()), "cv-mcp-desktop-"));
const profile = path.join(root, "desktop-profile"); fs.mkdirSync(profile);
const env = { ...process.env, CIPHER_VAULT_TEST_ROOT: root, CIPHER_VAULT_TEST_NODE: process.execPath }; delete env.ELECTRON_RUN_AS_NODE;
assert.ok(process.argv.length === 2 || (process.argv.length === 3 && process.argv[2] === "--codex"));
if (process.argv[2] === "--codex") env.CIPHER_VAULT_TEST_CODEX = "1";
try {
  const child = spawn(createRequire(import.meta.url)("electron"), ["tests/mcp-desktop.integration.mjs", `--user-data-dir=${profile}`], { env, stdio: "inherit", windowsHide: true });
  process.exitCode = await new Promise((resolve, reject) => { child.once("error", reject); child.once("close", code => resolve(code ?? 1)); });
} finally {
  assert.equal(path.dirname(root), fs.realpathSync(tmpdir())); assert.ok(path.basename(root).startsWith("cv-mcp-desktop-"));
  fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
