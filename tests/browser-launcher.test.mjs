import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { BROWSER_EXTENSION_ORIGIN } from "@password-manager/shared/browser-integration";
import { encodeBrowserMessage, BrowserMessageDecoder } from "../apps/electron/dist/apps/electron/src/browser-message.js";

test("launcher forwards only one validated public reply and rejects logs, private fields and trailing frames", { timeout: 30000 }, async () => {
  assert.equal(process.versions.electron, undefined, "Run this fake peer test with Node.js");
  const root = fs.mkdtempSync(path.join(fs.realpathSync(tmpdir()), "cv-launcher-wire-")); fs.chmodSync(root, 0o700);
  const binary = process.platform === "win32" ? "cipher-vault-native-host.exe" : "cipher-vault-native-host", launcher = path.join(root, binary), entry = path.join(root, "synthetic-peer.mjs");
  fs.copyFileSync(path.join("dist-desktop/native-transport", `${process.platform}-${process.arch}`, binary), launcher); fs.chmodSync(launcher, 0o700);
  fs.copyFileSync("tests/browser-launcher-peer.fixture.mjs", entry);
  fs.writeFileSync(path.join(root, "host-config.json"), JSON.stringify({ version: 1, browser: "chrome", extensionOrigin: BROWSER_EXTENSION_ORIGIN, applicationExecutable: fs.realpathSync(process.execPath), applicationEntry: entry }));
  async function run(mode, cancel) {
    const id = randomUUID(), chunks = [], errors = [];
    const child = spawn(launcher, [BROWSER_EXTENSION_ORIGIN], { stdio: ["pipe", "pipe", "pipe"], windowsHide: true, env: { ...process.env, CIPHER_VAULT_LAUNCHER_FIXTURE: mode } });
    child.stdout.on("data", chunk => chunks.push(chunk)); child.stderr.on("data", chunk => errors.push(chunk)); child.stdin.on("error", () => {});
    const closed = new Promise((resolve, reject) => { child.once("error", reject); child.once("close", resolve); });
    const timer = setTimeout(() => child.kill(), 6000);
    child.stdin.write(encodeBrowserMessage({ version: 1, id, operation: "get-state" }));
    if (cancel) {
      const marker = path.join(root, "synthetic-peer.pid");
      for (let i = 0; !fs.existsSync(marker) && i < 100; i++) await delay(20);
      assert.ok(fs.existsSync(marker)); const pid = Number(fs.readFileSync(marker, "utf8"));
      if (cancel === "EOF") child.stdin.end(); else child.stdin.write(encodeBrowserMessage({ version: 1, id: randomUUID(), operation: "get-state" }));
      const code = await closed; clearTimeout(timer); assert.equal(code, 70);
      let alive = true;
      for (let i = 0; i < 100 && alive; i++) { try { process.kill(pid, 0); await delay(20); } catch (cause) { if (cause.code === "ESRCH") alive = false; else throw cause; } }
      assert.equal(alive, false, "The owned child must exit on browser EOF or additional input"); fs.unlinkSync(marker);
    } else {
      const code = await closed; clearTimeout(timer); const output = Buffer.concat(chunks);
      if (mode === "valid" || (mode === "dev-crlf" && process.platform === "win32")) {
        assert.equal(code, 0); assert.equal(new BrowserMessageDecoder().push(output).id, id);
      } else { assert.equal(code, 70); assert.equal(output.length, 0); }
    }
    assert.equal(Buffer.concat(chunks).includes(Buffer.from("synthetic-private-canary")), false); assert.equal(Buffer.concat(errors).includes(Buffer.from("synthetic-private-canary")), false);
  }
  try {
    for (const mode of ["valid", "dev-crlf", "prefix", "private-field", "private-error", "wrong-id", "duplicate", "trailing"]) await run(mode);
    await run("wait", "EOF"); await run("wait", "duplicate");
  } finally { assert.ok(path.basename(root).startsWith("cv-launcher-wire-")); fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); }
});
