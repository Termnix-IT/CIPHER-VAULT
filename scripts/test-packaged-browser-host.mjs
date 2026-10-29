import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { BROWSER_EXTENSION_ORIGIN } from "@password-manager/shared/browser-integration";
import { inspectDesktopPackage } from "./verify-desktop-package.mjs";
import { BrowserMessageDecoder, encodeBrowserMessage } from "../apps/electron/dist/apps/electron/src/browser-message.js";

assert.equal(process.argv.length, 3, "Expected an unpacked application directory (or .app)");
const source = inspectDesktopPackage(process.argv[2]), root = fs.mkdtempSync(path.join(fs.realpathSync(tmpdir()), "cv-packaged-browser-"));
const application = path.join(root, process.platform === "darwin" ? `${source.productName}.app` : "application"), configDirectory = path.join(root, "native-host");
let child;
try {
  fs.cpSync(source.root, application, { recursive: true, verbatimSymlinks: true }); inspectDesktopPackage(application);
  fs.mkdirSync(configDirectory, { mode: 0o700 });
  const resources = path.join(application, process.platform === "darwin" ? "Contents/Resources" : "resources"), binary = process.platform === "win32" ? "cipher-vault-native-host.exe" : "cipher-vault-native-host";
  const executable = path.join(application, process.platform === "darwin" ? `Contents/MacOS/${source.productName}` : process.platform === "win32" ? `${source.productName}.exe` : "cipher-vault");
  const launcher = path.join(configDirectory, binary); fs.copyFileSync(path.join(resources, "native-transport", binary), launcher); fs.chmodSync(launcher, 0o700);
  fs.writeFileSync(path.join(configDirectory, "host-config.json"), JSON.stringify({ version: 1, browser: "edge", extensionOrigin: BROWSER_EXTENSION_ORIGIN, applicationExecutable: fs.realpathSync(executable), applicationEntry: null }));
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  child = spawn(launcher, [BROWSER_EXTENSION_ORIGIN], { env, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  const chunks = [], errors = []; let bytes = 0;
  child.stdout.on("data", chunk => { bytes += chunk.length; if (bytes > 65540) child.kill(); else chunks.push(chunk); });
  child.stderr.on("data", chunk => { if (errors.length < 8) errors.push(chunk); }); child.stdin.on("error", () => {});
  const closed = new Promise((resolve, reject) => { child.once("error", reject); child.once("close", resolve); });
  const timer = setTimeout(() => child.kill(), 20000), id = randomUUID(); child.stdin.write(encodeBrowserMessage({ version: 1, id, operation: "get-state" }));
  const code = await closed; clearTimeout(timer);
  assert.equal(code, 0, Buffer.concat(errors).toString().replaceAll(root, "<temporary>"));
  assert.deepEqual(new BrowserMessageDecoder().push(Buffer.concat(chunks)), { version: 1, id, ok: true, result: { state: "unpaired", displayName: null, fingerprint256: null } });
  assert.equal(fs.existsSync(path.join(configDirectory, "client-profile/data")), false);
  console.log("PASS copied packaged native launcher and dedicated client entry without creating a Vault or credential");
} finally {
  if (child && child.exitCode === null && child.signalCode === null) child.kill();
  assert.ok(path.basename(root).startsWith("cv-packaged-browser-")); fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
