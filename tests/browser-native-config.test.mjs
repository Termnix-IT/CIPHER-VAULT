import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { BROWSER_EXTENSION_KEY, BROWSER_EXTENSION_ID, BROWSER_EXTENSION_ORIGIN } from "@password-manager/shared/browser-integration";
import { readBrowserNativeConfig } from "../apps/electron/dist/apps/electron/src/browser-native-config.js";
const root = fileURLToPath(new URL("../", import.meta.url));

test("public development extension key determines the exact allowed origin", () => {
  const id = [...createHash("sha256").update(Buffer.from(BROWSER_EXTENSION_KEY, "base64")).digest().subarray(0, 16)]
    .flatMap(value => [value >> 4, value & 15]).map(value => String.fromCharCode(97 + value)).join("");
  assert.equal(id, BROWSER_EXTENSION_ID); assert.equal(BROWSER_EXTENSION_ORIGIN, `chrome-extension://${id}/`);
});
test("native host configuration is bounded, exact and cannot select arbitrary profiles", () => {
  const directory = fs.mkdtempSync(path.join(fs.realpathSync(tmpdir()), "cv-browser-config-")); fs.chmodSync(directory, 0o700);
  try {
    const file = path.join(directory, "host-config.json"), config = { version: 1, browser: "chrome", extensionOrigin: BROWSER_EXTENSION_ORIGIN,
      applicationExecutable: fs.realpathSync(process.execPath), applicationEntry: fs.realpathSync(path.join(root, "apps/electron/dist/apps/electron/src/main.js")) };
    fs.writeFileSync(file, JSON.stringify(config)); assert.deepEqual(readBrowserNativeConfig(file), { config, profile: path.join(directory, "client-profile") });
    for (const patch of [{ version: 2 }, { browser: "unknown" }, { extensionOrigin: "chrome-extension://" + "a".repeat(32) + "/" }, { profile: "synthetic-path" },
      { applicationExecutable: "relative.exe" }, { applicationEntry: false }]) { fs.writeFileSync(file, JSON.stringify({ ...config, ...patch })); assert.throws(() => readBrowserNativeConfig(file)); }
    fs.writeFileSync(file, Buffer.alloc(16385)); assert.throws(() => readBrowserNativeConfig(file));
  } finally { assert.ok(path.basename(directory).startsWith("cv-browser-config-")); fs.rmSync(directory, { recursive: true, force: true }); }
});
test("native launcher refuses invalid origin, arguments and config without emitting protocol data", () => {
  const directory = fs.mkdtempSync(path.join(fs.realpathSync(tmpdir()), "cv-browser-launcher-")); fs.chmodSync(directory, 0o700);
  try {
    const binary = process.platform === "win32" ? "cipher-vault-native-host.exe" : "cipher-vault-native-host", launcher = path.join(directory, binary);
    fs.copyFileSync(path.join(root, "dist-desktop/native-transport", `${process.platform}-${process.arch}`, binary), launcher); fs.chmodSync(launcher, 0o700);
    for (const args of [[], ["https://example.invalid/"], [BROWSER_EXTENSION_ORIGIN, "--inject"], [BROWSER_EXTENSION_ORIGIN],
      [BROWSER_EXTENSION_ORIGIN, "--parent-window=-1"], [BROWSER_EXTENSION_ORIGIN, "--parent-window=0", "extra"]]) {
      const result = spawnSync(launcher, args, { encoding: "utf8", timeout: 5000, windowsHide: true });
      assert.equal(result.status, 70); assert.equal(result.stdout, ""); assert.equal(result.stderr.trim(), "BROWSER_CONNECTION_UNAVAILABLE");
    }
    fs.writeFileSync(path.join(directory, "host-config.json"), JSON.stringify({ extra: "synthetic-private-canary" }));
    const result = spawnSync(launcher, [BROWSER_EXTENSION_ORIGIN], { encoding: "utf8", timeout: 5000, windowsHide: true });
    assert.equal(result.status, 70); assert.equal(result.stdout, ""); assert.equal(result.stderr.includes("synthetic-private-canary"), false);
  } finally { assert.ok(path.basename(directory).startsWith("cv-browser-launcher-")); fs.rmSync(directory, { recursive: true, force: true }); }
});
