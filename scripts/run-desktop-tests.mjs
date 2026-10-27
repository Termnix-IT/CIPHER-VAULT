import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { spawn } from "node:child_process";

const mode = process.argv[2];
assert.ok(mode === undefined || mode === "--dev" || mode === "--web", "Unknown integration mode");

const temporaryRoot = mkdtempSync(path.join(tmpdir(), "cipher-vault-desktop-session-"));
let developmentServer;
try {
  if (mode === "--dev") {
    const webRequire = createRequire(new URL("../apps/web/package.json", import.meta.url));
    const { createServer } = await import(pathToFileURL(webRequire.resolve("vite")).href);
    developmentServer = await createServer({ root: path.resolve("apps/web"),
      configFile: path.resolve("apps/web/vite.config.ts"), server: { host: "127.0.0.1", port: 0, strictPort: false } });
    await developmentServer.listen();
  }
  const environment = { ...process.env, CIPHER_VAULT_TEST_ROOT: temporaryRoot };
  delete environment.ELECTRON_RUN_AS_NODE;
  if (developmentServer) environment.CIPHER_VAULT_TEST_RENDERER_URL = developmentServer.resolvedUrls.local[0];
  else delete environment.CIPHER_VAULT_TEST_RENDERER_URL;
  const child = spawn(createRequire(import.meta.url)("electron"), [mode === "--web" ? "tests/web-policy.integration.mjs" : "tests/desktop-session.integration.mjs"], {
    stdio: "inherit", windowsHide: true,
    env: environment
  });
  process.exitCode = await new Promise((resolve, reject) => {
    child.once("error", reject); child.once("close", (code) => resolve(code ?? 1));
  });
} finally {
  await developmentServer?.close();
  // Chromium can retain profile handles until AFTER app's quit event on Windows.
  const relative = path.relative(tmpdir(), temporaryRoot);
  assert.ok(relative.startsWith("cipher-vault-desktop-session-") && !relative.includes(path.sep));
  rmSync(temporaryRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
