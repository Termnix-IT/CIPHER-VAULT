import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";

// Exercise the same Node.js runtime bundled with the desktop application.
const require = createRequire(import.meta.url);
const result = spawnSync(require("electron"), ["--test", "tests/api-regression.test.mjs", "tests/crypto-compatibility.test.mjs", "tests/v2-codec.test.mjs", "tests/database-lifecycle.test.mjs", "tests/v2-store.test.mjs", "tests/migration-preflight.test.mjs", "tests/migration-staging.test.mjs", "tests/vault-activation.test.mjs", "tests/v2-runtime.test.mjs"], {
  stdio: "inherit",
  env: { ...process.env, ELECTRON_RUN_AS_NODE: "1" }
});
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
if (process.exitCode === 0) {
  // The standalone Web distribution uses the host's Node.js, without Electron.
  const release = spawnSync(process.execPath, ["--test", "tests/web-release.test.mjs", "tests/v2-codec.test.mjs", "tests/database-lifecycle.test.mjs", "tests/v2-store.test.mjs", "tests/migration-preflight.test.mjs", "tests/migration-staging.test.mjs", "tests/vault-activation.test.mjs", "tests/v2-runtime.test.mjs"], { stdio: "inherit" });
  if (release.error) throw release.error;
  process.exitCode = release.status ?? 1;
}
