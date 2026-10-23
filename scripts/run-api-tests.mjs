import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";

// Exercise the same Node.js runtime bundled with the desktop application.
const require = createRequire(import.meta.url);
const result = spawnSync(require("electron"), ["--test", "tests/api-regression.test.mjs"], {
  stdio: "inherit",
  env: { ...process.env, ELECTRON_RUN_AS_NODE: "1" }
});
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
