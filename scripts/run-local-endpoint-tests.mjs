import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";

assert.equal(process.argv.length, 2, "Local endpoint tests accept no arguments");
const require = createRequire(import.meta.url);
for (const runtime of ["node", "electron"]) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.toLowerCase() === "electron_run_as_node") delete env[key];
  if (runtime === "electron") env.ELECTRON_RUN_AS_NODE = "1";
  console.log(`Native local endpoint probe: ${runtime}, ${process.platform}/${process.arch}`);
  const result = spawnSync(runtime === "electron" ? require("electron") : process.execPath, ["--test", "tests/local-endpoint.test.mjs"], { env, stdio: "inherit", windowsHide: true });
  if (result.error) throw result.error;
  if (result.status !== 0) { process.exitCode = result.status ?? 1; break; }
}
