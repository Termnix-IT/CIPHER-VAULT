import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";

const native = process.argv.length === 3 && process.argv[2] === "--native";
assert.ok(process.argv.length === 2 || native, "Expected no arguments or --native");
const files = native ? ["tests/native-transport.test.mjs", "tests/local-client-auth.test.mjs", "tests/local-client-store.test.mjs", "tests/local-client-registry.test.mjs", "tests/local-identity.test.mjs", "tests/protected-local-identity.test.mjs", "tests/local-pairing.test.mjs", "tests/local-connections.test.mjs", "tests/browser-client.test.mjs"] : ["tests/local-endpoint.test.mjs"];
const require = createRequire(import.meta.url);
for (const runtime of ["node", "electron"]) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.toLowerCase() === "electron_run_as_node") delete env[key];
  if (runtime === "electron") env.ELECTRON_RUN_AS_NODE = "1";
  console.log(`Native local endpoint probe: ${runtime}, ${process.platform}/${process.arch}`);
  const result = spawnSync(runtime === "electron" ? require("electron") : process.execPath, ["--test", ...files], { env, stdio: "inherit", windowsHide: true });
  if (result.error) throw result.error;
  if (result.status !== 0) { process.exitCode = result.status ?? 1; break; }
}
