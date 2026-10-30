import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";

const mode = process.argv[2] ?? "--all";
assert.ok(process.argv.length <= 3 && ["--all", "--core", "--windows-release"].includes(mode), "Expected --all, --core or --windows-release");
if (mode !== "--core") assert.equal(process.platform, "win32", "Windows release tests require Windows; use test:core on other systems");

// The same Core contracts run in both supported server runtimes, without pwsh.
const core = ["tests/api-regression.test.mjs", "tests/crypto-compatibility.test.mjs", "tests/v2-codec.test.mjs",
  "tests/database-lifecycle.test.mjs", "tests/v2-store.test.mjs", "tests/migration-preflight.test.mjs",
  "tests/migration-staging.test.mjs", "tests/vault-activation.test.mjs", "tests/v2-runtime.test.mjs",
  "tests/v2-replacement.test.mjs", "tests/vault-maintenance.test.mjs", "tests/item-types.test.mjs", "tests/item-type-maintenance.test.mjs", "tests/web-release.test.mjs", "tests/api-test-runner.test.mjs"];
const runs = mode === "--windows-release" ? [] : [
  { runtime: "electron", files: core }, { runtime: "node", files: core }
];
if (mode !== "--core") runs.push({ runtime: "node", files: ["tests/windows-release.test.mjs"] });
const require = createRequire(import.meta.url);
for (const { runtime, files } of runs) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.toLowerCase() === "electron_run_as_node") delete env[key];
  if (runtime === "electron") env.ELECTRON_RUN_AS_NODE = "1";
  console.log(`Running ${files === core ? "Core" : "Windows release"} tests: ${runtime}, ${process.platform}/${process.arch}`);
  const result = spawnSync(runtime === "electron" ? require("electron") : process.execPath, ["--test", ...files], { stdio: "inherit", env, windowsHide: true });
  if (result.error) throw result.error;
  if (result.status !== 0) { process.exitCode = result.status ?? 1; break; }
}
