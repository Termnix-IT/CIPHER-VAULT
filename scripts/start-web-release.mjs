import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = fileURLToPath(new URL(".", import.meta.url));
process.chdir(root);
if (Number(process.versions.node.split(".")[0]) < 22) throw new Error("Node.js 22 or newer is required.");

// Record success only after npm ci finishes. Changes and interrupted installs retry.
const fingerprint = createHash("sha256")
  .update(readFileSync(path.join(root, "package.json")))
  .update(readFileSync(path.join(root, "package-lock.json")))
  .update(readFileSync(path.join(root, "packages/shared/package.json")))
  .update(JSON.stringify([process.versions.modules, process.platform, process.arch]))
  .digest("hex");
const marker = path.join(root, "node_modules/.cipher-vault-runtime");
let installed;
try { installed = readFileSync(marker, "utf8"); } catch (error) { if (error.code !== "ENOENT") throw error; }
if (installed !== fingerprint) {
  console.log("Installing locked runtime dependencies...");
  const command = process.platform === "win32" ? (process.env.ComSpec ?? "cmd.exe") : "npm";
  // The Windows command is fixed; paths and user input never enter shell text.
  const args = process.platform === "win32"
    ? ["/d", "/s", "/c", "npm ci --omit=dev --no-audit --no-fund"]
    : ["ci", "--omit=dev", "--no-audit", "--no-fund"];
  const result = spawnSync(command, args, { cwd: root, stdio: "inherit", windowsHide: true });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
  writeFileSync(marker, fingerprint);
}
await import("./dist/apps/api/src/server.js");
