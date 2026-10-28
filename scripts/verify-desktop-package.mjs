import assert from "node:assert/strict";
import { existsSync, realpathSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";

const archiveApi = createRequire(createRequire(import.meta.url).resolve("app-builder-lib"))("@electron/asar");

export function inspectDesktopPackage(directory, platform = process.platform, arch = process.arch) {
  const root = realpathSync(directory), resources = path.join(root, platform === "darwin" ? "Contents/Resources" : "resources"), archive = path.join(resources, "app.asar");
  const files = archiveApi.listPackage(archive).map(file => file.replaceAll("\\", "/").replace(/^\/+/, ""));
  for (const file of files) assert.ok(!/^(?:tests|scripts|data|release|apps\/api\/data)(?:\/|$)/.test(file) &&
    !/(?:^|\/)\.env(?:\.|$)|\.(?:db|sqlite)(?:-(?:wal|shm|journal))?$|\.log$/i.test(file), "Unexpected private data or test tooling in package");
  const required = ["package.json", "apps/electron/dist/apps/electron/src/main.js", "apps/electron/dist/apps/electron/src/preload.cjs",
    "apps/api/dist/apps/api/src/services/vault-maintenance-service.js", "apps/api/dist/apps/api/src/db/sqlite-file-scope.js", "apps/web/dist/index.html",
    "node_modules/@password-manager/shared/package.json", "node_modules/@password-manager/shared/dist/index.js", "node_modules/@password-manager/shared/dist/renderer-policy.js"];
  for (const file of required) assert.ok(files.includes(file), `Missing packaged runtime file: ${file}`);
  assert.ok(files.some(file => file.startsWith("apps/web/dist/fonts/") && file.endsWith(".ttf")), "Missing local fonts");
  assert.ok(files.some(file => file.startsWith("apps/web/dist/fonts/") && /(?:OFL|LICENSE)/.test(file)), "Missing font license");
  const native = `node_modules/better-sqlite3/prebuilds/${platform}-${arch}.node`;
  assert.equal(archiveApi.statFile(archive, path.join(...native.split("/"))).unpacked, true, "SQLite binary must be unpacked");
  assert.ok(existsSync(path.join(resources, "app.asar.unpacked", native)), "Missing native SQLite binary");
  const metadata = JSON.parse(archiveApi.extractFile(archive, "package.json").toString("utf8"));
  assert.equal(metadata.productName, "CIPHER VAULT", "Unexpected packaged product identity");
  return Object.freeze({ root, archive, version: metadata.version, productName: metadata.productName, files });
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  assert.equal(process.argv.length, 3, "Expected an unpacked application directory (or .app)");
  const result = inspectDesktopPackage(process.argv[2]);
  console.log(`PASS packaged runtime, native SQLite, fonts and data exclusions (${result.version})`);
}
