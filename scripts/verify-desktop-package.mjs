import assert from "node:assert/strict";
import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";

const archiveApi = createRequire(createRequire(import.meta.url).resolve("app-builder-lib"))("@electron/asar");

export function inspectDesktopPackage(directory, platform = process.platform, arch = process.arch) {
  const root = realpathSync(directory), resources = path.join(root, platform === "darwin" ? "Contents/Resources" : "resources"), archive = path.join(resources, "app.asar");
  const files = archiveApi.listPackage(archive).map(file => file.replaceAll("\\", "/").replace(/^\/+/, ""));
  for (const file of files) assert.ok(!/^(?:tests|scripts|native|data|release|apps\/api\/data)(?:\/|$)/.test(file) &&
    !/(?:^|\/)\.env(?:\.|$)|\.(?:db|sqlite)(?:-(?:wal|shm|journal))?$|\.log$/i.test(file), "Unexpected private data or test tooling in package");
  const required = ["package.json", "apps/electron/dist/apps/electron/src/main.js", "apps/electron/dist/apps/electron/src/preload.cjs",
    "apps/api/dist/apps/api/src/services/vault-maintenance-service.js", "apps/api/dist/apps/api/src/db/sqlite-file-scope.js", "apps/web/dist/index.html",
    "node_modules/@password-manager/shared/package.json", "node_modules/@password-manager/shared/dist/index.js", "node_modules/@password-manager/shared/dist/renderer-policy.js",
    "apps/electron/dist/apps/electron/src/native-transport.js", "apps/electron/dist/apps/electron/src/local-client-auth.js"];
  for (const file of required) assert.ok(files.includes(file), `Missing packaged runtime file: ${file}`);
  assert.ok(files.some(file => file.startsWith("apps/web/dist/fonts/") && file.endsWith(".ttf")), "Missing local fonts");
  assert.ok(files.some(file => file.startsWith("apps/web/dist/fonts/") && /(?:OFL|LICENSE)/.test(file)), "Missing font license");
  const native = `node_modules/better-sqlite3/prebuilds/${platform}-${arch}.node`;
  assert.equal(archiveApi.statFile(archive, path.join(...native.split("/"))).unpacked, true, "SQLite binary must be unpacked");
  assert.ok(existsSync(path.join(resources, "app.asar.unpacked", native)), "Missing native SQLite binary");
  const metadata = JSON.parse(archiveApi.extractFile(archive, "package.json").toString("utf8"));
  assert.equal(metadata.productName, "CIPHER VAULT", "Unexpected packaged product identity");
  const helperDirectory = path.join(resources, "native-transport"), binary = platform === "win32" ? "cipher-vault-transport.exe" : "cipher-vault-transport";
  assert.ok(lstatSync(helperDirectory).isDirectory() && !lstatSync(helperDirectory).isSymbolicLink(), "Native transport directory must not be a link");
  assert.deepEqual(readdirSync(helperDirectory).sort(), [binary, "native-transport.json", "LICENSE.TXT", "THIRD-PARTY-NOTICES.TXT"].sort(), "Unexpected native transport package contents");
  for (const file of readdirSync(helperDirectory)) assert.ok(lstatSync(path.join(helperDirectory, file)).isFile(), "Native transport files must be regular files");
  const helper = JSON.parse(readFileSync(path.join(helperDirectory, "native-transport.json"), "utf8"));
  assert.deepEqual(Object.keys(helper).sort(), ["arch", "buildSha256", "platform", "protocol", "runtimeVersion", "version"]);
  assert.equal(helper.protocol, 1); assert.equal(helper.platform, platform, "Wrong native helper OS"); assert.equal(helper.arch, arch, "Wrong native helper architecture");
  assert.equal(helper.version, metadata.version, "Wrong native helper version"); assert.match(helper.buildSha256, /^[a-f0-9]{64}$/, "Missing native build digest");
  assert.match(helper.runtimeVersion, /^[0-9]+\.[0-9]+\.[0-9]+$/);
  for (const file of ["LICENSE.TXT", "THIRD-PARTY-NOTICES.TXT"]) assert.ok(readFileSync(path.join(helperDirectory, file)).length > 0, "Missing native runtime license");
  return Object.freeze({ root, archive, version: metadata.version, productName: metadata.productName, files, nativeHelper: path.join(helperDirectory, binary) });
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  assert.equal(process.argv.length, 3, "Expected an unpacked application directory (or .app)");
  const result = inspectDesktopPackage(process.argv[2]);
  console.log(`PASS packaged runtime, native SQLite, fonts and data exclusions (${result.version})`);
}
