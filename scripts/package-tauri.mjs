// Builds the Tauri app's Windows setup and portable exe into dist-tauri/, named as the Electron
// app's files are. Nothing is published. The version comes from the root package.json through
// apps/desktop/tauri.conf.json. With TAURI_SIGNING_PRIVATE_KEY (the key file's path) and
// TAURI_SIGNING_PRIVATE_KEY_PASSWORD set, it also signs the setup and writes latest.json, which
// the installed app reads from the latest GitHub release. --notes <file> puts that file's text in
// latest.json as the release notes the app shows. Run after npm run build:web:tauri.
// Usage: node scripts/package-tauri.mjs [--notes <file>]
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const OUTPUT = path.join(ROOT, "dist-tauri");
// Cargo resolves a relative CARGO_TARGET_DIR from where the build runs.
const DESKTOP = path.join(ROOT, "apps", "desktop");
const RELEASE = path.join(process.env.CARGO_TARGET_DIR ? path.resolve(DESKTOP, process.env.CARGO_TARGET_DIR) : path.join(ROOT, "target"), "release");
const { version } = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"));
const signing = Boolean(process.env.TAURI_SIGNING_PRIVATE_KEY);
const RELEASES = "https://github.com/Termnix-IT/CIPHER-VAULT/releases";
const notesAt = process.argv.indexOf("--notes");
const notes = notesAt === -1 ? "" : readFileSync(process.argv[notesAt + 1] ?? "", "utf8").trim();
if (notes && !signing) throw new Error("--notes goes into latest.json, which is only written for a signed build.");

const args = [path.join(ROOT, "node_modules", "@tauri-apps", "cli", "tauri.js"), "build", "--bundles", "nsis"];
let overlay = null;
if (signing) {
  overlay = path.join(tmpdir(), `cipher-vault-package-${process.pid}.json`);
  writeFileSync(overlay, JSON.stringify({ bundle: { createUpdaterArtifacts: true } }));
  args.push("--config", overlay);
}
const setup = path.join(RELEASE, "bundle", "nsis", `CIPHER VAULT_${version}_x64-setup.exe`);
// A setup left by an earlier build must never be taken for this one.
for (const file of [setup, `${setup}.sig`]) rmSync(file, { force: true });
const build = spawnSync(process.execPath, args, { cwd: DESKTOP, stdio: "inherit" });
if (overlay) rmSync(overlay, { force: true });
if (build.status !== 0) process.exit(build.status ?? 1);

assert.ok(existsSync(setup), `the ${version} setup was built`);
// The bundler marks only the copy inside the setup, so the built exe never updates itself.
const portable = path.join(RELEASE, "cipher-vault.exe");
assert.ok(readFileSync(portable).includes("__TAURI_BUNDLE_TYPE_VAR_UNK"), "the portable exe must not carry the setup's bundle type");

rmSync(OUTPUT, { recursive: true, force: true });
mkdirSync(OUTPUT);
const files = [[setup, `CIPHER-VAULT-${version}-x64-setup.exe`], [portable, `CIPHER-VAULT-${version}-x64-portable.exe`]];
if (signing) files.push([`${setup}.sig`, `CIPHER-VAULT-${version}-x64-setup.exe.sig`]);
for (const [from, name] of files) copyFileSync(from, path.join(OUTPUT, name));
const written = files.map(([, name]) => name);
if (signing) {
  // The release is tagged v<version>, and the setup is attached under the name above.
  const setupName = `CIPHER-VAULT-${version}-x64-setup.exe`;
  const manifest = {
    version, notes, pub_date: new Date().toISOString(),
    platforms: { "windows-x86_64": { signature: readFileSync(`${setup}.sig`, "utf8").trim(), url: `${RELEASES}/download/v${version}/${setupName}` } }
  };
  writeFileSync(path.join(OUTPUT, "latest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  written.push("latest.json");
}
console.log(written.map((name) => path.join("dist-tauri", name)).join("\n"));
