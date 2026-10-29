import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

assert.ok(process.platform === "linux" || process.platform === "darwin", "Archive tests require native Linux or macOS");
assert.ok(process.argv.length <= 3, "Expected an optional artifact output directory");
const project = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const platform = process.platform === "darwin" ? "macos" : "linux";
const output = path.resolve(process.argv[2] ?? `dist-desktop/${platform}`), prefix = `CIPHER-VAULT-${project.version}-${platform}-${process.arch}`;
const temporary = mkdtempSync(path.join(realpathSync(tmpdir()), "cipher-vault-artifacts-")); let mounted = false;
const smokeScript = fileURLToPath(new URL("./test-packaged-desktop.mjs", import.meta.url));
function run(command, args, cwd = temporary) {
  const result = spawnSync(command, args, { cwd, env: process.env, encoding: "utf8", timeout: 180000, maxBuffer: 16 * 1024 * 1024, windowsHide: true });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, result.stderr + result.stdout);
  return result.stdout;
}
function bundle(root, depth = 0) {
  if (existsSync(path.join(root, process.platform === "darwin" ? "Contents/Resources/app.asar" : "resources/app.asar"))) return [root];
  if (depth === 3) return [];
  return readdirSync(root, { withFileTypes: true }).filter(entry => entry.isDirectory()).flatMap(entry => bundle(path.join(root, entry.name), depth + 1));
}
function smoke(root, appDir = false) {
  const matches = bundle(root); assert.equal(matches.length, 1, "Expected exactly one packaged app in artifact");
  if (process.platform === "darwin") run("codesign", ["--verify", "--deep", "--strict", matches[0]]);
  const result = run(process.execPath, [smokeScript, ...(appDir ? ["--appdir"] : []), matches[0]]);
  assert.match(result, /PASS packaged restart/);
}
try {
  if (process.platform === "linux") {
    const tar = path.join(output, prefix + ".tar.gz");
    const imageArch = process.arch === "x64" ? "x86_64" : process.arch;
    const image = path.join(output, `CIPHER-VAULT-${project.version}-linux-${imageArch}.AppImage`);
    assert.ok(existsSync(tar) && existsSync(image), "Build both Linux artifact formats first");
    const names = run("tar", ["-tzf", tar]).trim().split("\n");
    assert.ok(names.every(name => !path.isAbsolute(name) && !name.split(/[\\/]/).includes("..")), "Unexpected archive path");
    const extracted = path.join(temporary, "tar"); mkdirSync(extracted); run("tar", ["-xzf", tar, "-C", extracted]); smoke(extracted);
    console.log("PASS tar.gz artifact starts outside the checkout with a disposable vault");
    const imageDirectory = path.join(temporary, "appimage"); mkdirSync(imageDirectory); run(image, ["--appimage-extract"], imageDirectory);
    const appDir = path.join(imageDirectory, "squashfs-root");
    const desktop = readdirSync(appDir).filter(file => file.endsWith(".desktop")); assert.equal(desktop.length, 1);
    assert.ok(!readFileSync(path.join(appDir, desktop[0]), "utf8").includes("--no-sandbox"), "AppImage launcher must preserve sandboxing");
    smoke(appDir, true); console.log("PASS extracted AppImage AppRun preserves sandbox, data and restart behavior");
  } else {
    const zip = path.join(output, prefix + ".zip"), dmg = path.join(output, prefix + ".dmg");
    assert.ok(existsSync(zip) && existsSync(dmg), "Build both macOS artifact formats first");
    const extracted = path.join(temporary, "zip"); mkdirSync(extracted); run("ditto", ["-x", "-k", zip, extracted]); smoke(extracted);
    console.log("PASS zip artifact has a valid local signature and starts with a disposable vault");
    const mount = path.join(temporary, "mounted"); mkdirSync(mount);
    run("hdiutil", ["attach", dmg, "-readonly", "-nobrowse", "-mountpoint", mount]); mounted = true;
    smoke(mount); run("hdiutil", ["detach", mount]); mounted = false;
    console.log("PASS read-only dmg artifact retains the signed app and restart behavior");
  }
} finally {
  if (mounted) { run("hdiutil", ["detach", path.join(temporary, "mounted")]); mounted = false; }
  assert.equal(path.dirname(temporary), realpathSync(tmpdir())); assert.ok(path.basename(temporary).startsWith("cipher-vault-artifacts-"));
  rmSync(temporary, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
