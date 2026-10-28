import assert from "node:assert/strict";
import path from "node:path";
import { pathToFileURL } from "node:url";

export function requireNativeDesktopBuild(target, platform = process.platform, arch = process.arch) {
  assert.ok(target === "linux" || target === "mac", "Expected linux or mac");
  assert.equal(platform, target === "linux" ? "linux" : "darwin", `Build ${target} packages on its native OS`);
  assert.ok(arch === "x64" || arch === "arm64", "Desktop package evaluation requires x64 or arm64");
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  assert.equal(process.argv.length, 3, "Expected one native target");
  requireNativeDesktopBuild(process.argv[2]);
}
