import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const readJson = (file) => JSON.parse(readFileSync(file, "utf8").replace(/^\uFEFF/, ""));
const writeJson = (file, value) => writeFileSync(file, JSON.stringify(value, null, 2) + "\n");

export function prepareReleaseManifests(root, destination) {
  const manifest = readJson(path.join(root, "package.json"));
  const api = readJson(path.join(root, "apps/api/package.json"));
  const shared = readJson(path.join(root, "packages/shared/package.json"));
  const lock = readJson(path.join(root, "package-lock.json"));
  assert.equal(lock.lockfileVersion, 3, "Web packaging requires the current v3 lockfile");
  assert.equal(lock.version, manifest.version, "Root version and lockfile differ");
  assert.deepEqual(lock.packages["apps/api"].dependencies, api.dependencies, "API dependencies and lockfile differ");
  assert.equal(lock.packages["packages/shared"].version, shared.version, "Shared version and lockfile differ");
  for (const field of ["dependencies", "optionalDependencies", "peerDependencies"]) {
    assert.deepEqual(lock.packages["packages/shared"][field], shared[field], `Shared ${field} and lockfile differ`);
  }
  assert.equal(shared.name, "@password-manager/shared");

  mkdirSync(path.join(destination, "packages/shared"), { recursive: true });
  writeJson(path.join(destination, "package.json"), {
    name: "password-manager-release", version: manifest.version, private: true, type: "module",
    engines: { node: ">=22" }, workspaces: ["packages/shared"],
    scripts: { start: "node start.mjs" }, dependencies: api.dependencies
  });
  // Ship only runtime workspace metadata; npm must not pull in its build tools.
  const { devDependencies, scripts, ...runtimeShared } = shared;
  writeJson(path.join(destination, "packages/shared/package.json"), runtimeShared);
  copyFileSync(path.join(root, "package-lock.json"), path.join(destination, "package-lock.json"));
}

export function verifyReleaseLock(root, destination) {
  const original = readJson(path.join(root, "package-lock.json"));
  const release = readJson(path.join(destination, "package-lock.json"));
  const manifest = readJson(path.join(destination, "package.json"));
  assert.equal(release.lockfileVersion, 3);
  assert.equal(release.version, manifest.version);
  assert.deepEqual(release.packages[""].dependencies, manifest.dependencies);
  assert.deepEqual(release.packages[""].workspaces, ["packages/shared"]);
  assert.deepEqual(release.packages["node_modules/@password-manager/shared"], { resolved: "packages/shared", link: true });
  const metadata = (item) => Object.fromEntries(Object.entries(item).filter(([key]) =>
    !["dev", "devOptional", "optional", "peer"].includes(key)));
  for (const [location, item] of Object.entries(release.packages)) {
    if (location === "" || location === "packages/shared" || location === "node_modules/@password-manager/shared") continue;
    assert.ok(location.startsWith("node_modules/") && !item.link && !item.dev && !item.devOptional,
      `Unexpected non-runtime package: ${location}`);
    assert.ok(item.integrity, `Missing locked integrity: ${location}`);
    assert.ok(original.packages[location], `Package absent from source lockfile: ${location}`);
    // npm resolves the graph. This only rejects changes to the audited descriptors.
    assert.deepEqual(metadata(item), metadata(original.packages[location]), `Locked package changed: ${location}`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const [mode, root, destination] = process.argv.slice(2);
  assert.ok(root && destination && (mode === "prepare" || mode === "verify"), "Expected prepare|verify <root> <destination>");
  if (mode === "prepare") prepareReleaseManifests(root, destination);
  else verifyReleaseLock(root, destination);
}
