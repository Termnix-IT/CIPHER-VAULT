import assert from "node:assert/strict";
import { after, test } from "node:test";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { verifyReleaseLock } from "../scripts/web-release-manifest.mjs";

assert.equal(process.platform, "win32", "Windows release tests require Windows; use test:core on other systems");
const temporaryRoot = mkdtempSync(path.join(tmpdir(), "cipher-vault-windows-release-"));
after(() => {
  const relative = path.relative(tmpdir(), temporaryRoot);
  assert.ok(relative.startsWith("cipher-vault-windows-release-") && !relative.includes(path.sep));
  rmSync(temporaryRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

test("Web packaging excludes development DB and preserves existing release data", () => {
  const fixture = path.join(temporaryRoot, "package");
  for (const directory of ["scripts", "apps/api/dist", "apps/web/dist", "apps/api/data", "packages/shared/dist"]) {
    mkdirSync(path.join(fixture, directory), { recursive: true });
  }
  for (const file of ["scripts/package-release.ps1", "scripts/web-release-manifest.mjs", "scripts/start-web-release.mjs",
    "package.json", "package-lock.json", "apps/api/package.json", "packages/shared/package.json"]) {
    cpSync(new URL(`../${file}`, import.meta.url), path.join(fixture, file));
  }
  writeFileSync(path.join(fixture, "packages/shared/dist/index.js"), "export const fixture = true;");
  writeFileSync(path.join(fixture, "apps/api/data/password-manager.db"), "development sentinel");
  const run = () => spawnSync("pwsh", ["-NoProfile", "-File", path.join(fixture, "scripts/package-release.ps1")], {
    cwd: temporaryRoot, encoding: "utf8", env: { ...process.env, npm_config_cache: path.join(fixture, "empty-npm-cache") }
  });
  const first = run();
  assert.equal(first.status, 0, first.stdout + first.stderr);
  assert.deepEqual(readdirSync(path.join(fixture, "release/data")), []);
  const releaseManifest = JSON.parse(readFileSync(path.join(fixture, "release/package.json"), "utf8").replace(/^\uFEFF/, ""));
  assert.ok(releaseManifest.dependencies["@zxcvbn-ts/core"]);
  assert.ok(releaseManifest.dependencies["@zxcvbn-ts/language-common"]);
  assert.ok(releaseManifest.dependencies["@zxcvbn-ts/language-en"]);
  assert.deepEqual(releaseManifest.workspaces, ["packages/shared"]);
  assert.equal(readFileSync(path.join(fixture, "release/packages/shared/dist/index.js"), "utf8"), "export const fixture = true;");
  verifyReleaseLock(fixture, path.join(fixture, "release"));
  const lockPath = path.join(fixture, "release/package-lock.json");
  const lockBytes = readFileSync(lockPath);
  assert.equal(run().status, 0, "a second clean package generation should succeed");
  assert.deepEqual(readFileSync(lockPath), lockBytes, "packaging must preserve deterministic locked resolutions");
  const changedLock = JSON.parse(lockBytes);
  changedLock.packages["node_modules/better-sqlite3"].integrity = "sha512-untrusted-fixture";
  writeFileSync(lockPath, JSON.stringify(changedLock));
  assert.throws(() => verifyReleaseLock(fixture, path.join(fixture, "release")), /Locked package changed/);
  changedLock.packages["node_modules/better-sqlite3"].dev = true;
  writeFileSync(lockPath, JSON.stringify(changedLock));
  assert.throws(() => verifyReleaseLock(fixture, path.join(fixture, "release")), /Unexpected non-runtime/);
  writeFileSync(lockPath, lockBytes);

  const apiPath = path.join(fixture, "apps/api/package.json");
  const apiBytes = readFileSync(apiPath);
  const changedApi = JSON.parse(apiBytes);
  changedApi.dependencies["better-sqlite3"] = "999.0.0";
  writeFileSync(apiPath, JSON.stringify(changedApi));
  assert.notEqual(run().status, 0);
  assert.deepEqual(readFileSync(lockPath), lockBytes, "failed preparation must preserve the previous release");
  writeFileSync(apiPath, apiBytes);
  const protectedDatabase = path.join(fixture, "release/data/password-manager.db");
  writeFileSync(protectedDatabase, "existing user data sentinel");
  assert.notEqual(run().status, 0);
  assert.equal(readFileSync(protectedDatabase, "utf8"), "existing user data sentinel");
});

test("an isolated Web release installs locked dependencies and runs the real API and SQLite", { timeout: 120000 }, async () => {
  const fixture = mkdtempSync(path.join(tmpdir(), "cipher-vault-release-integration-"));
  let child;
  let output = "";
  const stop = async () => {
    if (child && child.exitCode === null && child.signalCode === null) {
      const closed = once(child, "close"); child.kill(); await closed;
    }
    child = undefined;
  };
  try {
    const source = path.join(fixture, "source");
    for (const directory of ["scripts", "apps/api", "apps/web/dist", "packages/shared"]) mkdirSync(path.join(source, directory), { recursive: true });
    for (const file of ["scripts/package-release.ps1", "scripts/web-release-manifest.mjs", "scripts/start-web-release.mjs",
      "package.json", "package-lock.json", "apps/api/package.json", "packages/shared/package.json"]) {
      cpSync(new URL(`../${file}`, import.meta.url), path.join(source, file));
    }
    for (const directory of ["apps/api/dist", "packages/shared/dist"]) cpSync(new URL(`../${directory}/`, import.meta.url), path.join(source, directory), { recursive: true });
    writeFileSync(path.join(source, "apps/web/dist/index.html"), "<!doctype html><title>Isolated release fixture</title>");
    const packaged = spawnSync("pwsh", ["-NoProfile", "-File", path.join(source, "scripts/package-release.ps1")], { encoding: "utf8", timeout: 30000 });
    assert.equal(packaged.status, 0, packaged.stdout + packaged.stderr);
    const release = path.join(fixture, "clean install 日本語");
    cpSync(path.join(source, "release"), release, { recursive: true });
    assert.deepEqual(readdirSync(path.join(release, "data")), []);
    const lockPath = path.join(release, "package-lock.json");
    const lockedBytes = readFileSync(lockPath);
    const lock = JSON.parse(lockedBytes);
    const env = { ...process.env };
    for (const key of Object.keys(env)) {
      if (["electron_run_as_node", "node_path", "password_manager_data_dir", "password_manager_web_dist", "password_manager_web_origin"].includes(key.toLowerCase())) delete env[key];
    }
    const available = createServer();
    await new Promise(resolve => available.listen(0, "127.0.0.1", resolve));
    const port = available.address().port;
    await new Promise(resolve => available.close(resolve));
    const origin = `http://127.0.0.1:${port}`;
    env.PASSWORD_MANAGER_API_HOST = "127.0.0.1";
    env.PASSWORD_MANAGER_API_PORT = String(port);
    const launch = async () => {
      output = "";
      child = spawn(process.env.npm_node_execpath ?? "node", [path.join(release, "start.mjs")], { cwd: fixture, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
      child.stdout.on("data", bytes => { output += bytes; });
      child.stderr.on("data", bytes => { output += bytes; });
      let error;
      child.on("error", value => { error = value; });
      for (let attempt = 0; attempt < 600; attempt++) {
        if (error) throw error;
        assert.ok(child.exitCode === null && child.signalCode === null, output);
        try { const response = await fetch(origin + "/vault/status"); if (response.ok) return response.json(); } catch {}
        await delay(100);
      }
      throw new Error("Release server did not start: " + output);
    };
    const request = async (pathname, method = "GET", body) => {
      const { token } = await (await fetch(origin + "/vault/csrf")).json();
      const status = await (await fetch(origin + "/vault/status")).json();
      return fetch(origin + pathname, { method, headers: { Origin: origin, "Content-Type": "application/json",
        "X-Cipher-Vault-CSRF": token, "X-Cipher-Vault-Session": status.sessionId }, body: body === undefined ? undefined : JSON.stringify(body) });
    };
    assert.equal((await launch()).isConfigured, false);
    assert.match(output, /Installing locked runtime dependencies/);
    const installed = readFileSync(path.join(release, "node_modules/.cipher-vault-runtime"), "utf8");
    assert.equal(installed.length, 64);
    assert.deepEqual(readFileSync(lockPath), lockedBytes, "npm ci must not rewrite the packaged lockfile");
    for (const [location, item] of Object.entries(lock.packages)) {
      if (location.startsWith("node_modules/") && !item.link) {
        assert.equal(JSON.parse(readFileSync(path.join(release, location, "package.json"), "utf8")).version, item.version, location);
        assert.ok(!item.dev);
      }
    }
    const html = await fetch(origin);
    assert.match(html.headers.get("content-security-policy"), /default-src 'none'/);
    assert.match(await html.text(), /Isolated release fixture/);
    assert.equal((await request("/vault/setup", "POST", { masterPassword: "release-fixture-master-password" })).status, 201);
    const payload = { serviceName: "Release fixture", loginId: "synthetic-user", password: "synthetic-entry-password", notes: "synthetic note" };
    const created = await request("/entries", "POST", payload);
    assert.equal(created.status, 201);
    const entry = await created.json();
    assert.equal((await (await request(`/entries/${entry.id}`)).json()).password, payload.password);
    const listing = await (await request("/entries")).json();
    assert.equal(listing.items.length, 1);
    assert.ok(!JSON.stringify(listing).includes(payload.password));
    assert.equal((await request(`/entries/${entry.id}`, "PUT", { ...payload, loginId: "updated-fixture" })).status, 200);
    assert.equal((await request("/vault/audit", "POST")).status, 200);
    assert.equal((await request("/vault/lock", "POST")).status, 200);
    assert.equal((await request(`/entries/${entry.id}`)).status, 423);
    assert.equal((await request("/vault/unlock", "POST", { masterPassword: "release-fixture-master-password" })).status, 200);
    await stop();
    const restarted = await launch();
    assert.ok(restarted.isConfigured && !restarted.isUnlocked);
    assert.ok(!output.includes("Installing locked runtime dependencies"));
    assert.equal(readFileSync(path.join(release, "node_modules/.cipher-vault-runtime"), "utf8"), installed);
    assert.equal((await request("/vault/unlock", "POST", { masterPassword: "release-fixture-master-password" })).status, 200);
    assert.equal((await (await request(`/entries/${entry.id}`)).json()).loginId, "updated-fixture");
    assert.equal((await request(`/entries/${entry.id}`, "DELETE")).status, 200);
    await stop();

    const manifestPath = path.join(release, "package.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    manifest.dependencies["better-sqlite3"] = "13.0.2";
    writeFileSync(manifestPath, JSON.stringify(manifest));
    const failed = spawnSync(process.env.npm_node_execpath ?? "node", [path.join(release, "start.mjs")], {
      cwd: fixture, env, encoding: "utf8", timeout: 30000
    });
    assert.notEqual(failed.status, 0, "npm ci must reject a manifest/lock mismatch");
    assert.match(failed.stdout + failed.stderr, /Invalid: lock file|in sync|EUSAGE/);
    assert.deepEqual(readFileSync(lockPath), lockedBytes);
    assert.ok(existsSync(path.join(release, "data/password-manager.db")));
  } finally {
    await stop();
    assert.equal(path.dirname(fixture), path.resolve(tmpdir()));
    assert.ok(path.basename(fixture).startsWith("cipher-vault-release-integration-"));
    rmSync(fixture, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
});
