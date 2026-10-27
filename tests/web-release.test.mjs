import assert from "node:assert/strict";
import { test } from "node:test";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";

test("release startup retries failed installs, pins npm ci and reinstalls changed manifests", () => {
  const fixture = mkdtempSync(path.join(tmpdir(), "cipher-vault-release-start-"));
  try {
    for (const directory of ["fake npm", "dist/apps/api/src", "packages/shared"]) mkdirSync(path.join(fixture, directory), { recursive: true });
    cpSync(new URL("../scripts/start-web-release.mjs", import.meta.url), path.join(fixture, "start.mjs"));
    writeFileSync(path.join(fixture, "package.json"), '{"type":"module"}');
    writeFileSync(path.join(fixture, "package-lock.json"), '{}');
    writeFileSync(path.join(fixture, "packages/shared/package.json"), '{}');
    writeFileSync(path.join(fixture, "dist/apps/api/src/server.js"),
      'import { appendFileSync } from "node:fs"; appendFileSync("server-starts", "started\\n");');
    const bin = path.join(fixture, "fake npm");
    const stub = process.platform === "win32" ? "npm.cmd" : "npm";
    writeFileSync(path.join(bin, stub), process.platform === "win32" ?
      '@echo off\r\necho %*>>npm-calls\r\nif not exist node_modules mkdir node_modules\r\nif exist fail-install exit /b 23\r\nexit /b 0\r\n' :
      '#!/bin/sh\nprintf "%s\\n" "$*" >> npm-calls\nmkdir -p node_modules\nif [ -f fail-install ]; then exit 23; fi\n', { mode: 0o755 });
    const env = { ...process.env };
    const oldPath = Object.entries(env).find(([key]) => key.toLowerCase() === "path")?.[1] ?? "";
    for (const key of Object.keys(env)) if (key.toLowerCase() === "path") delete env[key];
    env.PATH = bin + path.delimiter + oldPath;
    const run = () => spawnSync(process.execPath, [path.join(fixture, "start.mjs")], { cwd: tmpdir(), env, encoding: "utf8", timeout: 15000 });
    const lines = (file) => readFileSync(path.join(fixture, file), "utf8").trim().split(/\r?\n/);
    const marker = path.join(fixture, "node_modules/.cipher-vault-runtime");
    writeFileSync(path.join(fixture, "fail-install"), "fixture");
    assert.equal(run().status, 23);
    assert.ok(!existsSync(marker) && !existsSync(path.join(fixture, "server-starts")));
    rmSync(path.join(fixture, "fail-install"));
    let result = run();
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.ok(existsSync(marker));
    assert.equal(lines("npm-calls").length, 2);
    assert.equal(run().status, 0);
    assert.equal(lines("npm-calls").length, 2, "successful installation should be reused");
    for (const file of ["package-lock.json", "package.json", "packages/shared/package.json"]) {
      writeFileSync(path.join(fixture, file), readFileSync(path.join(fixture, file), "utf8") + "\n");
      result = run(); assert.equal(result.status, 0, result.stdout + result.stderr);
    }
    assert.equal(lines("npm-calls").length, 5);
    assert.ok(lines("npm-calls").every(line => line === "ci --omit=dev --no-audit --no-fund"));
    const starts = lines("server-starts").length;
    rmSync(path.join(fixture, "package-lock.json"));
    assert.notEqual(run().status, 0, "missing lockfile must fail before installation or server startup");
    assert.equal(lines("npm-calls").length, 5);
    assert.equal(lines("server-starts").length, starts);
  } finally {
    assert.equal(path.dirname(fixture), path.resolve(tmpdir()));
    assert.ok(path.basename(fixture).startsWith("cipher-vault-release-start-"));
    rmSync(fixture, { recursive: true, force: true });
  }
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
