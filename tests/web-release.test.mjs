import assert from "node:assert/strict";
import { test } from "node:test";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

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
