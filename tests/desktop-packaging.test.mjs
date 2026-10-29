import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { tmpdir } from "node:os";
import { requireNativeDesktopBuild } from "../scripts/require-native-build.mjs";
import { inspectDesktopPackage } from "../scripts/verify-desktop-package.mjs";
const asar = createRequire(createRequire(import.meta.url).resolve("app-builder-lib"))("@electron/asar");

test("native packaging rejects other OSes, unknown targets and unsupported architectures", () => {
  assert.doesNotThrow(() => requireNativeDesktopBuild("linux", "linux", "x64"));
  assert.doesNotThrow(() => requireNativeDesktopBuild("mac", "darwin", "arm64"));
  for (const input of [["linux", "win32", "x64"], ["mac", "linux", "arm64"], ["mac", "darwin", "ia32"], ["unknown", "linux", "x64"]]) assert.throws(() => requireNativeDesktopBuild(...input));
});

test("package inspection detects missing shared runtime, packed native binaries and private data", async () => {
  const root = mkdtempSync(path.join(tmpdir(), "cipher-vault-package-policy-"));
  const native = `node_modules/better-sqlite3/prebuilds/${process.platform}-${process.arch}.node`;
  const required = ["apps/electron/dist/apps/electron/src/main.js", "apps/electron/dist/apps/electron/src/preload.cjs", "apps/api/dist/apps/api/src/services/vault-maintenance-service.js",
    "apps/api/dist/apps/api/src/db/sqlite-file-scope.js", "apps/web/dist/index.html", "apps/web/dist/fonts/test.ttf", "apps/web/dist/fonts/OFL.txt",
    "node_modules/@password-manager/shared/package.json", "node_modules/@password-manager/shared/dist/index.js", "node_modules/@password-manager/shared/dist/renderer-policy.js",
    "apps/electron/dist/apps/electron/src/native-transport.js", "apps/electron/dist/apps/electron/src/local-client-auth.js",
    "apps/electron/dist/apps/electron/src/local-client-store.js", "apps/electron/dist/apps/electron/src/local-client-registry.js",
    "apps/electron/dist/apps/electron/src/local-identity.js", "apps/electron/dist/apps/electron/src/local-certificates.js",
    "apps/electron/dist/apps/electron/src/device-key-protector.js", "apps/electron/dist/apps/electron/src/protected-local-identity.js",
    "apps/electron/dist/apps/electron/src/local-pairing.js", native];
  async function fixture(name, { omit, extra, unpack = true, helper = {} } = {}) {
    const source = path.join(root, name, "source"), application = path.join(root, name, "application");
    for (const file of ["package.json", ...required.filter(file => file !== omit), ...(extra ? [extra] : [])]) {
      const target = path.join(source, file); mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, file === "package.json" ? JSON.stringify({ productName: "CIPHER VAULT", version: "0.0.0-fixture" }) : "synthetic package fixture");
    }
    const resources = path.join(application, process.platform === "darwin" ? "Contents/Resources" : "resources"); mkdirSync(resources, { recursive: true });
    const helperDirectory = path.join(resources, "native-transport"); mkdirSync(helperDirectory);
    for (const file of [process.platform === "win32" ? "cipher-vault-transport.exe" : "cipher-vault-transport", "LICENSE.TXT", "THIRD-PARTY-NOTICES.TXT"]) writeFileSync(path.join(helperDirectory, file), "synthetic native resource");
    writeFileSync(path.join(helperDirectory, "native-transport.json"), JSON.stringify({ protocol: 1, platform: process.platform, arch: process.arch, version: "0.0.0-fixture", runtimeVersion: "10.0.11", buildSha256: "0".repeat(64), ...helper }));
    await asar.createPackageWithOptions(source, path.join(resources, "app.asar"), unpack ? { unpack: "**/*.node" } : {});
    return application;
  }
  try {
    assert.equal(inspectDesktopPackage(await fixture("valid")).version, "0.0.0-fixture");
    const missing = await fixture("missing", { omit: "node_modules/@password-manager/shared/dist/index.js" });
    assert.throws(() => inspectDesktopPackage(missing), /Missing packaged runtime file/);
    const packed = await fixture("packed", { unpack: false }); assert.throws(() => inspectDesktopPackage(packed), /SQLite binary must be unpacked/);
    for (const [key, value] of [["arch", "wrong"], ["platform", "wrong"], ["version", "wrong"]]) {
      const wrong = await fixture(`helper-${key}`, { helper: { [key]: value } });
      assert.throws(() => inspectDesktopPackage(wrong), /Wrong native helper/);
    }
    for (const extra of ["apps/api/data/password-manager.db", "data/vault.sqlite", ".env", "private.log", "identity-synthetic.cvkey", "tests/fixture.mjs", "native/Transport.csproj"]) {
      const application = await fixture(`private-${extra.replaceAll(/[^a-z]/gi, "-")}`, { extra });
      assert.throws(() => inspectDesktopPackage(application), /Unexpected private data/);
    }
  } finally {
    assert.equal(path.dirname(root), path.resolve(tmpdir())); assert.ok(path.basename(root).startsWith("cipher-vault-package-policy-"));
    rmSync(root, { recursive: true, force: true });
  }
});
