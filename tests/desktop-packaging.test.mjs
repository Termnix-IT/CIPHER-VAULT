import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { tmpdir } from "node:os";
import { inspectDesktopPackage } from "../scripts/verify-desktop-package.mjs";
const asar = createRequire(createRequire(import.meta.url).resolve("app-builder-lib"))("@electron/asar");

test("package inspection detects missing shared runtime, packed native binaries and private data", async () => {
  const root = mkdtempSync(path.join(tmpdir(), "cipher-vault-package-policy-"));
  const native = `node_modules/better-sqlite3/prebuilds/${process.platform}-${process.arch}.node`;
  const required = ["apps/electron/dist/apps/electron/src/main.js", "apps/electron/dist/apps/electron/src/preload.cjs", "apps/api/dist/apps/api/src/services/vault-maintenance-service.js",
    "apps/api/dist/apps/api/src/db/sqlite-file-scope.js", "apps/web/dist/index.html", "apps/web/dist/fonts/test.ttf", "apps/web/dist/fonts/OFL.txt",
    "apps/api/dist/apps/api/src/crypto/vault-backup.js", "apps/api/dist/apps/api/src/lib/vault-entry-validation.js",
    "apps/api/dist/apps/api/src/migration/typed-backup-recovery.js",
    "node_modules/@password-manager/shared/package.json", "node_modules/@password-manager/shared/dist/index.js", "node_modules/@password-manager/shared/dist/renderer-policy.js",
    "apps/electron/dist/apps/electron/src/desktop-main.js",
    "apps/web/dist/fonts/NotoSansJP-Variable.ttf", "apps/web/dist/fonts/NotoSansJP-OFL.txt", native];
  async function fixture(name, { omit, extra, unpack = true, helper = false } = {}) {
    const source = path.join(root, name, "source"), application = path.join(root, name, "application");
    for (const file of ["package.json", ...required.filter(file => file !== omit), ...(extra ? [extra] : [])]) {
      const target = path.join(source, file); mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, file === "package.json" ? JSON.stringify({ productName: "CIPHER VAULT", version: "0.0.0-fixture" }) : "synthetic package fixture");
    }
    const resources = path.join(application, "resources"); mkdirSync(resources, { recursive: true });
    if (helper) mkdirSync(path.join(resources, "native-transport"));
    await asar.createPackageWithOptions(source, path.join(resources, "app.asar"), unpack ? { unpack: "**/*.node" } : {});
    return application;
  }
  try {
    assert.equal(inspectDesktopPackage(await fixture("valid")).version, "0.0.0-fixture");
    const missing = await fixture("missing", { omit: "node_modules/@password-manager/shared/dist/index.js" });
    assert.throws(() => inspectDesktopPackage(missing), /Missing packaged runtime file/);
    const missingTyped = await fixture("missing-typed", { omit: "apps/api/dist/apps/api/src/migration/typed-backup-recovery.js" });
    assert.throws(() => inspectDesktopPackage(missingTyped), /Missing packaged runtime file/);
    const packed = await fixture("packed", { unpack: false }); assert.throws(() => inspectDesktopPackage(packed), /SQLite binary must be unpacked/);
    const helper = await fixture("helper", { helper: true });
    assert.throws(() => inspectDesktopPackage(helper), /Unexpected external connection helper/);
    for (const extra of ["apps/api/data/password-manager.db", "data/vault.sqlite", ".env", "private.log", "tests/fixture.mjs"]) {
      const application = await fixture(`private-${extra.replaceAll(/[^a-z]/gi, "-")}`, { extra });
      assert.throws(() => inspectDesktopPackage(application), /Unexpected private data/);
    }
  } finally {
    assert.equal(path.dirname(root), path.resolve(tmpdir())); assert.ok(path.basename(root).startsWith("cipher-vault-package-policy-"));
    rmSync(root, { recursive: true, force: true });
  }
});
