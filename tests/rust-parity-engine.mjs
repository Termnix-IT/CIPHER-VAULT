// The Node side of the differential test in crates/vault-core/tests/node_parity.rs. It calls the
// built TypeScript services the way apps/electron/src/desktop-main.ts registers them, so the Rust
// core can be compared with the app it replaces. Only synthetic vaults in temporary folders are used.
//
//   node tests/rust-parity-engine.mjs fixtures                 prints the shared invalid-input cases
//   node tests/rust-parity-engine.mjs prepare <kind> <folder>  writes a starting vault, prints its password
//   node tests/rust-parity-engine.mjs backups                  prints .cvault files of each version for one passphrase
//   node tests/rust-parity-engine.mjs serve                    runs calls from stdin on PASSWORD_MANAGER_DATA_DIR
//
// serve reads one JSON request per line, {"method": "...", "args": [...]}, where the string
// "$undefined" stands for a missing argument, and answers {"ok": value} or {"error": {status, message}}.
import { mkdirSync, readFileSync, unlinkSync } from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline";
import Database from "better-sqlite3";

const base = "../apps/api/dist/apps/api/src/";
const write = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
const [mode, ...rest] = process.argv.slice(2);

async function prepare(kind, directory) {
  const { compatibility, createMigratedFixture, v2Password } = await import("./v2-runtime-fixture.mjs");
  const schema = readFileSync(new URL("../apps/api/src/db/schema.sql", import.meta.url), "utf8");
  if (kind === "v2" || kind === "recovery") {
    await createMigratedFixture(directory);
    // A switch to v2 that stopped before the pointer was written, which the app must recover first.
    if (kind === "recovery") unlinkSync(path.join(directory, "vault-current.json"));
    return { password: v2Password };
  }
  mkdirSync(directory);
  if (kind === "empty") return {};
  const database = new Database(path.join(directory, "password-manager.db"));
  try {
    if (kind === "legacy-old-schema") {
      // A vault from before password_changed_at, which opening upgrades in place.
      database.exec(schema.replace(/\s*password_changed_at TEXT,/, ""));
      return {};
    }
    if (kind !== "legacy") throw new Error(`Unknown kind ${kind}`);
    const { metadata: m, rows } = compatibility.legacy;
    database.exec(schema);
    database.prepare("INSERT INTO vault_metadata VALUES(1,?,?,?,?,?)").run(m.passwordSalt, m.passwordVerifier, m.kdfParams, m.createdAt, m.updatedAt);
    const columns = database.pragma("table_info(password_entries)").map((column) => column.name);
    const insert = database.prepare(`INSERT INTO password_entries(${columns.join(",")}) VALUES(${columns.map((column) => "@" + column).join(",")})`);
    for (const row of rows) insert.run(row);
    return { password: compatibility.legacy.password };
  } finally {
    database.close();
  }
}

async function serve() {
  const maintenance = await import(`${base}services/vault-maintenance-service.js`);
  const vault = await import(`${base}services/vault-service.js`);
  const entries = await import(`${base}services/entry-service.js`);
  const { generatePassword } = await import(`${base}services/password-service.js`);
  const session = await import(`${base}services/vault-session.js`);
  const backup = await import(`${base}services/backup-service.js`);
  maintenance.openApplicationVault();
  // handleControl and handleSession in desktop-main.ts, without the quit and power checks.
  const control = (action) => (sessionId, payload) => { session.vaultSession.requireGeneration(sessionId); return action(payload); };
  const scoped = (action) => (sessionId, ...args) => session.withVaultSession(sessionId, () => action(...args));
  const methods = {
    status: () => vault.getVaultStatus(),
    activity: (sessionId) => vault.recordVaultActivity(sessionId),
    setup: control(vault.setupVault),
    unlock: control(vault.unlockVault),
    reset: control(vault.resetVault),
    lock: (sessionId) => vault.lockVaultForSession(sessionId),
    list: scoped(entries.listEntries),
    get: scoped(entries.getEntryById),
    create: scoped(entries.createEntry),
    update: scoped(entries.updateEntry),
    delete: scoped(entries.deleteEntry),
    setGroup: scoped(entries.setEntriesGroup),
    generate: scoped(generatePassword),
    exportBackup: scoped(backup.exportBackup),
    restoreBackup: scoped(backup.restoreBackup),
    decodeBackup: decodeBackup
  };
  for await (const line of createInterface({ input: process.stdin })) {
    const { method, args } = JSON.parse(line);
    try {
      const value = await methods[method](...args.map((arg) => arg === "$undefined" ? undefined : arg));
      write({ ok: value ?? null });
    } catch (error) {
      write({ error: { status: error?.statusCode ?? 500, message: error instanceof Error ? error.message : String(error) } });
    }
  }
  maintenance.closeApplicationVault();
}

/** Reads a file the other engine wrote, without a vault. */
async function decodeBackup(content, passphrase) {
  const { deriveBackupKey } = await import(`${base}crypto/backup-v1.js`);
  const { decodeVaultBackup, parseVaultBackup } = await import(`${base}crypto/vault-backup.js`);
  const envelope = parseVaultBackup(content), key = await deriveBackupKey(passphrase, envelope.salt);
  try { return { version: envelope.version, entries: decodeVaultBackup(envelope, key) }; } finally { key.fill(0); }
}

/** One file of each version, with fixed ids and dates so both engines restore the same entries. */
async function backups() {
  const { randomBytes } = await import("node:crypto");
  const { deriveBackupKey } = await import(`${base}crypto/backup-v1.js`);
  const { encodeVaultBackup } = await import(`${base}crypto/vault-backup.js`);
  const passphrase = "synthetic-parity-backup-passphrase";
  const dates = { createdAt: "2026-01-01T00:00:00.000Z", updatedAt: "2026-02-01T00:00:00.000Z" };
  const common = { notes: "", url: "", tags: ["backup"], group: null, ...dates };
  const login = { id: "aaaaaaaa-0000-4000-8000-000000000001", serviceName: "Restored login", loginId: "restored", password: "synthetic-restored-password",
    ...common, notes: "restored notes", url: "https://example.test/", group: "復元", passwordChangedAt: "2026-01-15T00:00:00.000Z" };
  const second = { ...login, id: "AAAAAAAA-0000-4000-8000-000000000002", serviceName: "Restored second", notes: "", passwordChangedAt: null };
  const apiKey = { id: "aaaaaaaa-0000-4000-8000-000000000003", type: "apiKey", serviceName: "Restored key", ...common, apiKey: { key: "synthetic-restored-key", keyId: "", expiresOn: null } };
  const financial = { id: "aaaaaaaa-0000-4000-8000-000000000004", type: "financial", serviceName: "Restored bank", ...common,
    financial: { loginId: "bank", loginPassword: "synthetic-restored-bank", tradingPassword: "", extraSecrets: [] } };
  const files = { passphrase };
  for (const [name, entries] of [["v1", [login, second]], ["v2", [login, apiKey]], ["v3", [login, apiKey, financial]]]) {
    const salt = randomBytes(16), key = await deriveBackupKey(passphrase, salt);
    try { files[name] = encodeVaultBackup(entries, key, salt); } finally { key.fill(0); }
  }
  return files;
}

if (mode === "fixtures") {
  const { invalidContractCases, validEntryPayload } = await import("./input-contract-fixtures.mjs");
  write({ valid: validEntryPayload(), invalid: invalidContractCases() });
} else if (mode === "backups") {
  write(await backups());
} else if (mode === "prepare") {
  write(await prepare(rest[0], rest[1]));
} else if (mode === "serve") {
  await serve();
} else {
  throw new Error("Expected fixtures, prepare or serve");
}
