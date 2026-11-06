// The Node side of the differential test in crates/vault-core/tests/node_parity.rs. It calls the
// built TypeScript services the way apps/electron/src/desktop-main.ts registers them, so the Rust
// core can be compared with the app it replaces. Only synthetic vaults in temporary folders are used.
//
//   node tests/rust-parity-engine.mjs fixtures                 prints the shared invalid-input cases
//   node tests/rust-parity-engine.mjs prepare <kind> <folder>  writes a starting vault, prints its password
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
    generate: scoped(generatePassword)
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

if (mode === "fixtures") {
  const { invalidContractCases, validEntryPayload } = await import("./input-contract-fixtures.mjs");
  write({ valid: validEntryPayload(), invalid: invalidContractCases() });
} else if (mode === "prepare") {
  write(await prepare(rest[0], rest[1]));
} else if (mode === "serve") {
  await serve();
} else {
  throw new Error("Expected fixtures, prepare or serve");
}
