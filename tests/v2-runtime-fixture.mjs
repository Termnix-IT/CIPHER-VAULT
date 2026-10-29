// Synthetic legacy -> staging -> committed pointer, shared by service and real Electron tests.
import { mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { stageLegacyVault } from "../apps/api/dist/apps/api/src/migration/staging.js";
import { activateStagedVault } from "../apps/api/dist/apps/api/src/migration/activation.js";
import { VaultSession } from "../apps/api/dist/apps/api/src/services/vault-session.js";

export const compatibility = JSON.parse(readFileSync(new URL("./fixtures/crypto-compatibility.json", import.meta.url), "utf8"));
export const v2Password = "synthetic-v2-runtime-master-password";
export async function createMigratedFixture(directory) {
  mkdirSync(directory); mkdirSync(path.join(directory, "vaults"));
  const legacy = compatibility.legacy, m = legacy.metadata, database = new Database(path.join(directory, "password-manager.db"));
  try {
    database.exec(readFileSync(new URL("../apps/api/src/db/schema.sql", import.meta.url), "utf8"));
    database.prepare("INSERT INTO vault_metadata VALUES(1,?,?,?,?,?)").run(m.passwordSalt, m.passwordVerifier, m.kdfParams, m.createdAt, m.updatedAt);
    const columns = database.pragma("table_info(password_entries)").map(column => column.name);
    const insert = database.prepare(`INSERT INTO password_entries(${columns.join(",")}) VALUES(${columns.map(column => "@" + column).join(",")})`);
    for (const row of legacy.rows) insert.run(row);
  } finally { database.close(); }
  const result = await stageLegacyVault(path.join(directory, "password-manager.db"), path.join(directory, "vaults"), {
    masterPassword: legacy.password, newMasterPassword: v2Password, confirmNewMasterPassword: v2Password, backupPassphrase: compatibility.backupV1.passphrase
  });
  const context = { vaultId: result.vaultId, keyId: result.keyId, slotRevision: 1 }, session = new VaultSession(), key = Buffer.from(legacy.keyHex, "hex");
  try {
    session.unlock(key);
    await activateStagedVault(directory, context, { masterPassword: legacy.password, newMasterPassword: v2Password, backupPassphrase: compatibility.backupV1.passphrase },
      { session, sessionId: session.requireUnlocked() });
  } finally { key.fill(0); session.lock(); }
  return context;
}
