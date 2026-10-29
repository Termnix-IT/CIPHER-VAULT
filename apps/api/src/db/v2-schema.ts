import type Database from "better-sqlite3";
import { parsePasswordSlotEnvelope, parsePasswordSlotContext, V2_LIMITS } from "../crypto/v2-format.js";
import type { PasswordSlotContext, PasswordSlotEnvelope } from "../crypto/v2-codec.js";

export const V2_APPLICATION_ID = 0x43563200;
export const V2_SCHEMA_VERSION = 1;
export const V2_STORE_LIMITS = Object.freeze({ encryptions: 2 ** 20, entries: 10000 });

type StoreCode = "EXISTS" | "INVALID_STORE" | "IO_FAILED" | "CLOSED" | "FAULTED" |
  "READ_ONLY" | "BUSY" | "CONFLICT" | "KEY_LIMIT" | "ENTRY_LIMIT";
const messages: Record<StoreCode, string> = {
  EXISTS: "V2 storage file already exists", INVALID_STORE: "Invalid or unsupported v2 storage",
  IO_FAILED: "V2 storage operation failed", CLOSED: "V2 storage is closed", FAULTED: "V2 storage requires reopening after failure",
  READ_ONLY: "V2 storage is read-only", BUSY: "V2 storage write is busy", CONFLICT: "V2 entry revision conflict",
  KEY_LIMIT: "V2 key encryption limit reached; a new root key is required", ENTRY_LIMIT: "V2 entry limit reached"
};
export class V2StoreError extends Error {
  constructor(readonly code: StoreCode) { super(messages[code]); this.name = "V2StoreError"; }
}

// Stored SQL is part of schema version 1. Compare the creator's exact DDL instead of parsing SQL ourselves.
export const V2_TABLES = Object.freeze({
  vault_header: `CREATE TABLE vault_header (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  vault_id TEXT NOT NULL,
  key_id TEXT NOT NULL UNIQUE,
  slot_revision INTEGER NOT NULL CHECK (slot_revision BETWEEN 1 AND ${V2_LIMITS.maxRevision}),
  password_slot TEXT NOT NULL CHECK (length(password_slot) BETWEEN 1 AND ${V2_LIMITS.envelopeBytes}),
  encryption_count INTEGER NOT NULL CHECK (encryption_count BETWEEN 0 AND ${V2_STORE_LIMITS.encryptions})
) STRICT`,
  vault_entries: `CREATE TABLE vault_entries (
  entry_id TEXT PRIMARY KEY NOT NULL,
  revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND ${V2_LIMITS.maxRevision}),
  envelope TEXT CHECK (envelope IS NULL OR length(envelope) BETWEEN 1 AND ${V2_LIMITS.envelopeBytes})
) STRICT`,
  vault_nonces: `CREATE TABLE vault_nonces (
  key_id TEXT NOT NULL REFERENCES vault_header(key_id),
  iv BLOB NOT NULL CHECK (length(iv) = 12),
  entry_id TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND ${V2_LIMITS.maxRevision}),
  PRIMARY KEY (key_id, iv)
) STRICT`
});
export const V2_SCHEMA_SQL = Object.values(V2_TABLES).join(";\n") + ";\n";
export type V2Header = Readonly<{ context: PasswordSlotContext; slot: PasswordSlotEnvelope; encryptionCount: number }>;

export function invalidStore(): never { throw new V2StoreError("INVALID_STORE"); }

export function readHeader(database: Database.Database, expected: PasswordSlotContext): V2Header {
  const rows = database.prepare("SELECT * FROM vault_header LIMIT 2").all() as {
    singleton: number; vault_id: string; key_id: string; slot_revision: number; password_slot: string; encryption_count: number
  }[];
  if (rows.length !== 1 || rows[0].singleton !== 1) invalidStore();
  const row = rows[0];
  try {
    const context = parsePasswordSlotContext({ vaultId: row.vault_id, keyId: row.key_id, slotRevision: row.slot_revision });
    if (context.vaultId !== expected.vaultId || context.keyId !== expected.keyId || context.slotRevision !== expected.slotRevision) invalidStore();
    const slot = parsePasswordSlotEnvelope(row.password_slot);
    if (slot.vaultId !== context.vaultId || slot.keyId !== context.keyId || slot.slotRevision !== context.slotRevision ||
        !Number.isInteger(row.encryption_count) || row.encryption_count < 0 || row.encryption_count > V2_STORE_LIMITS.encryptions) invalidStore();
    return Object.freeze({ context, slot, encryptionCount: row.encryption_count });
  } catch { return invalidStore(); }
}

export function inspectV2Database(database: Database.Database, expected: PasswordSlotContext): V2Header {
  if (database.pragma("application_id", { simple: true }) !== V2_APPLICATION_ID ||
      database.pragma("user_version", { simple: true }) !== V2_SCHEMA_VERSION ||
      database.pragma("journal_mode", { simple: true }) !== "delete") invalidStore();
  const objects = database.prepare("SELECT type, name, sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' LIMIT 4")
    .all() as { type: string; name: string; sql: string }[];
  if (objects.length !== 3 || objects.some(object => object.type !== "table" ||
      !Object.prototype.hasOwnProperty.call(V2_TABLES, object.name) || object.sql !== V2_TABLES[object.name as keyof typeof V2_TABLES])) invalidStore();
  const header = readHeader(database, expected);
  const count = database.prepare("SELECT COUNT(*) AS count FROM vault_nonces").get() as { count: number };
  if (count.count !== header.encryptionCount || database.prepare("SELECT 1 FROM vault_nonces WHERE key_id != ? LIMIT 1").get(expected.keyId) ||
      database.prepare("SELECT 1 FROM pragma_foreign_key_check LIMIT 1").get()) invalidStore();
  const entries = database.prepare("SELECT COUNT(*) AS count FROM vault_entries WHERE envelope IS NOT NULL").get() as { count: number };
  if (entries.count > V2_STORE_LIMITS.entries) invalidStore();
  return header;
}
