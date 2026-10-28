import type Database from "better-sqlite3";
import type { PasswordEntry } from "@password-manager/shared/types";
import { TextDecoder } from "node:util";
import { setImmediate } from "node:timers/promises";
import { inspectDatabase } from "../db/database-format.js";
import { decryptLegacySecret } from "../crypto/legacy-codec.js";
import { copyPlaintext, decodeBase64, record, validateEntryPlaintext } from "../crypto/v2-format.js";
import { validateBackupEntries } from "../crypto/backup-v1.js";
import { INPUT_LIMITS } from "../lib/input-validation.js";

type Code = "INVALID_INPUT" | "INVALID_SOURCE" | "AUTHENTICATION_FAILED" | "CAPACITY" |
  "SOURCE_CHANGED" | "CANCELLED" | "BUSY" | "BACKUP_MISMATCH" | "FAILED";
export class LegacyPreflightError extends Error {
  constructor(readonly code: Code) { super(`Legacy migration preflight: ${code}`); this.name = "LegacyPreflightError"; }
}
export const PREFLIGHT_RAW_BYTES = 32 * 1024 * 1024;
const fields = ["id", "service_name", "login_id", "encrypted_password", "encrypted_notes", "url", "tags", "group_name", "password_changed_at", "created_at", "updated_at"];
const metadataFields = ["password_salt", "password_verifier", "kdf_params", "created_at", "updated_at"];
type RawRow = Record<string, unknown>;
const invalid = (): never => { throw new LegacyPreflightError("INVALID_SOURCE"); };
const decode = (bytes: Buffer) => new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
const date = (value: string) => Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;

function projection(names: string[], missing: readonly string[] = []) {
  return names.flatMap(name => {
    const expression = missing.includes(name) ? "NULL" : name;
    return [`CAST(${expression} AS BLOB) AS ${name}_bytes`, `typeof(${expression}) AS ${name}_type`];
  }).join(", ");
}
function text(row: RawRow, name: string, nullable = false): string | null {
  if (row[`${name}_type`] === "null" && nullable) return null;
  const bytes = row[`${name}_bytes`];
  if (row[`${name}_type`] !== "text" || !Buffer.isBuffer(bytes)) invalid();
  return decode(bytes as Buffer);
}
function wipe(row: RawRow) { for (const value of Object.values(row)) if (Buffer.isBuffer(value)) value.fill(0); }

export function inspectLegacySource(database: Database.Database) {
  try {
    const format = inspectDatabase(database);
    if (format.format !== "legacy" || database.pragma("encoding", { simple: true }) !== "UTF-8") invalid();
    const columns = database.pragma("table_info(password_entries)") as { name: string }[];
    const missing = ["group_name", "password_changed_at"].filter(name => !columns.some(column => column.name === name));
    const count = (database.prepare("SELECT COUNT(*) AS count FROM password_entries").get() as { count: number }).count;
    if (count > INPUT_LIMITS.entries) throw new LegacyPreflightError("CAPACITY");
    const sum = fields.filter(name => !missing.includes(name)).map(name => `coalesce(length(CAST(${name} AS BLOB)), 0)`).join(" + ");
    const bytes = (database.prepare(`SELECT coalesce(sum(${sum}), 0) AS bytes FROM password_entries`).get() as { bytes: number }).bytes;
    if (bytes > PREFLIGHT_RAW_BYTES) throw new LegacyPreflightError("CAPACITY");
    return { count, missing: Object.freeze(missing) };
  } catch (error) { if (error instanceof LegacyPreflightError) throw error; return invalid(); }
}

export function readLegacyMetadata(database: Database.Database) {
  let rows: RawRow[] = [];
  try {
    const sum = metadataFields.map(name => `coalesce(length(CAST(${name} AS BLOB)), 0)`).join(" + ");
    if (database.prepare(`SELECT 1 FROM vault_metadata WHERE ${sum} > 8192 LIMIT 1`).get()) invalid();
    rows = database.prepare(`SELECT id, ${projection(metadataFields)} FROM vault_metadata LIMIT 2`).all() as RawRow[];
    if (rows.length !== 1 || rows[0].id !== 1) invalid();
    const row = rows[0], salt = text(row, "password_salt")!, verifier = text(row, "password_verifier")!;
    decodeBase64(salt, 16, 16); decodeBase64(verifier, 32, 32);
    const params = record(JSON.parse(text(row, "kdf_params")!), ["algorithm", "keyLength", "verifierAlgorithm"], ["algorithm", "keyLength"]);
    if (params.algorithm !== "scrypt" || params.keyLength !== 32 ||
        (params.verifierAlgorithm !== undefined && params.verifierAlgorithm !== "hmac-sha256-v1")) invalid();
    const created = text(row, "created_at")!, updated = text(row, "updated_at")!;
    if (!date(created) || !date(updated) || created > updated) invalid();
    return { salt, verifier, rawVerifier: params.verifierAlgorithm === undefined };
  } catch { return invalid(); }
  finally { rows.forEach(wipe); }
}

function secret(key: Buffer, encoded: string) {
  if (decodeBase64(encoded, INPUT_LIMITS.backupFileBytes).length < 28) invalid();
  const plaintext = decryptLegacySecret(key, encoded);
  try { return decode(plaintext); } finally { plaintext.fill(0); }
}

export async function readLegacyEntries(database: Database.Database, key: Buffer, active: () => void) {
  const { missing } = inspectLegacySource(database);
  const entries: PasswordEntry[] = [];
  let plaintextBytes = Buffer.byteLength('{"version":1,"entries":[]}');
  const statement = database.prepare(`SELECT ${projection(fields, missing)} FROM password_entries ORDER BY id`);
  try {
    for (const row of statement.iterate() as IterableIterator<RawRow>) {
      try {
        active();
        const entry: PasswordEntry = {
          id: text(row, "id")!, serviceName: text(row, "service_name")!, loginId: text(row, "login_id")!,
          password: secret(key, text(row, "encrypted_password")!),
          notes: row.encrypted_notes_type === "null" ? "" : secret(key, text(row, "encrypted_notes")!),
          url: text(row, "url", true) ?? "", tags: JSON.parse(text(row, "tags")!), group: text(row, "group_name", true),
          createdAt: text(row, "created_at")!, updatedAt: text(row, "updated_at")!, passwordChangedAt: text(row, "password_changed_at", true)
        };
        const serialized = JSON.stringify(entry);
        const nextSize = plaintextBytes + Buffer.byteLength(serialized) + (entries.length ? 1 : 0);
        if (nextSize > INPUT_LIMITS.backupPlaintextBytes) throw new LegacyPreflightError("CAPACITY");
        const encoded = copyPlaintext(serialized);
        try { validateEntryPlaintext(encoded, entry.id); plaintextBytes = nextSize; }
        finally { encoded.fill(0); }
        entries.push(entry);
      } finally { wipe(row); }
      if (entries.length % 32 === 0) { await setImmediate(); active(); }
    }
    validateBackupEntries(entries);
    return { entries, plaintextBytes };
  } catch (error) {
    entries.length = 0;
    if (error instanceof LegacyPreflightError) throw error;
    return invalid();
  }
}
