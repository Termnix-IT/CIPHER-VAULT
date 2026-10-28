import Database from "better-sqlite3";
import { closeSync, openSync } from "node:fs";
import path from "node:path";
import { sealEntry, VaultCodecError } from "../crypto/v2-codec.js";
import type { CodecOptions, EntryContext, EntryEnvelope, PasswordSlotContext, PasswordSlotEnvelope } from "../crypto/v2-codec.js";
import { parseEntryContext, parseEntryEnvelope, parsePasswordSlotContext, parsePasswordSlotEnvelope, record } from "../crypto/v2-format.js";
import { inspectV2Database, invalidStore, readHeader, V2_APPLICATION_ID, V2_SCHEMA_SQL, V2_SCHEMA_VERSION, V2_STORE_LIMITS, V2StoreError } from "./v2-schema.js";
export { V2_APPLICATION_ID, V2_SCHEMA_VERSION, V2_STORE_LIMITS, V2StoreError } from "./v2-schema.js";

export interface V2Store {
  readonly closed: boolean;
  readPasswordSlot(): PasswordSlotEnvelope;
  getUsage(): Readonly<{ encryptionCount: number; maxEncryptions: number }>;
  listEntryContexts(): readonly EntryContext[];
  readEntry(entryId: string): EntryEnvelope | null;
  writeEntry(root: Buffer, plaintext: string | Buffer, context: EntryContext, options?: CodecOptions): Promise<EntryEnvelope>;
  deleteEntry(context: EntryContext): void;
  close(): void;
}

function ioError(error: unknown): never {
  if (error instanceof V2StoreError || error instanceof VaultCodecError) throw error;
  throw new V2StoreError("IO_FAILED");
}
function close(database?: Database.Database) {
  try { if (database?.open) database.close(); } catch { throw new V2StoreError("IO_FAILED"); }
}
function resolveFilePath(value: string) {
  if (typeof value !== "string" || !value || value.includes("\0")) invalidStore();
  try { return path.resolve(value); } catch (error) { return ioError(error); }
}
function configureWriter(database: Database.Database) {
  database.pragma("synchronous = EXTRA");
  database.pragma("foreign_keys = ON");
  database.pragma("secure_delete = ON");
  database.pragma("trusted_schema = OFF");
  if (database.pragma("synchronous", { simple: true }) !== 3 || database.pragma("foreign_keys", { simple: true }) !== 1) invalidStore();
}

/** No environment-derived paths, implicit creation, default writer mode or live-vault integration. */
export function openV2Store(filePath: string, expectedInput: PasswordSlotContext, options: { writable?: boolean } = {}): V2Store {
  const expected = parsePasswordSlotContext(expectedInput);
  const parsed = record(options, ["writable"], []);
  if (parsed.writable !== undefined && typeof parsed.writable !== "boolean") invalidStore();
  const writable = parsed.writable === true;
  const resolved = resolveFilePath(filePath);
  let reader: Database.Database | undefined, database: Database.Database | undefined;
  try {
    reader = new Database(resolved, { readonly: true, fileMustExist: true });
    reader.transaction(() => inspectV2Database(reader!, expected))();
    if (!writable) return adapter(reader, expected, false);
    close(reader); reader = undefined;
    database = new Database(resolved, { fileMustExist: true });
    configureWriter(database);
    database.transaction(() => inspectV2Database(database!, expected)).immediate();
    return adapter(database, expected, true);
  } catch (error) { close(reader); close(database); return ioError(error); }
}

/** Parent directory must already exist. An existing file, including legacy or empty, is never overwritten. */
export function createV2Store(filePath: string, slotInput: PasswordSlotEnvelope): V2Store {
  const slot = parsePasswordSlotEnvelope(slotInput);
  const expected = parsePasswordSlotContext({ vaultId: slot.vaultId, keyId: slot.keyId, slotRevision: slot.slotRevision });
  const resolved = resolveFilePath(filePath);
  try { closeSync(openSync(resolved, "wx")); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new V2StoreError("EXISTS");
    return ioError(error);
  }
  let database: Database.Database | undefined;
  try {
    database = new Database(resolved, { fileMustExist: true });
    configureWriter(database);
    database.transaction(() => {
      database!.exec(V2_SCHEMA_SQL);
      database!.pragma(`application_id = ${V2_APPLICATION_ID}`);
      database!.pragma(`user_version = ${V2_SCHEMA_VERSION}`);
      database!.prepare("INSERT INTO vault_header VALUES (1, ?, ?, ?, ?, 0)")
        .run(slot.vaultId, slot.keyId, slot.slotRevision, JSON.stringify(slot));
      inspectV2Database(database!, expected);
    }).immediate();
    return adapter(database, expected, true);
  } catch (error) { close(database); return ioError(error); }
}

function adapter(database: Database.Database, expected: PasswordSlotContext, writable: boolean): V2Store {
  let busy = false, faulted = false;
  function available(write = false) {
    if (!database.open) throw new V2StoreError("CLOSED");
    if (faulted) throw new V2StoreError("FAULTED");
    if (write && !writable) throw new V2StoreError("READ_ONLY");
  }
  function run<T>(action: () => T): T {
    available();
    try { return action(); }
    catch (error) {
      const cancelled = error instanceof VaultCodecError && error.code === "CANCELLED";
      if (!cancelled && (!(error instanceof V2StoreError) || error.code === "INVALID_STORE")) faulted = true;
      return ioError(error);
    }
  }
  function context(input: EntryContext) {
    const parsed = parseEntryContext(input);
    if (parsed.vaultId !== expected.vaultId || parsed.keyId !== expected.keyId) invalidStore();
    return parsed;
  }
  function entryRow(id: string) {
    return database.prepare("SELECT revision, envelope FROM vault_entries WHERE entry_id = ?").get(id) as
      { revision: number; envelope: string | null } | undefined;
  }
  function canWrite(value: EntryContext) {
    const current = entryRow(value.entryId);
    if (value.revision !== (current ? current.revision + 1 : 1)) throw new V2StoreError("CONFLICT");
    if (!current || current.envelope === null) {
      const row = database.prepare("SELECT COUNT(*) AS count FROM vault_entries WHERE envelope IS NOT NULL").get() as { count: number };
      if (row.count >= V2_STORE_LIMITS.entries) throw new V2StoreError("ENTRY_LIMIT");
    }
  }
  function reserve(value: EntryContext, iv: Buffer) {
    available(true);
    return run(() => database.transaction(() => {
      const header = readHeader(database, expected);
      canWrite(value);
      if (database.prepare("SELECT 1 FROM vault_nonces WHERE key_id = ? AND iv = ?").get(value.keyId, iv)) return false;
      if (header.encryptionCount >= V2_STORE_LIMITS.encryptions) throw new V2StoreError("KEY_LIMIT");
      database.prepare("INSERT INTO vault_nonces VALUES (?, ?, ?, ?)").run(value.keyId, iv, value.entryId, value.revision);
      database.prepare("UPDATE vault_header SET encryption_count = encryption_count + 1 WHERE singleton = 1").run();
      return true;
    }).immediate());
  }
  const store: V2Store = {
    get closed() { return !database.open; },
    readPasswordSlot() { return run(() => readHeader(database, expected).slot); },
    getUsage() { return run(() => Object.freeze({ encryptionCount: readHeader(database, expected).encryptionCount, maxEncryptions: V2_STORE_LIMITS.encryptions })); },
    listEntryContexts() {
      return run(() => {
        const rows = database.prepare("SELECT entry_id, revision FROM vault_entries WHERE envelope IS NOT NULL ORDER BY entry_id LIMIT ?")
          .all(V2_STORE_LIMITS.entries + 1) as { entry_id: string; revision: number }[];
        if (rows.length > V2_STORE_LIMITS.entries) invalidStore();
        return Object.freeze(rows.map(row => context({ vaultId: expected.vaultId, keyId: expected.keyId, entryId: row.entry_id, revision: row.revision })));
      });
    },
    readEntry(entryId) {
      const value = context({ vaultId: expected.vaultId, keyId: expected.keyId, entryId, revision: 1 });
      return run(() => {
        const row = entryRow(value.entryId);
        if (!row || row.envelope === null) return null;
        const envelope = parseEntryEnvelope(row.envelope);
        if (envelope.vaultId !== expected.vaultId || envelope.keyId !== expected.keyId || envelope.entryId !== value.entryId || envelope.revision !== row.revision ||
            !database.prepare("SELECT 1 FROM vault_nonces WHERE key_id = ? AND iv = ? AND entry_id = ? AND revision = ?")
              .get(expected.keyId, Buffer.from(envelope.iv, "base64"), value.entryId, row.revision)) invalidStore();
        return envelope;
      });
    },
    async writeEntry(root, plaintext, input, options = {}) {
      available(true);
      if (busy) throw new V2StoreError("BUSY");
      const parsedOptions = record(options, ["signal"], []);
      if (parsedOptions.signal !== undefined && !(parsedOptions.signal instanceof AbortSignal)) throw new VaultCodecError("INVALID_INPUT");
      const signal = parsedOptions.signal as AbortSignal | undefined;
      const active = () => { if (signal?.aborted) throw new VaultCodecError("CANCELLED"); };
      active();
      const value = context(input);
      run(() => { canWrite(value); if (readHeader(database, expected).encryptionCount >= V2_STORE_LIMITS.encryptions) throw new V2StoreError("KEY_LIMIT"); });
      busy = true;
      let reservationError: unknown;
      try {
        const sealed = await sealEntry(root, plaintext, value, (_keyId, iv) => {
          try { return reserve(value, iv); }
          catch (error) { reservationError = error; throw error; }
        }, { signal });
        available(true);
        active();
        return run(() => database.transaction(() => {
          active();
          readHeader(database, expected);
          canWrite(value);
          if (!database.prepare("SELECT 1 FROM vault_nonces WHERE key_id = ? AND iv = ? AND entry_id = ? AND revision = ?")
            .get(value.keyId, Buffer.from(sealed.iv, "base64"), value.entryId, value.revision)) invalidStore();
          database.prepare(`INSERT INTO vault_entries (entry_id, revision, envelope) VALUES (?, ?, ?)
            ON CONFLICT(entry_id) DO UPDATE SET revision = excluded.revision, envelope = excluded.envelope`)
            .run(value.entryId, value.revision, JSON.stringify(sealed));
          return sealed;
        }).immediate());
      } catch (error) { return ioError(reservationError ?? error); }
      finally { busy = false; }
    },
    deleteEntry(input) {
      available(true);
      if (busy) throw new V2StoreError("BUSY");
      const value = context(input);
      run(() => database.transaction(() => {
        const row = entryRow(value.entryId);
        if (!row || row.envelope === null || row.revision !== value.revision) throw new V2StoreError("CONFLICT");
        database.prepare("UPDATE vault_entries SET envelope = NULL WHERE entry_id = ?").run(value.entryId);
      }).immediate());
    },
    close() {
      try { close(database); }
      catch (error) { faulted = true; throw error; }
    }
  };
  return Object.freeze(store);
}
