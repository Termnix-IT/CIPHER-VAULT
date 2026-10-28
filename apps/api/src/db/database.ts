import Database from "better-sqlite3";
import { closeSync, existsSync, mkdirSync, openSync, statSync } from "node:fs";
import path from "node:path";
import { inspectDatabase, VaultStorageError } from "./database-format.js";
import type { DatabaseInspection } from "./database-format.js";
export { VaultStorageError } from "./database-format.js";

export type DatabaseOptions = { dataDirectory?: string; readonly?: boolean; createIfMissing?: boolean };
let connection: Database.Database | undefined;

function resolveDataDirectory() {
  const override = process.env.PASSWORD_MANAGER_DATA_DIR;

  if (override) {
    return path.resolve(override);
  }

  const candidates = [
    path.resolve(process.cwd(), "apps/api/data"),
    path.resolve(process.cwd(), "data"),
    path.resolve(import.meta.dirname, "../../data")
  ];

  const existing = candidates.find((candidate) => existsSync(candidate));
  return existing ?? candidates[0];
}

function storageError(error: unknown): never {
  if (error instanceof VaultStorageError) throw error;
  const code = error instanceof Database.SqliteError ? error.code : "";
  throw new VaultStorageError(["SQLITE_NOTADB", "SQLITE_CORRUPT", "SQLITE_ERROR"].includes(code) ? "INVALID_DATABASE" : "OPEN_FAILED");
}

function closeConnection(database?: Database.Database) {
  try {
    if (database?.inTransaction) throw new VaultStorageError("CLOSE_FAILED");
    if (database?.open) database.close();
  } catch { throw new VaultStorageError("CLOSE_FAILED"); }
}

function fileExists(filePath: string) {
  try {
    if (!statSync(filePath).isFile()) throw new VaultStorageError("OPEN_FAILED");
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    return storageError(error);
  }
}

/** Missing paths are reported without creating directories, DBs or schemas. */
export function inspectDatabaseFile(filePath: string): DatabaseInspection | Readonly<{ format: "missing"; needsMigration: false }> {
  if (!fileExists(filePath)) return Object.freeze({ format: "missing", needsMigration: false });
  let reader: Database.Database | undefined;
  try {
    reader = new Database(filePath, { readonly: true, fileMustExist: true });
    return reader.transaction(() => inspectDatabase(reader!))();
  } catch (error) { return storageError(error); }
  finally { closeConnection(reader); }
}

function initializeLegacyDatabase(database: Database.Database) {
  database.exec(`
    CREATE TABLE IF NOT EXISTS vault_metadata (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      password_salt TEXT NOT NULL,
      password_verifier TEXT NOT NULL,
      kdf_params TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS password_entries (
      id TEXT PRIMARY KEY,
      service_name TEXT NOT NULL,
      login_id TEXT NOT NULL,
      encrypted_password TEXT NOT NULL,
      encrypted_notes TEXT,
      url TEXT,
      tags TEXT NOT NULL,
      group_name TEXT,
      password_changed_at TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);
  const columns = database.pragma("table_info(password_entries)") as { name: string }[];
  if (!columns.some(column => column.name === "group_name")) database.exec("ALTER TABLE password_entries ADD COLUMN group_name TEXT");
  if (!columns.some(column => column.name === "password_changed_at")) database.exec("ALTER TABLE password_entries ADD COLUMN password_changed_at TEXT");
}

/** Independent scratch vault: no provider switch and no filesystem-backed temporary store. */
export function createMemoryDatabase(): Database.Database {
  const database = new Database(":memory:");
  try {
    database.pragma("temp_store = MEMORY");
    initializeLegacyDatabase(database);
    return database;
  } catch (error) { closeConnection(database); return storageError(error); }
}

export function openDatabase(options: DatabaseOptions = {}): Database.Database {
  if (connection?.open) throw new VaultStorageError("ALREADY_OPEN");
  const databasePath = path.join(options.dataDirectory ? path.resolve(options.dataDirectory) : resolveDataDirectory(), "password-manager.db");
  const initial = inspectDatabaseFile(databasePath);
  if (initial.format === "missing") {
    if (options.readonly || options.createIfMissing === false) throw new VaultStorageError("NOT_FOUND");
    try {
      mkdirSync(path.dirname(databasePath), { recursive: true });
      // Never truncate a file created by another process after inspection.
      closeSync(openSync(databasePath, "wx"));
    } catch (error) { return storageError(error); }
  }
  let candidate: Database.Database | undefined;
  try {
    candidate = new Database(databasePath, { readonly: options.readonly ?? false, fileMustExist: true });
    const database = candidate;
    const prepare = () => {
      // Recheck under the transaction used for migration; no async gap or cached schema.
      const current = inspectDatabase(database);
      if (options.readonly) {
        if (current.needsMigration) throw new VaultStorageError("MIGRATION_REQUIRED");
      } else {
        database.pragma("secure_delete = ON");
        if (current.needsMigration) initializeLegacyDatabase(database);
      }
    };
    const transaction = database.transaction(prepare);
    if (options.readonly) transaction(); else transaction.immediate();
    connection = database;
    return database;
  } catch (error) { closeConnection(candidate); return storageError(error); }
}

export function getDatabase(): Database.Database {
  if (!connection?.open) throw new VaultStorageError("NOT_OPEN");
  return connection;
}

export function closeDatabase() {
  closeConnection(connection);
  connection = undefined;
}

export function getDatabasePath() { return getDatabase().name; }
