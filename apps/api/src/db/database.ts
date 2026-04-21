import Database from "better-sqlite3";
import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";

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

const dataDirectory = resolveDataDirectory();
const databasePath = path.join(dataDirectory, "password-manager.db");

if (!existsSync(dataDirectory)) {
  mkdirSync(dataDirectory, { recursive: true });
}

export const database = new Database(databasePath);

export function initializeDatabase() {
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
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);
}

initializeDatabase();

// Migration: add group_name column to existing databases
try {
  database.exec("ALTER TABLE password_entries ADD COLUMN group_name TEXT");
} catch {
  // Column already exists — safe to ignore
}

export function getDatabasePath() {
  return databasePath;
}
