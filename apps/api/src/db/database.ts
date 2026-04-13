import Database from "better-sqlite3";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
function resolveSchemaPath() {
  const candidates = [
    path.resolve(__dirname, "./schema.sql"),
    path.resolve(process.cwd(), "apps/api/src/db/schema.sql"),
    path.resolve(process.cwd(), "src/db/schema.sql")
  ];

  const existing = candidates.find((candidate) => existsSync(candidate));

  if (!existing) {
    throw new Error("schema.sql was not found");
  }

  return existing;
}

const schemaPath = resolveSchemaPath();

function resolveDataDirectory() {
  const candidates = [
    path.resolve(process.cwd(), "apps/api/data"),
    path.resolve(process.cwd(), "data"),
    path.resolve(__dirname, "../../data")
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
  const schema = readFileSync(schemaPath, "utf-8");
  database.exec(schema);
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
