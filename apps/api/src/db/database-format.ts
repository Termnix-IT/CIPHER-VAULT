import type Database from "better-sqlite3";

type StorageErrorCode = "NOT_OPEN" | "ALREADY_OPEN" | "NOT_FOUND" | "UNSUPPORTED_FORMAT" |
  "INVALID_DATABASE" | "MIGRATION_REQUIRED" | "OPEN_FAILED" | "CLOSE_FAILED";
const messages: Record<StorageErrorCode, string> = {
  NOT_OPEN: "保管庫の保存先が開かれていません",
  ALREADY_OPEN: "保管庫の保存先はすでに開かれています",
  NOT_FOUND: "保管庫の保存先が見つかりません",
  UNSUPPORTED_FORMAT: "未対応の保管庫保存形式です。原本を保持して対応する版で確認してください",
  INVALID_DATABASE: "保管庫の保存形式を読み取れません。原本を保持して復旧を確認してください",
  MIGRATION_REQUIRED: "この保存先は読取専用では利用できません。対応する版で初期化・旧列の追加が必要です",
  OPEN_FAILED: "保管庫の保存先を開けません。アクセス権・使用状況・復旧の必要性を確認してください",
  CLOSE_FAILED: "保管庫の保存先を閉じられません"
};

export class VaultStorageError extends Error {
  constructor(readonly code: StorageErrorCode) { super(messages[code]); this.name = "VaultStorageError"; }
}

export type DatabaseInspection = Readonly<{ format: "empty" | "legacy"; needsMigration: boolean }>;
type Column = { name: string; type: string; notnull: number; pk: number; hidden: number; dflt_value: unknown };
const metadataColumns = {
  id: ["INTEGER", 0, 1], password_salt: ["TEXT", 1, 0], password_verifier: ["TEXT", 1, 0],
  kdf_params: ["TEXT", 1, 0], created_at: ["TEXT", 1, 0], updated_at: ["TEXT", 1, 0]
} as const;
const entryColumns = {
  id: ["TEXT", 0, 1], service_name: ["TEXT", 1, 0], login_id: ["TEXT", 1, 0],
  encrypted_password: ["TEXT", 1, 0], encrypted_notes: ["TEXT", 0, 0], url: ["TEXT", 0, 0],
  tags: ["TEXT", 1, 0], group_name: ["TEXT", 0, 0], password_changed_at: ["TEXT", 0, 0],
  created_at: ["TEXT", 1, 0], updated_at: ["TEXT", 1, 0]
} as const;

function unsupported(): never { throw new VaultStorageError("UNSUPPORTED_FORMAT"); }

function checkColumns(database: Database.Database, table: "vault_metadata" | "password_entries",
  expected: Record<string, readonly [string, number, number]>, optional: readonly string[] = []) {
  // Identifiers are fixed application constants, never file-provided SQL.
  const columns = database.pragma(`table_xinfo(${table})`) as Column[];
  const names = new Set(columns.map(column => column.name));
  if (Object.keys(expected).some(name => !optional.includes(name) && !names.has(name))) unsupported();
  for (const column of columns) {
    const spec = Object.prototype.hasOwnProperty.call(expected, column.name) ? expected[column.name] : undefined;
    if (!spec || column.type !== spec[0] || column.notnull !== spec[1] || column.pk !== spec[2] ||
        column.hidden !== 0 || column.dflt_value !== null) unsupported();
  }
  if ((database.pragma(`foreign_key_list(${table})`) as unknown[]).length) unsupported();
  return optional.some(name => !names.has(name));
}

/** Inspect one SQLite snapshot without executing schema SQL or modifying version markers. */
export function inspectDatabase(database: Database.Database): DatabaseInspection {
  if (database.pragma("application_id", { simple: true }) !== 0 || database.pragma("user_version", { simple: true }) !== 0) unsupported();
  const objects = database.prepare("SELECT type, name FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' LIMIT 3")
    .all() as { type: string; name: string }[];
  if (!objects.length) return Object.freeze({ format: "empty", needsMigration: true });
  if (objects.length !== 2 || objects.some(object => object.type !== "table") ||
      !objects.some(object => object.name === "vault_metadata") || !objects.some(object => object.name === "password_entries")) unsupported();
  const tables = database.pragma("table_list") as { schema: string; name: string; type: string; wr: number; strict: number }[];
  if (tables.some(table => table.schema === "main" && ["vault_metadata", "password_entries"].includes(table.name) &&
      (table.type !== "table" || table.wr !== 0 || table.strict !== 0))) unsupported();
  checkColumns(database, "vault_metadata", metadataColumns);
  const needsMigration = checkColumns(database, "password_entries", entryColumns, ["group_name", "password_changed_at"]);
  return Object.freeze({ format: "legacy", needsMigration });
}
