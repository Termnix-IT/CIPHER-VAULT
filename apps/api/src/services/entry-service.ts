import { randomUUID } from "node:crypto";
import type {
  PasswordEntry,
  PasswordEntrySummary,
  PasswordEntryUpsertPayload
} from "@password-manager/shared/types";
import { database } from "../db/database.js";
import { HttpError } from "../lib/errors.js";
import { decryptSecret, encryptSecret, hasActiveVaultKey } from "./crypto-service.js";

type PasswordEntryRow = {
  id: string;
  service_name: string;
  login_id: string;
  encrypted_password: string;
  encrypted_notes: string | null;
  url: string | null;
  tags: string;
  group_name: string | null;
  created_at: string;
  updated_at: string;
  password_changed_at: string | null;
};

const listEntriesStatement = database.prepare(
  `SELECT id, service_name, login_id, encrypted_password, encrypted_notes, url, tags, group_name, created_at, updated_at, password_changed_at
   FROM password_entries
   ORDER BY updated_at DESC`
);

const getEntryStatement = database.prepare(
  `SELECT id, service_name, login_id, encrypted_password, encrypted_notes, url, tags, group_name, created_at, updated_at, password_changed_at
   FROM password_entries
   WHERE id = ?`
);

const insertEntryStatement = database.prepare(
  `INSERT INTO password_entries (
    id, service_name, login_id, encrypted_password, encrypted_notes, url, tags, group_name, created_at, updated_at, password_changed_at
   ) VALUES (
    @id, @service_name, @login_id, @encrypted_password, @encrypted_notes, @url, @tags, @group_name, @created_at, @updated_at, @password_changed_at
   )`
);

const updateEntryStatement = database.prepare(
  `UPDATE password_entries
   SET service_name = @service_name,
       login_id = @login_id,
       encrypted_password = @encrypted_password,
       encrypted_notes = @encrypted_notes,
       url = @url,
       tags = @tags,
       group_name = @group_name,
       password_changed_at = @password_changed_at,
       updated_at = @updated_at
   WHERE id = @id`
);

const deleteEntryStatement = database.prepare("DELETE FROM password_entries WHERE id = ?");

export function requireUnlockedVault() {
  if (!hasActiveVaultKey()) {
    throw new HttpError(423, "保管庫はロックされています");
  }
}

function parseTags(tags: string) {
  try {
    const parsed = JSON.parse(tags) as string[];
    return Array.isArray(parsed) ? parsed.filter((tag) => typeof tag === "string") : [];
  } catch {
    return [];
  }
}

function mapRowToSummary(row: PasswordEntryRow): PasswordEntrySummary {
  return {
    id: row.id,
    serviceName: row.service_name,
    loginId: row.login_id,
    tags: parseTags(row.tags),
    group: row.group_name ?? null,
    updatedAt: row.updated_at
  };
}

function mapRowToEntry(row: PasswordEntryRow): PasswordEntry {
  return {
    ...mapRowToSummary(row),
    password: decryptSecret(row.encrypted_password),
    notes: row.encrypted_notes ? decryptSecret(row.encrypted_notes) : "",
    url: row.url ?? "",
    createdAt: row.created_at,
    passwordChangedAt: row.password_changed_at
  };
}

export function validatePayload(payload: PasswordEntryUpsertPayload) {
  if (typeof payload?.serviceName !== "string" || !payload.serviceName.trim()) {
    throw new HttpError(400, "サービス名は必須です");
  }

  if (typeof payload.loginId !== "string" || !payload.loginId.trim()) {
    throw new HttpError(400, "ログインIDは必須です");
  }

  if (typeof payload.password !== "string" || !payload.password) {
    throw new HttpError(400, "パスワードは必須です");
  }
  for (const field of ["notes", "url", "group"] as const) {
    if (payload[field] != null && typeof payload[field] !== "string") {
      throw new HttpError(400, `${field}は文字列で指定してください`);
    }
  }
  if (payload.tags != null && (!Array.isArray(payload.tags) || payload.tags.some((tag) => typeof tag !== "string"))) {
    throw new HttpError(400, "タグは文字列の配列で指定してください");
  }
}

export function listEntries() {
  requireUnlockedVault();
  const rows = listEntriesStatement.all() as PasswordEntryRow[];

  return {
    items: rows.map(mapRowToSummary)
  };
}

export function getEntryById(id: string) {
  requireUnlockedVault();
  const row = getEntryStatement.get(id) as PasswordEntryRow | undefined;

  if (!row) {
    throw new HttpError(404, "エントリが見つかりません");
  }

  return mapRowToEntry(row);
}

export function createEntry(payload: PasswordEntryUpsertPayload) {
  requireUnlockedVault();
  validatePayload(payload);

  const now = new Date().toISOString();
  const id = randomUUID();

  insertEntryStatement.run({
    id,
    service_name: payload.serviceName.trim(),
    login_id: payload.loginId.trim(),
    encrypted_password: encryptSecret(payload.password),
    encrypted_notes: payload.notes ? encryptSecret(payload.notes) : null,
    url: payload.url?.trim() || null,
    tags: JSON.stringify(payload.tags ?? []),
    group_name: payload.group?.trim() || null,
    created_at: now,
    password_changed_at: now,
    updated_at: now
  });

  return getEntryById(id);
}

export function updateEntry(id: string, payload: PasswordEntryUpsertPayload) {
  requireUnlockedVault();
  validatePayload(payload);

  const existing = getEntryStatement.get(id) as PasswordEntryRow | undefined;

  if (!existing) {
    throw new HttpError(404, "エントリが見つかりません");
  }

  const now = new Date().toISOString();
  updateEntryStatement.run({
    id,
    service_name: payload.serviceName.trim(),
    login_id: payload.loginId.trim(),
    encrypted_password: encryptSecret(payload.password),
    encrypted_notes: payload.notes ? encryptSecret(payload.notes) : null,
    url: payload.url?.trim() || null,
    tags: JSON.stringify(payload.tags ?? []),
    group_name: payload.group?.trim() || null,
    updated_at: now,
    password_changed_at: decryptSecret(existing.encrypted_password) === payload.password
      ? existing.password_changed_at : now
  });

  return getEntryById(id);
}

export function deleteEntry(id: string) {
  requireUnlockedVault();
  const result = deleteEntryStatement.run(id);

  if (result.changes === 0) {
    throw new HttpError(404, "エントリが見つかりません");
  }

  return {
    success: true
  };
}

export function restoreEntriesIntoEmptyVault(entries: PasswordEntry[]) {
  return database.transaction(() => {
    requireUnlockedVault();
    if (listEntriesStatement.get()) throw new HttpError(409, "復元できるのは空の保管庫のみです");
    for (const entry of entries) {
      insertEntryStatement.run({
        id: entry.id, service_name: entry.serviceName, login_id: entry.loginId,
        encrypted_password: encryptSecret(entry.password),
        encrypted_notes: encryptSecret(entry.notes), url: entry.url,
        tags: JSON.stringify(entry.tags), group_name: entry.group,
        created_at: entry.createdAt, updated_at: entry.updatedAt,
        password_changed_at: entry.passwordChangedAt
      });
    }
    return { restoredCount: entries.length };
  })();
}
