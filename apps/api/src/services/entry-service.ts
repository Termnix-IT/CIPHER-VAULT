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
};

const listEntriesStatement = database.prepare(
  `SELECT id, service_name, login_id, encrypted_password, encrypted_notes, url, tags, group_name, created_at, updated_at
   FROM password_entries
   ORDER BY updated_at DESC`
);

const getEntryStatement = database.prepare(
  `SELECT id, service_name, login_id, encrypted_password, encrypted_notes, url, tags, group_name, created_at, updated_at
   FROM password_entries
   WHERE id = ?`
);

const insertEntryStatement = database.prepare(
  `INSERT INTO password_entries (
    id, service_name, login_id, encrypted_password, encrypted_notes, url, tags, group_name, created_at, updated_at
   ) VALUES (
    @id, @service_name, @login_id, @encrypted_password, @encrypted_notes, @url, @tags, @group_name, @created_at, @updated_at
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
       updated_at = @updated_at
   WHERE id = @id`
);

const deleteEntryStatement = database.prepare("DELETE FROM password_entries WHERE id = ?");

function requireUnlockedVault() {
  if (!hasActiveVaultKey()) {
    throw new HttpError(423, "保管庫はロックされています");
  }
}

function parseTags(tags: string) {
  try {
    const parsed = JSON.parse(tags) as string[];
    return Array.isArray(parsed) ? parsed : [];
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
    createdAt: row.created_at
  };
}

function validatePayload(payload: PasswordEntryUpsertPayload) {
  if (!payload.serviceName?.trim()) {
    throw new HttpError(400, "サービス名は必須です");
  }

  if (!payload.loginId?.trim()) {
    throw new HttpError(400, "ログインIDは必須です");
  }

  if (!payload.password) {
    throw new HttpError(400, "パスワードは必須です");
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

  updateEntryStatement.run({
    id,
    service_name: payload.serviceName.trim(),
    login_id: payload.loginId.trim(),
    encrypted_password: encryptSecret(payload.password),
    encrypted_notes: payload.notes ? encryptSecret(payload.notes) : null,
    url: payload.url?.trim() || null,
    tags: JSON.stringify(payload.tags ?? []),
    group_name: payload.group?.trim() || null,
    updated_at: new Date().toISOString()
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
