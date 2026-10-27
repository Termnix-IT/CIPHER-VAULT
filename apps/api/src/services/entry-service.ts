import { randomUUID } from "node:crypto";
import type {
  PasswordEntry,
  PasswordEntrySummary
} from "@password-manager/shared/types";
import { database } from "../db/database.js";
import { HttpError } from "../lib/errors.js";
import { decryptSecret, encryptSecret } from "./crypto-service.js";
import { vaultSession } from "./vault-session.js";
import { INPUT_LIMITS, parseEntryId, parseEntryPayload } from "../lib/input-validation.js";

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
const countEntriesStatement = database.prepare("SELECT COUNT(*) AS count FROM password_entries");

export function requireUnlockedVault(expectedSessionId?: string) {
  return vaultSession.requireUnlocked(expectedSessionId);
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

export function listEntries() {
  const session = requireUnlockedVault();
  const rows = listEntriesStatement.all() as PasswordEntryRow[];
  const items = rows.map(mapRowToSummary);
  requireUnlockedVault(session);
  return { items };
}

export function getEntryById(inputId: unknown) {
  const session = requireUnlockedVault();
  const id = parseEntryId(inputId);
  const row = getEntryStatement.get(id) as PasswordEntryRow | undefined;

  if (!row) {
    throw new HttpError(404, "エントリが見つかりません");
  }

  const entry = mapRowToEntry(row);
  requireUnlockedVault(session);
  return entry;
}

export function createEntry(input: unknown) {
  requireUnlockedVault();
  const payload = parseEntryPayload(input);
  if ((countEntriesStatement.get() as { count: number }).count >= INPUT_LIMITS.entries) {
    throw new HttpError(413, "保管庫への新規登録は10000件まで対応しています");
  }

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

export function updateEntry(inputId: unknown, input: unknown) {
  requireUnlockedVault();
  const id = parseEntryId(inputId);
  const payload = parseEntryPayload(input);

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

export function deleteEntry(inputId: unknown) {
  requireUnlockedVault();
  const id = parseEntryId(inputId);
  const result = deleteEntryStatement.run(id);

  if (result.changes === 0) {
    throw new HttpError(404, "エントリが見つかりません");
  }

  return {
    success: true
  };
}

export function restoreEntriesIntoEmptyVault(entries: PasswordEntry[]) {
  const session = requireUnlockedVault();
  return database.transaction(() => {
    requireUnlockedVault(session);
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
    requireUnlockedVault(session);
    return { restoredCount: entries.length };
  })();
}
