import type Database from "better-sqlite3";
import type { PasswordEntry } from "@password-manager/shared/types";
import { HttpError } from "../lib/errors.js";

export function restoreLegacyEntries(database: Database.Database, entries: PasswordEntry[],
  encrypt: (plaintext: string) => string, assertCurrent: () => void = () => {}) {
  return database.transaction(() => {
    assertCurrent();
    if (database.prepare("SELECT 1 FROM password_entries LIMIT 1").get()) throw new HttpError(409, "復元できるのは空の保管庫のみです");
    const insert = database.prepare(`INSERT INTO password_entries
      (id, service_name, login_id, encrypted_password, encrypted_notes, url, tags, group_name, created_at, updated_at, password_changed_at)
      VALUES (@id, @service_name, @login_id, @encrypted_password, @encrypted_notes, @url, @tags, @group_name, @created_at, @updated_at, @password_changed_at)`);
    for (const entry of entries) insert.run({ id: entry.id, service_name: entry.serviceName, login_id: entry.loginId,
      encrypted_password: encrypt(entry.password), encrypted_notes: encrypt(entry.notes), url: entry.url,
      tags: JSON.stringify(entry.tags), group_name: entry.group, created_at: entry.createdAt, updated_at: entry.updatedAt,
      password_changed_at: entry.passwordChangedAt });
    assertCurrent();
    return { restoredCount: entries.length };
  })();
}
