import type { PasswordEntry, VaultEntry } from "@password-manager/shared/types";
import { HttpError } from "../lib/errors.js";
import { INPUT_LIMITS } from "../lib/input-validation.js";
import { validateAdditionalEntry } from "../lib/vault-entry-validation.js";
import { decodeBackupVersion, encodeBackupVersion, parseBackupVersion, validateBackupEntries, type BackupEnvelopeV1 } from "./backup-v1.js";

export type VaultBackupEnvelope = BackupEnvelopeV1 & { version: 1 | 2 };
export function validateVaultEntries(input: unknown): VaultEntry[] {
  if (!Array.isArray(input) || input.length > INPUT_LIMITS.entries) throw new HttpError(400, "バックアップの項目が正しくありません");
  const ids = new Set<string>();
  for (const item of input) {
    const type = item && typeof item === "object" ? Object.getOwnPropertyDescriptor(item, "type") : undefined;
    if (type && !("value" in type)) throw new HttpError(400, "バックアップの項目が正しくありません");
    const entry = type?.value === undefined ? validateBackupEntries([item])[0] : validateAdditionalEntry(item);
    if (ids.has(entry.id)) throw new HttpError(400, "バックアップの項目が重複しています");
    ids.add(entry.id);
  }
  return input as VaultEntry[];
}
export function encodeVaultBackup(entries: VaultEntry[], key: Buffer, salt: Buffer): string {
  validateVaultEntries(entries);
  return encodeBackupVersion(entries, key, salt, entries.some(entry => entry.type === "apiKey" || entry.type === "creditCard") ? 2 : 1);
}
export function parseVaultBackup(content: string): VaultBackupEnvelope {
  try {
    if (typeof content !== "string" || Buffer.byteLength(content) > INPUT_LIMITS.backupFileBytes) throw new Error();
    const version: unknown = JSON.parse(content)?.version;
    if (version !== 1 && version !== 2) throw new Error();
    return { ...parseBackupVersion(content, version), version };
  } catch { throw new HttpError(400, "未対応または破損したバックアップファイルです"); }
}
export function decodeVaultBackup(envelope: VaultBackupEnvelope, key: Buffer): VaultEntry[] {
  try {
    if (envelope.version !== 1 && envelope.version !== 2) throw new Error();
    const entries = decodeBackupVersion(envelope, key, envelope.version);
    return envelope.version === 1 ? validateBackupEntries(entries) as PasswordEntry[] : validateVaultEntries(entries);
  } catch { throw new HttpError(400, "パスフレーズが違うか、バックアップファイルが破損しています"); }
}
