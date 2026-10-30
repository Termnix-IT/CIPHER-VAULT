import { randomBytes } from "node:crypto";
import { HttpError } from "../lib/errors.js";
import { getVaultSession } from "./crypto-service.js";
import { getEntryById, listEntries, requireUnlockedVault, restoreEntriesIntoEmptyVault } from "./entry-service.js";
import { INPUT_LIMITS, parseBackupPayload } from "../lib/input-validation.js";
import { deriveBackupKey } from "../crypto/backup-v1.js";
import { decodeVaultBackup, encodeVaultBackup, parseVaultBackup } from "../crypto/vault-backup.js";

let busy = false;
async function withBackupKey<T>(passphrase: string, salt: Buffer, action: (key: Buffer) => T | Promise<T>): Promise<T> {
  requireUnlockedVault();
  if (busy) throw new HttpError(409, "バックアップ処理の完了を待ってください");
  busy = true;
  const session = getVaultSession();
  let key: Buffer | undefined;
  try {
    key = await deriveBackupKey(passphrase, salt);
    requireUnlockedVault();
    if (getVaultSession() !== session) throw new HttpError(409, "保管庫の状態が変わりました。もう一度操作してください");
    const result = await action(key);
    requireUnlockedVault(session);
    return result;
  } finally { key?.fill(0); busy = false; }
}

export async function exportBackup(input: unknown) {
  requireUnlockedVault();
  const payload = parseBackupPayload(input, false);
  const salt = randomBytes(16);
  return withBackupKey(payload.passphrase, salt, key => {
    const summaries = listEntries().items;
    if (summaries.length > INPUT_LIMITS.entries) throw new HttpError(400, "バックアップは10000件まで対応しています");
    const entries = summaries.map(entry => getEntryById(entry.id));
    return {
      fileName: `CIPHER-VAULT-${new Date().toISOString().replace(/[:.]/g, "-")}.cvault`,
      content: encodeVaultBackup(entries, key, salt)
    };
  });
}

export async function restoreBackup(input: unknown) {
  requireUnlockedVault();
  const payload = parseBackupPayload(input, true);
  if (listEntries().items.length !== 0) throw new HttpError(409, "復元できるのは空の保管庫のみです");
  const envelope = parseVaultBackup(payload.content);
  return withBackupKey(payload.passphrase, envelope.salt, key => restoreEntriesIntoEmptyVault(decodeVaultBackup(envelope, key)));
}
