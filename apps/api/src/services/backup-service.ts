import { createCipheriv, createDecipheriv, randomBytes, scrypt } from "node:crypto";
import type { BackupExportPayload, BackupRestorePayload, PasswordEntry } from "@password-manager/shared/types";
import { HttpError } from "../lib/errors.js";
import { getVaultSession } from "./crypto-service.js";
import { getEntryById, listEntries, requireUnlockedVault, restoreEntriesIntoEmptyVault, validatePayload } from "./entry-service.js";

const FORMAT = "CIPHER-VAULT";
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_PLAINTEXT_BYTES = 11 * 1024 * 1024;
const MAX_ENTRIES = 10000;
const KDF = "scrypt-N131072-r8-p1";
const AAD = Buffer.from(`${FORMAT}:1:${KDF}:aes-256-gcm`);
let busy = false;

function validatePassphrase(payload: BackupExportPayload) {
  if (typeof payload?.passphrase !== "string" || payload.passphrase.length < 12 || payload.passphrase.length > 1024) {
    throw new HttpError(400, "バックアップ用パスフレーズは12〜1024文字で入力してください");
  }
}

async function withBackupKey<T>(passphrase: string, salt: Buffer, action: (key: Buffer) => T): Promise<T> {
  requireUnlockedVault();
  if (busy) throw new HttpError(409, "バックアップ処理の完了を待ってください");
  busy = true;
  const session = getVaultSession();
  let key: Buffer | undefined;
  try {
    key = await new Promise<Buffer>((resolve, reject) => {
      scrypt(passphrase, salt, 32, { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 }, (error, value) => {
        if (error) reject(error); else resolve(value);
      });
    });
    requireUnlockedVault();
    if (getVaultSession() !== session) throw new HttpError(409, "保管庫の状態が変わりました。もう一度操作してください");
    return action(key);
  } finally {
    key?.fill(0);
    busy = false;
  }
}

function decodeBase64(value: unknown, length?: number) {
  if (typeof value !== "string" || value.length > MAX_FILE_BYTES) throw new Error("invalid field");
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value || (length !== undefined && bytes.length !== length)) throw new Error("invalid encoding");
  return bytes;
}

function validDate(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}

function validateEntries(value: unknown): PasswordEntry[] {
  if (!Array.isArray(value) || value.length > MAX_ENTRIES) throw new Error("invalid entries");
  const ids = new Set<string>();
  for (const entry of value) {
    if (!entry || typeof entry !== "object" || typeof entry.id !== "string" ||
        !/^[0-9a-f-]{36}$/i.test(entry.id) || ids.has(entry.id)) throw new Error("invalid id");
    ids.add(entry.id);
    validatePayload({ ...entry, group: entry.group ?? undefined });
    if (typeof entry.notes !== "string" || typeof entry.url !== "string" || !Array.isArray(entry.tags) ||
        !(entry.group === null || typeof entry.group === "string") ||
        !validDate(entry.createdAt) || !validDate(entry.updatedAt) ||
        !(entry.passwordChangedAt === null || validDate(entry.passwordChangedAt)) ||
        entry.createdAt > entry.updatedAt ||
        (entry.passwordChangedAt !== null && (entry.passwordChangedAt < entry.createdAt || entry.passwordChangedAt > entry.updatedAt))) {
      throw new Error("invalid entry");
    }
  }
  return value as PasswordEntry[];
}

export async function exportBackup(payload: BackupExportPayload) {
  requireUnlockedVault();
  validatePassphrase(payload);
  const salt = randomBytes(16);
  return withBackupKey(payload.passphrase, salt, (key) => {
    const summaries = listEntries().items;
    if (summaries.length > MAX_ENTRIES) throw new HttpError(400, "バックアップは10000件まで対応しています");
    const entries = summaries.map((entry) => getEntryById(entry.id));
    const plaintext = Buffer.from(JSON.stringify({ version: 1, entries }));
    try {
      if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new HttpError(400, "バックアップ可能な容量を超えています（内容は11 MiBまで）");
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", key, iv);
      cipher.setAAD(AAD);
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      return {
        fileName: `CIPHER-VAULT-${new Date().toISOString().replace(/[:.]/g, "-")}.cvault`,
        content: JSON.stringify({ format: FORMAT, version: 1, kdf: KDF, cipher: "aes-256-gcm",
          salt: salt.toString("base64"), iv: iv.toString("base64"),
          tag: cipher.getAuthTag().toString("base64"), data: ciphertext.toString("base64") })
      };
    } finally { plaintext.fill(0); }
  });
}

export async function restoreBackup(payload: BackupRestorePayload) {
  requireUnlockedVault();
  validatePassphrase(payload);
  if (listEntries().items.length !== 0) throw new HttpError(409, "復元できるのは空の保管庫のみです");
  if (typeof payload.content !== "string" || Buffer.byteLength(payload.content) > MAX_FILE_BYTES) {
    throw new HttpError(400, "バックアップファイルは16 MiB以内で指定してください");
  }
  let salt: Buffer, iv: Buffer, tag: Buffer, data: Buffer;
  try {
    const envelope = JSON.parse(payload.content);
    if (envelope?.format !== FORMAT || envelope.version !== 1 || envelope.kdf !== KDF || envelope.cipher !== "aes-256-gcm") {
      throw new Error("unsupported format");
    }
    salt = decodeBase64(envelope.salt, 16);
    iv = decodeBase64(envelope.iv, 12);
    tag = decodeBase64(envelope.tag, 16);
    data = decodeBase64(envelope.data);
    if (data.length > MAX_PLAINTEXT_BYTES) throw new Error("oversized data");
  } catch { throw new HttpError(400, "未対応または破損したバックアップファイルです"); }
  return withBackupKey(payload.passphrase, salt, (key) => {
    let plaintext: Buffer | undefined;
    let partial: Buffer | undefined;
    let entries: PasswordEntry[];
    try {
      const decipher = createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAAD(AAD);
      decipher.setAuthTag(tag);
      partial = decipher.update(data);
      plaintext = Buffer.concat([partial, decipher.final()]);
      const decoded = JSON.parse(plaintext.toString("utf8"));
      if (decoded?.version !== 1) throw new Error("unsupported payload");
      entries = validateEntries(decoded.entries);
    } catch {
      throw new HttpError(400, "パスフレーズが違うか、バックアップファイルが破損しています");
    } finally { partial?.fill(0); plaintext?.fill(0); }
    return restoreEntriesIntoEmptyVault(entries);
  });
}
