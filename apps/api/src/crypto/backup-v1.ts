import { createCipheriv, createDecipheriv, randomBytes, scrypt } from "node:crypto";
import type { PasswordEntry } from "@password-manager/shared/types";
import { HttpError } from "../lib/errors.js";
import { INPUT_LIMITS, parseEntryPayload, parseRecord } from "../lib/input-validation.js";

const KDF = "scrypt-N131072-r8-p1";
const aad = (version: 1 | 2) => Buffer.from(`CIPHER-VAULT:${version}:${KDF}:aes-256-gcm`);
export type BackupEnvelopeV1 = { salt: Buffer; iv: Buffer; tag: Buffer; data: Buffer };

export function deriveBackupKey(passphrase: string | Buffer, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(passphrase, salt, 32, { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 }, (error, key) => {
      if (error) { key?.fill(0); reject(error); } else resolve(key);
    });
  });
}

function decodeBase64(value: unknown, length?: number) {
  if (typeof value !== "string" || value.length > INPUT_LIMITS.backupFileBytes) throw new Error("invalid field");
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value || (length !== undefined && bytes.length !== length)) throw new Error("invalid encoding");
  return bytes;
}
function validDate(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}

export function validateBackupEntries(value: unknown): PasswordEntry[] {
  if (!Array.isArray(value) || value.length > INPUT_LIMITS.entries) throw new Error("invalid entries");
  const ids = new Set<string>();
  for (const entry of value) {
    parseRecord(entry, ["id", "serviceName", "loginId", "password", "notes", "url", "tags", "group", "createdAt", "updatedAt", "passwordChangedAt"]);
    if (typeof entry.id !== "string" || !/^[0-9a-f-]{36}$/i.test(entry.id) || ids.has(entry.id)) throw new Error("invalid id");
    ids.add(entry.id);
    parseEntryPayload({ serviceName: entry.serviceName, loginId: entry.loginId, password: entry.password,
      notes: entry.notes, url: entry.url, group: entry.group, tags: entry.tags }, "backup");
    if (typeof entry.notes !== "string" || typeof entry.url !== "string" || !Array.isArray(entry.tags) ||
        !(entry.group === null || typeof entry.group === "string") || !validDate(entry.createdAt) || !validDate(entry.updatedAt) ||
        !(entry.passwordChangedAt === null || validDate(entry.passwordChangedAt)) || entry.createdAt > entry.updatedAt ||
        (entry.passwordChangedAt !== null && (entry.passwordChangedAt < entry.createdAt || entry.passwordChangedAt > entry.updatedAt))) throw new Error("invalid entry");
  }
  return value as PasswordEntry[];
}

export function encodeBackupV1(entries: PasswordEntry[], key: Buffer, salt: Buffer): string {
  return encodeBackupVersion(entries, key, salt, 1);
}
export function encodeBackupVersion(entries: readonly unknown[], key: Buffer, salt: Buffer, version: 1 | 2): string {
  if (entries.length > INPUT_LIMITS.entries) throw new HttpError(400, "バックアップは10000件まで対応しています");
  const plaintext = Buffer.from(JSON.stringify({ version, entries }));
  try {
    if (plaintext.length > INPUT_LIMITS.backupPlaintextBytes) throw new HttpError(400, "バックアップ可能な容量を超えています（内容は11 MiBまで）");
    const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
    cipher.setAAD(aad(version));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return JSON.stringify({ format: "CIPHER-VAULT", version, kdf: KDF, cipher: "aes-256-gcm", salt: salt.toString("base64"),
      iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), data: ciphertext.toString("base64") });
  } finally { plaintext.fill(0); }
}

export function parseBackupV1(content: string): BackupEnvelopeV1 {
  return parseBackupVersion(content, 1);
}
export function parseBackupVersion(content: string, version: 1 | 2): BackupEnvelopeV1 {
  try {
    if (typeof content !== "string" || Buffer.byteLength(content) > INPUT_LIMITS.backupFileBytes) throw new Error("oversized file");
    const envelope = parseRecord(JSON.parse(content), ["format", "version", "kdf", "cipher", "salt", "iv", "tag", "data"]);
    if (envelope.format !== "CIPHER-VAULT" || envelope.version !== version || envelope.kdf !== KDF || envelope.cipher !== "aes-256-gcm") throw new Error("unsupported format");
    const result = { salt: decodeBase64(envelope.salt, 16), iv: decodeBase64(envelope.iv, 12), tag: decodeBase64(envelope.tag, 16), data: decodeBase64(envelope.data) };
    if (result.data.length > INPUT_LIMITS.backupPlaintextBytes) throw new Error("oversized data");
    return result;
  } catch { throw new HttpError(400, "未対応または破損したバックアップファイルです"); }
}

export function decodeBackupV1(envelope: BackupEnvelopeV1, key: Buffer): PasswordEntry[] {
  try { return validateBackupEntries(decodeBackupVersion(envelope, key, 1)); }
  catch { throw new HttpError(400, "パスフレーズが違うか、バックアップファイルが破損しています"); }
}
export function decodeBackupVersion(envelope: BackupEnvelopeV1, key: Buffer, version: 1 | 2): unknown {
  let plaintext: Buffer | undefined, partial: Buffer | undefined, tail: Buffer | undefined;
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, envelope.iv, { authTagLength: 16 });
    decipher.setAAD(aad(version)); decipher.setAuthTag(envelope.tag);
    partial = decipher.update(envelope.data); tail = decipher.final(); plaintext = Buffer.concat([partial, tail]);
    const decoded = parseRecord(JSON.parse(plaintext.toString("utf8")), ["version", "entries"]);
    if (decoded.version !== version) throw new Error("unsupported payload");
    return decoded.entries;
  } catch { throw new HttpError(400, "パスフレーズが違うか、バックアップファイルが破損しています"); }
  finally { partial?.fill(0); tail?.fill(0); plaintext?.fill(0); }
}
