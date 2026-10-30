import { TextDecoder } from "node:util";
import { validateAdditionalEntry } from "../lib/vault-entry-validation.js";

export const V2_PROFILE = "scrypt-n17-r8-p1-k32";
export const V2_CIPHER = "aes-256-gcm";
export const V2_LIMITS = Object.freeze({ envelopeBytes: 16 * 1024 * 1024, plaintextBytes: 11 * 1024 * 1024,
  passwordBytes: 1024 * 1024, idBytes: 128, maxRevision: 0xffffffff });

type ErrorCode = "INVALID_FORMAT" | "INVALID_INPUT" | "AUTHENTICATION_FAILED" | "CRYPTO_FAILED" | "BUSY" | "CANCELLED" | "NONCE_UNAVAILABLE";
const messages: Record<ErrorCode, string> = {
  INVALID_FORMAT: "Invalid v2 format", INVALID_INPUT: "Invalid v2 input", AUTHENTICATION_FAILED: "V2 authentication failed",
  CRYPTO_FAILED: "V2 cryptographic operation failed", BUSY: "V2 key derivation is busy", CANCELLED: "V2 operation cancelled",
  NONCE_UNAVAILABLE: "V2 nonce reservation failed"
};
export class VaultCodecError extends Error {
  constructor(readonly code: ErrorCode) { super(messages[code]); this.name = "VaultCodecError"; }
}

export type EntryContext = Readonly<{ vaultId: string; keyId: string; entryId: string; revision: number }>;
export type PasswordSlotContext = Readonly<{ vaultId: string; keyId: string; slotRevision: number }>;
export type PasswordKdf = Readonly<{ profile: typeof V2_PROFILE; salt: string }>;
type Sealed = Readonly<{ iv: string; tag: string; data: string }>;
export type EntryEnvelope = EntryContext & Sealed & Readonly<{ cryptoVersion: 2; cipher: typeof V2_CIPHER }>;
export type PasswordSlotEnvelope = PasswordSlotContext & Sealed & Readonly<{
  cryptoVersion: 2; cipher: typeof V2_CIPHER; slotId: "password"; kdf: PasswordKdf
}>;

function invalid(): never { throw new VaultCodecError("INVALID_FORMAT"); }

export function record(value: unknown, fields: readonly string[], required = fields): Record<string, unknown> {
  if (value === null || typeof value !== "object" || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  const keys = Reflect.ownKeys(value);
  if (keys.length > fields.length || required.some(field => !Object.prototype.hasOwnProperty.call(value, field))) invalid();
  const result: Record<string, unknown> = Object.create(null);
  for (const key of keys) {
    if (typeof key !== "string" || !fields.includes(key)) invalid();
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!("value" in descriptor)) invalid();
    result[key] = descriptor.value;
  }
  return result;
}

function unicodeText(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const encoded = Buffer.from(value, "utf8");
  try { return encoded.toString("utf8") === value; } finally { encoded.fill(0); }
}

function uuid(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)) invalid();
  return value;
}

function revision(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > V2_LIMITS.maxRevision) invalid();
  return value;
}

function entryId(value: unknown): string {
  if (typeof value !== "string" || !value || value.length > V2_LIMITS.idBytes || value.includes("\0") ||
      Buffer.byteLength(value, "utf8") > V2_LIMITS.idBytes || !unicodeText(value)) invalid();
  return value;
}

export function parseEntryContext(input: unknown): EntryContext {
  const value = record(input, ["vaultId", "keyId", "entryId", "revision"]);
  return Object.freeze({ vaultId: uuid(value.vaultId), keyId: uuid(value.keyId), entryId: entryId(value.entryId), revision: revision(value.revision) });
}

export function parsePasswordSlotContext(input: unknown): PasswordSlotContext {
  const value = record(input, ["vaultId", "keyId", "slotRevision"]);
  return Object.freeze({ vaultId: uuid(value.vaultId), keyId: uuid(value.keyId), slotRevision: revision(value.slotRevision) });
}

export function decodeBase64(value: unknown, maxBytes: number, exactBytes?: number): Buffer {
  if (typeof value !== "string" || value.length > 4 * Math.ceil(maxBytes / 3) || value.length % 4 !== 0 ||
      !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) invalid();
  const bytes = Buffer.from(value, "base64");
  if (bytes.length > maxBytes || (exactBytes !== undefined && bytes.length !== exactBytes) || bytes.toString("base64") !== value) invalid();
  return bytes;
}

export function parsePasswordKdf(input: unknown): PasswordKdf {
  const value = record(input, ["profile", "salt"]);
  if (value.profile !== V2_PROFILE) invalid();
  decodeBase64(value.salt, 16, 16);
  return Object.freeze({ profile: V2_PROFILE, salt: value.salt as string });
}

function envelopeValue(input: unknown): unknown {
  if (typeof input !== "string" && !Buffer.isBuffer(input)) return input;
  const bytes = copyPlaintext(input, V2_LIMITS.envelopeBytes);
  try { return JSON.parse(decodeUtf8(bytes)); } catch { return invalid(); } finally { bytes.fill(0); }
}

export function parseEntryEnvelope(input: unknown): EntryEnvelope {
  const value = record(envelopeValue(input), ["cryptoVersion", "cipher", "vaultId", "keyId", "entryId", "revision", "iv", "tag", "data"]);
  if (value.cryptoVersion !== 2 || value.cipher !== V2_CIPHER) invalid();
  const context = parseEntryContext({ vaultId: value.vaultId, keyId: value.keyId, entryId: value.entryId, revision: value.revision });
  decodeBase64(value.iv, 12, 12); decodeBase64(value.tag, 16, 16);
  if (!decodeBase64(value.data, V2_LIMITS.plaintextBytes).length) invalid();
  return Object.freeze({ cryptoVersion: 2, cipher: V2_CIPHER, ...context, iv: value.iv as string, tag: value.tag as string, data: value.data as string });
}

export function parsePasswordSlotEnvelope(input: unknown): PasswordSlotEnvelope {
  const value = record(envelopeValue(input), ["cryptoVersion", "cipher", "vaultId", "keyId", "slotId", "slotRevision", "kdf", "iv", "tag", "data"]);
  if (value.cryptoVersion !== 2 || value.cipher !== V2_CIPHER || value.slotId !== "password") invalid();
  const context = parsePasswordSlotContext({ vaultId: value.vaultId, keyId: value.keyId, slotRevision: value.slotRevision });
  const kdf = parsePasswordKdf(value.kdf);
  decodeBase64(value.iv, 12, 12); decodeBase64(value.tag, 16, 16); decodeBase64(value.data, 32, 32);
  return Object.freeze({ cryptoVersion: 2, cipher: V2_CIPHER, ...context, slotId: "password", kdf,
    iv: value.iv as string, tag: value.tag as string, data: value.data as string });
}

export function entryAad(input: unknown): Buffer {
  const value = parseEntryContext(input);
  return Buffer.from(JSON.stringify(["CIPHER-VAULT", 2, "entry", value.vaultId, value.keyId,
    Buffer.from(value.entryId, "utf8").toString("hex"), value.revision]), "utf8");
}

export function passwordSlotAad(input: unknown, kdfInput: unknown): Buffer {
  const value = parsePasswordSlotContext(input), kdf = parsePasswordKdf(kdfInput);
  return Buffer.from(JSON.stringify(["CIPHER-VAULT", 2, "password-slot", value.vaultId, value.keyId,
    "password", value.slotRevision, kdf.profile, kdf.salt]), "utf8");
}

export function copyPlaintext(value: unknown, maxBytes = V2_LIMITS.plaintextBytes): Buffer {
  if (typeof value === "string") {
    if (value.length > maxBytes || Buffer.byteLength(value, "utf8") > maxBytes) invalid();
    const bytes = Buffer.from(value, "utf8");
    if (bytes.toString("utf8") === value) return bytes;
    bytes.fill(0); invalid();
  }
  if (!Buffer.isBuffer(value) || value.length > maxBytes) invalid();
  return Buffer.from(value);
}

function decodeUtf8(value: Buffer) {
  // Keep a BOM in the text so JSON.parse rejects it consistently with string input.
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(value);
}

export function validateEntryPlaintext(plaintext: Buffer, expectedId: string) {
  try {
    const decoded = JSON.parse(decodeUtf8(plaintext));
    if (decoded?.type === "apiKey" || decoded?.type === "creditCard") { validateAdditionalEntry(decoded, expectedId); return; }
    const value = record(decoded, ["id", "serviceName", "loginId", "password", "notes", "url", "tags", "group", "createdAt", "updatedAt", "passwordChangedAt"]);
    if (value.id !== expectedId) invalid();
    for (const field of ["serviceName", "loginId", "password", "notes", "url"]) if (!unicodeText(value[field])) invalid();
    if (!(value.serviceName as string).trim() || !(value.loginId as string).trim() || !value.password) invalid();
    if (!(value.group === null || unicodeText(value.group)) || !Array.isArray(value.tags) || !value.tags.every(unicodeText)) invalid();
    const validDate = (date: unknown): date is string => typeof date === "string" && Number.isFinite(Date.parse(date)) && new Date(date).toISOString() === date;
    if (!validDate(value.createdAt) || !validDate(value.updatedAt) || value.createdAt > value.updatedAt ||
        !(value.passwordChangedAt === null || (validDate(value.passwordChangedAt) && value.passwordChangedAt >= value.createdAt && value.passwordChangedAt <= value.updatedAt))) invalid();
  } catch { invalid(); }
}
