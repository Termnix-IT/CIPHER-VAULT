import { createCipheriv, createDecipheriv, hkdfSync, randomBytes, scrypt } from "node:crypto";
import {
  V2_CIPHER, V2_LIMITS, V2_PROFILE, VaultCodecError, copyPlaintext, decodeBase64, entryAad,
  parseEntryContext, parseEntryEnvelope, parsePasswordSlotContext, parsePasswordSlotEnvelope,
  passwordSlotAad, record, validateEntryPlaintext
} from "./v2-format.js";
import type { EntryContext, EntryEnvelope, PasswordSlotContext, PasswordSlotEnvelope } from "./v2-format.js";
export { V2_LIMITS, V2_PROFILE, VaultCodecError, entryAad, passwordSlotAad, parseEntryEnvelope, parsePasswordSlotEnvelope } from "./v2-format.js";
export type { EntryContext, EntryEnvelope, PasswordSlotContext, PasswordSlotEnvelope } from "./v2-format.js";

export type CodecOptions = { signal?: AbortSignal };
// A true result must mean that this nonce is durably reserved, even if the write later fails.
export type ReserveNonce = (keyId: string, iv: Buffer) => boolean | Promise<boolean>;
let deriving = false;

function signalFrom(options: CodecOptions): AbortSignal | undefined {
  const value = record(options, ["signal"], []);
  if (value.signal !== undefined && !(value.signal instanceof AbortSignal)) throw new VaultCodecError("INVALID_INPUT");
  return value.signal as AbortSignal | undefined;
}
function active(signal?: AbortSignal) { if (signal?.aborted) throw new VaultCodecError("CANCELLED"); }
function keyCopy(value: Buffer): Buffer {
  if (!Buffer.isBuffer(value) || value.length !== 32) throw new VaultCodecError("INVALID_INPUT");
  return Buffer.from(value);
}
function freshBytes(length: number): Buffer {
  try { return randomBytes(length); } catch { throw new VaultCodecError("CRYPTO_FAILED"); }
}
function derivedKey(key: Buffer, vaultId: string, purpose: "entry" | "password-wrap") {
  try { return Buffer.from(hkdfSync("sha256", key, Buffer.from(vaultId.replace(/-/g, ""), "hex"), `CIPHER-VAULT/v2/${purpose}`, 32)); }
  catch { throw new VaultCodecError("CRYPTO_FAILED"); }
}
function authenticateContext(actual: EntryContext | PasswordSlotContext, expected: EntryContext | PasswordSlotContext) {
  for (const [field, value] of Object.entries(expected)) {
    if (Reflect.get(actual, field) !== value) throw new VaultCodecError("AUTHENTICATION_FAILED");
  }
}
function encrypt(key: Buffer, iv: Buffer, plaintext: Buffer, aad: Buffer) {
  try {
    const cipher = createCipheriv(V2_CIPHER, key, iv, { authTagLength: 16 });
    cipher.setAAD(aad);
    const data = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return { iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), data: data.toString("base64") };
  } catch { throw new VaultCodecError("CRYPTO_FAILED"); }
}
function decrypt(key: Buffer, envelope: { iv: string; tag: string; data: string }, aad: Buffer): Buffer {
  let partial: Buffer | undefined, tail: Buffer | undefined;
  try {
    const decipher = createDecipheriv(V2_CIPHER, key, Buffer.from(envelope.iv, "base64"), { authTagLength: 16 });
    decipher.setAAD(aad); decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
    partial = decipher.update(Buffer.from(envelope.data, "base64"));
    tail = decipher.final();
    return Buffer.concat([partial, tail]);
  } catch { throw new VaultCodecError("AUTHENTICATION_FAILED"); }
  finally { partial?.fill(0); tail?.fill(0); }
}

async function withPasswordKey<T>(password: unknown, salt: Buffer, vaultId: string, signal: AbortSignal | undefined,
  action: (key: Buffer) => T, setup = false): Promise<T> {
  active(signal);
  if (typeof password !== "string" || password.length > V2_LIMITS.passwordBytes ||
      Buffer.byteLength(password, "utf8") > V2_LIMITS.passwordBytes || (setup && password.length < 12)) throw new VaultCodecError("INVALID_INPUT");
  if (deriving) throw new VaultCodecError("BUSY");
  let encoded: Buffer;
  try { encoded = copyPlaintext(password, V2_LIMITS.passwordBytes); }
  catch { throw new VaultCodecError("INVALID_INPUT"); }
  deriving = true;
  let kdf: Buffer | undefined, kek: Buffer | undefined, result: T | undefined;
  try {
    kdf = await new Promise<Buffer>((resolve, reject) => {
      scrypt(encoded, salt, 32, { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 }, (error, key) => {
        if (error) { key?.fill(0); reject(new VaultCodecError("CRYPTO_FAILED")); } else resolve(key);
      });
    });
    active(signal);
    kek = derivedKey(kdf, vaultId, "password-wrap");
    result = action(kek);
    active(signal);
    return result;
  } catch (error) {
    if (Buffer.isBuffer(result)) result.fill(0);
    if (error instanceof VaultCodecError) throw error;
    throw new VaultCodecError("CRYPTO_FAILED");
  } finally { encoded.fill(0); kdf?.fill(0); kek?.fill(0); salt.fill(0); deriving = false; }
}

export function createRootKey(): Buffer { return freshBytes(32); }

export async function wrapRootKey(root: Buffer, password: unknown, contextInput: PasswordSlotContext,
  options: CodecOptions = {}): Promise<PasswordSlotEnvelope> {
  const context = parsePasswordSlotContext(contextInput), signal = signalFrom(options);
  active(signal);
  const snapshot = keyCopy(root);
  try {
    const salt = freshBytes(16);
    const kdf = Object.freeze({ profile: V2_PROFILE, salt: salt.toString("base64") });
    return await withPasswordKey(password, salt, context.vaultId, signal, key => Object.freeze({
      cryptoVersion: 2, cipher: V2_CIPHER, ...context, slotId: "password", kdf,
      ...encrypt(key, freshBytes(12), snapshot, passwordSlotAad(context, kdf))
    }), true);
  } finally { snapshot.fill(0); }
}

export async function unwrapRootKey(input: unknown, password: unknown, expectedInput: PasswordSlotContext,
  options: CodecOptions = {}): Promise<Buffer> {
  const envelope = parsePasswordSlotEnvelope(input), expected = parsePasswordSlotContext(expectedInput), signal = signalFrom(options);
  active(signal); authenticateContext(envelope, expected);
  return withPasswordKey(password, decodeBase64(envelope.kdf.salt, 16, 16), expected.vaultId, signal,
    key => decrypt(key, envelope, passwordSlotAad(expected, envelope.kdf)));
}

export async function sealEntry(root: Buffer, plaintextInput: string | Buffer, contextInput: EntryContext,
  reserveNonce: ReserveNonce, options: CodecOptions = {}): Promise<EntryEnvelope> {
  const context = parseEntryContext(contextInput), signal = signalFrom(options);
  active(signal);
  if (typeof reserveNonce !== "function") throw new VaultCodecError("INVALID_INPUT");
  const snapshot = keyCopy(root);
  let plaintext: Buffer | undefined, key: Buffer | undefined;
  try {
    plaintext = copyPlaintext(plaintextInput); validateEntryPlaintext(plaintext, context.entryId);
    let iv: Buffer | undefined;
    for (let attempt = 0; attempt < 8; attempt++) {
      active(signal);
      const candidate = freshBytes(12);
      let reserved;
      try { reserved = await reserveNonce(context.keyId, Buffer.from(candidate)); }
      catch { active(signal); throw new VaultCodecError("NONCE_UNAVAILABLE"); }
      active(signal);
      if (reserved === true) { iv = candidate; break; }
      if (reserved !== false) throw new VaultCodecError("NONCE_UNAVAILABLE");
    }
    if (!iv) throw new VaultCodecError("NONCE_UNAVAILABLE");
    key = derivedKey(snapshot, context.vaultId, "entry");
    const result = Object.freeze({ cryptoVersion: 2 as const, cipher: V2_CIPHER, ...context, ...encrypt(key, iv, plaintext, entryAad(context)) });
    active(signal);
    return result;
  } finally { snapshot.fill(0); plaintext?.fill(0); key?.fill(0); }
}

export function openEntry(root: Buffer, input: unknown, expectedInput: EntryContext, options: CodecOptions = {}): Buffer {
  const envelope = parseEntryEnvelope(input), expected = parseEntryContext(expectedInput), signal = signalFrom(options);
  active(signal); authenticateContext(envelope, expected);
  const snapshot = keyCopy(root);
  let key: Buffer | undefined, plaintext: Buffer | undefined;
  try {
    key = derivedKey(snapshot, expected.vaultId, "entry");
    plaintext = decrypt(key, envelope, entryAad(expected));
    validateEntryPlaintext(plaintext, expected.entryId); active(signal);
    return plaintext;
  } catch (error) { plaintext?.fill(0); throw error; }
  finally { snapshot.fill(0); key?.fill(0); }
}
