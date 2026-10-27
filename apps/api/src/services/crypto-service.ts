import { createCipheriv, createDecipheriv, createHmac, randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { vaultSession } from "./vault-session.js";

const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const VERIFIER_LABEL = "CIPHER VAULT password verifier v1";
// Pin the original Node defaults. Salt remains the stored Base64 STRING, not decoded bytes.
const LEGACY_SCRYPT_OPTIONS = { N: 16384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 };

export function getVaultSession() { return vaultSession.getState().sessionId; }

export function createPasswordSalt() {
  return randomBytes(16).toString("base64");
}

export function deriveVaultKey(masterPassword: string, salt: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(masterPassword, salt, KEY_LENGTH, LEGACY_SCRYPT_OPTIONS, (error, key) => {
      if (error) reject(error); else resolve(key);
    });
  });
}

export function deriveVerifier(vaultKey: Buffer) {
  return createHmac("sha256", vaultKey).update(VERIFIER_LABEL).digest("base64");
}

export function verifyVaultKey(
  vaultKey: Buffer,
  expectedVerifier: string,
  legacy = false
) {
  const actual = legacy ? vaultKey : Buffer.from(deriveVerifier(vaultKey), "base64");
  const expected = Buffer.from(expectedVerifier, "base64");
  try {
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } finally {
    // The caller owns the derived key and wipes it after activation or rejection.
    if (!legacy) actual.fill(0);
    expected.fill(0);
  }
}

export function setActiveVaultKey(key: Buffer) {
  vaultSession.unlock(key);
}

export function clearActiveVaultKey() {
  vaultSession.lock();
}

export function hasActiveVaultKey() {
  return vaultSession.getState().isUnlocked;
}

function requireActiveVaultKey() {
  return vaultSession.requireKey();
}

export function encryptSecret(plainText: string) {
  const session = vaultSession.requireUnlocked();
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv("aes-256-gcm", requireActiveVaultKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plainText, "utf-8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const payload = Buffer.concat([iv, authTag, encrypted]).toString("base64");
  vaultSession.requireUnlocked(session);
  return payload;
}

export function decryptSecret(payload: string) {
  const session = vaultSession.requireUnlocked();
  const buffer = Buffer.from(payload, "base64");
  const iv = buffer.subarray(0, IV_LENGTH);
  const authTag = buffer.subarray(IV_LENGTH, IV_LENGTH + 16);
  const encrypted = buffer.subarray(IV_LENGTH + 16);
  const decipher = createDecipheriv("aes-256-gcm", requireActiveVaultKey(), iv);
  decipher.setAuthTag(authTag);

  const plaintext = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf-8");
  vaultSession.requireUnlocked(session);
  return plaintext;
}
