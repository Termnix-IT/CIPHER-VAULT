import { createCipheriv, createDecipheriv, createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

const KEY_LENGTH = 32;
const IV_LENGTH = 12;

let activeVaultKey: Buffer | null = null;

export function createPasswordSalt() {
  return randomBytes(16).toString("base64");
}

export function deriveVaultKey(masterPassword: string, salt: string) {
  return scryptSync(masterPassword, salt, KEY_LENGTH);
}

export function deriveVerifier(masterPassword: string, salt: string) {
  const key = deriveVaultKey(masterPassword, salt);
  try {
    return createHmac("sha256", key).update("CIPHER VAULT password verifier v1").digest("base64");
  } finally {
    key.fill(0);
  }
}

export function verifyMasterPassword(
  masterPassword: string,
  salt: string,
  expectedVerifier: string,
  legacy = false
) {
  const actual = legacy ? deriveVaultKey(masterPassword, salt) : Buffer.from(deriveVerifier(masterPassword, salt), "base64");
  const expected = Buffer.from(expectedVerifier, "base64");
  try {
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } finally {
    actual.fill(0);
    expected.fill(0);
  }
}

export function setActiveVaultKey(key: Buffer) {
  clearActiveVaultKey();
  activeVaultKey = Buffer.from(key);
}

export function clearActiveVaultKey() {
  activeVaultKey?.fill(0);
  activeVaultKey = null;
}

export function hasActiveVaultKey() {
  return activeVaultKey !== null;
}

function requireActiveVaultKey() {
  if (activeVaultKey === null) {
    throw new Error("保管庫の鍵が利用できません");
  }

  return activeVaultKey;
}

export function encryptSecret(plainText: string) {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv("aes-256-gcm", requireActiveVaultKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plainText, "utf-8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([iv, authTag, encrypted]).toString("base64");
}

export function decryptSecret(payload: string) {
  const buffer = Buffer.from(payload, "base64");
  const iv = buffer.subarray(0, IV_LENGTH);
  const authTag = buffer.subarray(IV_LENGTH, IV_LENGTH + 16);
  const encrypted = buffer.subarray(IV_LENGTH + 16);
  const decipher = createDecipheriv("aes-256-gcm", requireActiveVaultKey(), iv);
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf-8");
}
