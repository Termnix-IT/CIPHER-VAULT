import { createCipheriv, createDecipheriv, createHmac, randomBytes, scrypt, timingSafeEqual } from "node:crypto";

const LEGACY_SCRYPT_OPTIONS = { N: 16384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 };
const VERIFIER_LABEL = "CIPHER VAULT password verifier v1";

// The original Base64 Salt STRING is the KDF input, never its decoded bytes.
export function deriveVaultKey(masterPassword: string | Buffer, salt: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(masterPassword, salt, 32, LEGACY_SCRYPT_OPTIONS, (error, key) => {
      if (error) { key?.fill(0); reject(error); } else resolve(key);
    });
  });
}

export function deriveVerifier(key: Buffer) {
  return createHmac("sha256", key).update(VERIFIER_LABEL).digest("base64");
}

export function verifyVaultKey(key: Buffer, verifier: string, legacy = false) {
  const actual = legacy ? key : Buffer.from(deriveVerifier(key), "base64");
  const expected = Buffer.from(verifier, "base64");
  try { return actual.length === expected.length && timingSafeEqual(actual, expected); }
  finally { if (!legacy) actual.fill(0); expected.fill(0); }
}

export function encryptLegacySecret(key: Buffer, plaintext: string) {
  const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString("base64");
}

/** Return authenticated bytes; text decoding policy belongs to the reader. */
export function decryptLegacySecret(key: Buffer, payload: string): Buffer {
  const bytes = Buffer.from(payload, "base64");
  let partial: Buffer | undefined, tail: Buffer | undefined;
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, bytes.subarray(0, 12), { authTagLength: 16 });
    decipher.setAuthTag(bytes.subarray(12, 28));
    partial = decipher.update(bytes.subarray(28)); tail = decipher.final();
    return Buffer.concat([partial, tail]);
  } finally { partial?.fill(0); tail?.fill(0); }
}
