import { randomBytes } from "node:crypto";
import { vaultSession } from "./vault-session.js";
import { decryptLegacySecret, encryptLegacySecret } from "../crypto/legacy-codec.js";
export { deriveVaultKey, deriveVerifier, verifyVaultKey } from "../crypto/legacy-codec.js";

export function getVaultSession() { return vaultSession.getState().sessionId; }

export function createPasswordSalt() {
  return randomBytes(16).toString("base64");
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
  const payload = encryptLegacySecret(requireActiveVaultKey(), plainText);
  vaultSession.requireUnlocked(session);
  return payload;
}

export function decryptSecret(payload: string) {
  const session = vaultSession.requireUnlocked();
  const plaintext = decryptLegacySecret(requireActiveVaultKey(), payload);
  try { vaultSession.requireUnlocked(session); return plaintext.toString("utf8"); }
  finally { plaintext.fill(0); }
}
