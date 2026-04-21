import type { VaultSetupPayload, VaultUnlockPayload } from "@password-manager/shared/types";
import { HttpError } from "../lib/errors.js";
import {
  clearActiveVaultKey,
  createPasswordSalt,
  deriveVerifier,
  deriveVaultKey,
  setActiveVaultKey,
  verifyMasterPassword
} from "./crypto-service.js";
import { getVaultMetadata, saveVaultMetadata } from "./vault-store.js";

let isUnlocked = false;

export function getVaultStatus() {
  return {
    isConfigured: getVaultMetadata() !== null,
    isUnlocked
  };
}

export function setupVault(payload: VaultSetupPayload) {
  if (getVaultMetadata() !== null) {
    throw new HttpError(409, "保管庫はすでに設定済みです");
  }

  if (!payload.masterPassword || payload.masterPassword.length < 12) {
    throw new HttpError(400, "マスターパスワードは12文字以上で入力してください");
  }

  const salt = createPasswordSalt();
  const now = new Date().toISOString();
  const vaultKey = deriveVaultKey(payload.masterPassword, salt);

  saveVaultMetadata({
    id: 1,
    passwordSalt: salt,
    passwordVerifier: deriveVerifier(payload.masterPassword, salt),
    kdfParams: JSON.stringify({ algorithm: "scrypt", keyLength: 32 }),
    createdAt: now,
    updatedAt: now
  });

  setActiveVaultKey(vaultKey);
  isUnlocked = true;

  return {
    isConfigured: true,
    isUnlocked
  };
}

export function unlockVault(payload: VaultUnlockPayload) {
  const metadata = getVaultMetadata();

  if (metadata === null) {
    throw new HttpError(400, "保管庫はまだ設定されていません");
  }

  if (!verifyMasterPassword(payload.masterPassword, metadata.passwordSalt, metadata.passwordVerifier)) {
    throw new HttpError(401, "マスターパスワードが正しくありません");
  }

  setActiveVaultKey(deriveVaultKey(payload.masterPassword, metadata.passwordSalt));
  isUnlocked = true;

  return {
    isUnlocked
  };
}

export function lockVault() {
  clearActiveVaultKey();
  isUnlocked = false;

  return {
    isUnlocked
  };
}
