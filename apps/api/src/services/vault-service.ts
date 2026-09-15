import type { VaultResetPayload, VaultSetupPayload, VaultUnlockPayload } from "@password-manager/shared/types";
import { HttpError } from "../lib/errors.js";
import {
  clearActiveVaultKey,
  createPasswordSalt,
  deriveVerifier,
  deriveVaultKey,
  setActiveVaultKey,
  verifyMasterPassword
} from "./crypto-service.js";
import { getVaultMetadata, resetVaultData, saveVaultMetadata } from "./vault-store.js";

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

  if (typeof payload?.masterPassword !== "string" || payload.masterPassword.length < 12) {
    throw new HttpError(400, "マスターパスワードは12文字以上で入力してください");
  }

  const salt = createPasswordSalt();
  const now = new Date().toISOString();
  const vaultKey = deriveVaultKey(payload.masterPassword, salt);

  try {
    saveVaultMetadata({
      id: 1,
      passwordSalt: salt,
      passwordVerifier: deriveVerifier(payload.masterPassword, salt),
      kdfParams: JSON.stringify({ algorithm: "scrypt", keyLength: 32, verifierAlgorithm: "hmac-sha256-v1" }),
      createdAt: now,
      updatedAt: now
    });

    setActiveVaultKey(vaultKey);
  } finally {
    vaultKey.fill(0);
  }
  isUnlocked = true;

  return {
    isConfigured: true,
    isUnlocked
  };
}

export function unlockVault(payload: VaultUnlockPayload) {
  if (typeof payload?.masterPassword !== "string") {
    throw new HttpError(400, "マスターパスワードを文字列で入力してください");
  }
  const metadata = getVaultMetadata();

  if (metadata === null) {
    throw new HttpError(400, "保管庫はまだ設定されていません");
  }

  let params;
  try {
    params = JSON.parse(metadata.kdfParams);
  } catch {
    throw new HttpError(400, "保管庫の形式情報が壊れています");
  }
  if (params?.algorithm !== "scrypt" || params.keyLength !== 32 ||
      (params.verifierAlgorithm !== undefined && params.verifierAlgorithm !== "hmac-sha256-v1")) {
    throw new HttpError(400, "未対応の保管庫形式です");
  }
  const legacy = params.verifierAlgorithm === undefined;
  if (!verifyMasterPassword(payload.masterPassword, metadata.passwordSalt, metadata.passwordVerifier, legacy)) {
    throw new HttpError(401, "マスターパスワードが正しくありません");
  }

  const vaultKey = deriveVaultKey(payload.masterPassword, metadata.passwordSalt);
  try {
    if (legacy) {
      saveVaultMetadata({
        ...metadata,
        passwordVerifier: deriveVerifier(payload.masterPassword, metadata.passwordSalt),
        kdfParams: JSON.stringify({ ...params, verifierAlgorithm: "hmac-sha256-v1" }),
        updatedAt: new Date().toISOString()
      });
    }
    setActiveVaultKey(vaultKey);
  } finally {
    vaultKey.fill(0);
  }
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

export function resetVault(payload: VaultResetPayload) {
  if (payload?.confirmation !== "RESET_ALL_DATA") {
    throw new HttpError(400, "保管庫のリセット確認が必要です");
  }

  clearActiveVaultKey();
  isUnlocked = false;
  resetVaultData();

  return {
    isConfigured: false,
    isUnlocked: false
  };
}
