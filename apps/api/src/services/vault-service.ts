import type { VaultLockReason, VaultStatus } from "@password-manager/shared/types";
import { HttpError } from "../lib/errors.js";
import {
  createPasswordSalt,
  deriveVerifier,
  deriveVaultKey,
  setActiveVaultKey,
  verifyVaultKey
} from "./crypto-service.js";
import { getVaultMetadata, resetVaultData, saveVaultMetadata } from "./vault-store.js";
import { requireSessionId, vaultSession } from "./vault-session.js";
import { vaultUnlockGuard } from "./vault-unlock-guard.js";
import { parseMasterPassword, parseResetPayload } from "../lib/input-validation.js";
import { assertVaultStorage, isV2Vault, isVaultContextFailed } from "../db/vault-context.js";
import { unlockV2Vault } from "./v2-vault-service.js";

function isConfigured() { return isV2Vault() || isVaultContextFailed() || getVaultMetadata() !== null; }

export function getVaultStatus() {
  return {
    isConfigured: isConfigured(),
    ...vaultSession.getState()
  };
}

export async function setupVault(payload: unknown) {
  assertVaultStorage();
  if (isConfigured()) {
    throw new HttpError(409, "保管庫はすでに設定済みです");
  }

  const masterPassword = parseMasterPassword(payload, true);

  const intent = vaultSession.getState().sessionId;
  return vaultUnlockGuard.run(async () => {
    const salt = createPasswordSalt();
    const vaultKey = await deriveVaultKey(masterPassword, salt);

    try {
      vaultSession.requireGeneration(intent);
      assertVaultStorage();
      const now = new Date().toISOString();
      saveVaultMetadata({
        id: 1,
        passwordSalt: salt,
        passwordVerifier: deriveVerifier(vaultKey),
        kdfParams: JSON.stringify({ algorithm: "scrypt", keyLength: 32, verifierAlgorithm: "hmac-sha256-v1" }),
        createdAt: now,
        updatedAt: now
      });

      setActiveVaultKey(vaultKey);
    } finally {
      vaultKey.fill(0);
    }
    return getVaultStatus();
  });
}

export async function unlockVault(payload: unknown) {
  assertVaultStorage();
  if (isV2Vault()) { await unlockV2Vault(payload); return getVaultStatus(); }
  const masterPassword = parseMasterPassword(payload, false);
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
  const intent = vaultSession.getState().sessionId;

  return vaultUnlockGuard.run(async () => {
    const vaultKey = await deriveVaultKey(masterPassword, metadata.passwordSalt);
    try {
      vaultSession.requireGeneration(intent);
      assertVaultStorage();
      if (!verifyVaultKey(vaultKey, metadata.passwordVerifier, legacy)) {
        throw new HttpError(401, "マスターパスワードが正しくありません");
      }
      if (legacy) {
        saveVaultMetadata({
          ...metadata,
          passwordVerifier: deriveVerifier(vaultKey),
          kdfParams: JSON.stringify({ ...params, verifierAlgorithm: "hmac-sha256-v1" }),
          updatedAt: new Date().toISOString()
        });
      }
      setActiveVaultKey(vaultKey);
    } finally {
      vaultKey.fill(0);
    }
    return getVaultStatus();
  });
}

export function lockVault(reason: VaultLockReason = "manual") {
  vaultSession.lock(reason);
  return getVaultStatus();
}

export function lockVaultForSession(sessionId: unknown) {
  vaultSession.requireGeneration(sessionId);
  return lockVault();
}

export function recordVaultActivity(sessionId: unknown) {
  vaultSession.recordActivity(requireSessionId(sessionId));
  return getVaultStatus();
}

export function onVaultState(listener: (state: VaultStatus) => void) {
  return vaultSession.subscribe((state) => listener({ isConfigured: isConfigured(), ...state }));
}

export function resetVault(payload: unknown) {
  parseResetPayload(payload);
  assertVaultStorage();

  vaultSession.lock("reset");
  if (isV2Vault()) throw new HttpError(409, "この保管庫の初期化は現在利用できません");
  resetVaultData();

  return getVaultStatus();
}
