import type {
  BackupExportPayload, BackupRestorePayload, BackupFile, SecurityAudit,
  PasswordGenerationOptions, PasswordGenerationResult, PasswordManagerDesktopApi,
  PasswordEntry, PasswordEntrySummary, PasswordEntryUpsertPayload,
  VaultResetPayload, VaultSetupPayload, VaultStatus, VaultUnlockPayload, VaultMaintenancePayload
} from "@password-manager/shared/types";
import { VaultClientSession, VaultSessionChangedError } from "./vault-client-session";

const session = new VaultClientSession();

function getDesktopApi(): PasswordManagerDesktopApi | null {
  return typeof window === "undefined" ? null : window.passwordManager ?? null;
}

async function request<T>(path: string, init?: RequestInit, sessionId?: string): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set("Content-Type", "application/json");
  if (sessionId) headers.set("X-Cipher-Vault-Session", sessionId);
  if (!["GET", "HEAD", "OPTIONS"].includes((init?.method ?? "GET").toUpperCase())) {
    const { token } = await request<{ token: string }>("/vault/csrf");
    headers.set("X-Cipher-Vault-CSRF", token);
  }
  const response = await fetch(path, { ...init, signal: init?.signal ?? AbortSignal.timeout(30000), headers, credentials: "same-origin", cache: "no-store", redirect: "error" });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({})) as { error?: string };
    throw new Error(payload.error ?? "リクエストに失敗しました");
  }
  return response.status === 204 ? undefined as T : await response.json() as T;
}

async function readStatus() {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      getDesktopApi()?.fetchVaultStatus() ?? request<VaultStatus>("/vault/status", { signal: AbortSignal.timeout(5000) }),
      new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error("保管庫の状態を確認できませんでした")), 5000); })
    ]);
  } finally { clearTimeout(timer); }
}

export function fetchVaultStatus() { return session.readStatus(readStatus); }

export function runVaultMaintenance(payload: VaultMaintenancePayload) {
  return session.maintain((id) => getDesktopApi()?.runVaultMaintenance(payload, id) ?? request<VaultStatus>("/vault/maintenance",
    { method: "POST", body: JSON.stringify(payload), signal: AbortSignal.timeout(315000) }, id), readStatus);
}

export async function cancelVaultMaintenance(sourceSessionId: string) {
  const state = await fetchVaultStatus();
  if (state.sessionId !== sourceSessionId && state.maintenance?.sourceSessionId !== sourceSessionId) return { state, requested: false };
  return { state: await session.change(() => getDesktopApi()?.lockVault(state.sessionId) ?? request<VaultStatus>("/vault/lock", { method: "POST" }, state.sessionId)), requested: true };
}

export function observeVaultStatus(listener: (state: VaultStatus) => void) {
  let alive = true;
  let reading = false;
  const unsubscribe = session.subscribe(listener);
  const desktopUnsubscribe = getDesktopApi()?.onVaultState((state) => { session.observe(state); });
  const poll = async () => {
    if (reading || !alive) return;
    reading = true;
    try { await fetchVaultStatus(); }
    catch (error) { if (alive && !(error instanceof VaultSessionChangedError)) session.lockLocally(); }
    finally { reading = false; }
  };
  void poll();
  // Polling/status reads never count as activity. Desktop events give immediate updates.
  const timer = window.setInterval(() => { void poll(); }, 1000);
  const refresh = () => { void poll(); };
  window.addEventListener("focus", refresh);
  document.addEventListener("visibilitychange", refresh);
  return () => {
    alive = false;
    unsubscribe(); desktopUnsubscribe?.();
    window.clearInterval(timer);
    window.removeEventListener("focus", refresh);
    document.removeEventListener("visibilitychange", refresh);
  };
}

export function setupVault(payload: VaultSetupPayload) {
  return session.change((id) => getDesktopApi()?.setupVault(payload, id) ?? request<VaultStatus>("/vault/setup", { method: "POST", body: JSON.stringify(payload) }, id));
}
export function unlockVault(payload: VaultUnlockPayload) {
  return session.change((id) => getDesktopApi()?.unlockVault(payload, id) ?? request<VaultStatus>("/vault/unlock", { method: "POST", body: JSON.stringify(payload) }, id));
}
export function resetVault(payload: VaultResetPayload) {
  return session.change((id) => getDesktopApi()?.resetVault(payload, id) ?? request<VaultStatus>("/vault/reset", { method: "POST", body: JSON.stringify(payload) }, id));
}
export function lockVault() {
  const id = session.requireSessionId();
  session.lockLocally();
  return session.change(() => getDesktopApi()?.lockVault(id) ?? request<VaultStatus>("/vault/lock", { method: "POST" }, id));
}

function run<T>(action: (sessionId: string) => Promise<T>) { return session.run(action, readStatus); }

export function recordVaultActivity() {
  return run((id) => getDesktopApi()?.recordVaultActivity(id) ?? request<VaultStatus>("/vault/activity", { method: "POST" }, id));
}
export function fetchEntries() {
  return run((id) => getDesktopApi()?.fetchEntries(id) ?? request<{ items: PasswordEntrySummary[] }>("/entries", undefined, id));
}
export function fetchEntry(entryId: string) {
  return run((id) => getDesktopApi()?.fetchEntry(entryId, id) ?? request<PasswordEntry>(`/entries/${entryId}`, undefined, id));
}
export function createEntry(payload: PasswordEntryUpsertPayload) {
  return run((id) => getDesktopApi()?.createEntry(payload, id) ?? request<PasswordEntry>("/entries", { method: "POST", body: JSON.stringify(payload) }, id));
}
export function updateEntry(entryId: string, payload: PasswordEntryUpsertPayload) {
  return run((id) => getDesktopApi()?.updateEntry(entryId, payload, id) ?? request<PasswordEntry>(`/entries/${entryId}`, { method: "PUT", body: JSON.stringify(payload) }, id));
}
export function deleteEntry(entryId: string) {
  return run((id) => getDesktopApi()?.deleteEntry(entryId, id) ?? request<{ success: boolean }>(`/entries/${entryId}`, { method: "DELETE" }, id));
}
export function generatePassword(options: PasswordGenerationOptions = {}) {
  return run((id) => getDesktopApi()?.generatePassword(options, id) ?? request<PasswordGenerationResult>("/password/generate", { method: "POST", body: JSON.stringify(options) }, id));
}
export function exportBackup(payload: BackupExportPayload) {
  return run((id) => getDesktopApi()?.exportBackup(payload, id) ?? request<BackupFile>("/vault/backup/export", { method: "POST", body: JSON.stringify(payload) }, id));
}
export function restoreBackup(payload: BackupRestorePayload) {
  return run((id) => getDesktopApi()?.restoreBackup(payload, id) ?? request<{ restoredCount: number }>("/vault/backup/restore", { method: "POST", body: JSON.stringify(payload) }, id));
}
export function auditVault() {
  return run((id) => getDesktopApi()?.auditVault(id) ?? request<SecurityAudit>("/vault/audit", { method: "POST" }, id));
}
export function copyText(value: string) {
  return run(async (id) => {
    const desktop = getDesktopApi();
    if (desktop) return desktop.copyText(value, id);
    const state = await fetchVaultStatus();
    if (!state.isUnlocked || state.sessionId !== id) throw new VaultSessionChangedError();
    await navigator.clipboard.writeText(value);
  });
}

export function supportsLocalConnections() { return Boolean(getDesktopApi()?.getLocalConnections); }
function localConnectionCall<T>(action: (desktop: PasswordManagerDesktopApi, id: string) => Promise<T>) {
  return run(id => { const desktop = getDesktopApi(); if (!desktop?.getLocalConnections) throw new Error("接続の管理はデスクトップ版で利用できます"); return action(desktop, id); });
}
export const getLocalConnections = () => localConnectionCall((desktop, id) => desktop.getLocalConnections(id));
export const setLocalConnectionsEnabled = (enabled: boolean, revision: number) => localConnectionCall((desktop, id) => desktop.setLocalConnectionsEnabled(enabled, revision, id));
export const selectLocalPairingRequest = () => localConnectionCall((desktop, id) => desktop.selectLocalPairingRequest(id));
export const approveLocalPairing = (approval: import("@password-manager/shared/types").LocalPairingApproval) => localConnectionCall((desktop, id) => desktop.approveLocalPairing(approval, id));
export const cancelLocalPairing = (pendingId: string) => localConnectionCall((desktop, id) => desktop.cancelLocalPairing(pendingId, id));
export const revokeLocalClient = (clientId: string, revision: number) => localConnectionCall((desktop, id) => desktop.revokeLocalClient(clientId, revision, id));
export const saveLocalConnectionInfo = (clientId: string) => localConnectionCall((desktop, id) => desktop.saveLocalConnectionInfo(clientId, id));
