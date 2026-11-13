import type {
  BackupExportPayload, BackupRestorePayload, BackupFile, EntriesGroupPayload, EntryIcon, SecurityAudit,
  PasswordGenerationOptions, PasswordGenerationResult, PasswordManagerDesktopApi,
  VaultEntry, VaultEntrySummary, VaultEntryUpsertPayload,
  VaultSetupPayload, VaultStatus, VaultUnlockPayload, VaultMaintenancePayload
} from "@password-manager/shared/types";
import { VaultClientSession, VaultSessionChangedError } from "./vault-client-session";

const session = new VaultClientSession();

// The desktop app (apps/desktop/src/desktop-api.js) installs this API before the screen loads.
// Without it the screen has no vault to talk to.
function desktop(): PasswordManagerDesktopApi {
  const api = typeof window === "undefined" ? undefined : window.passwordManager;
  if (!api) throw new Error("CIPHER VAULTのアプリから開いてください");
  return api;
}

async function readStatus() {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      desktop().fetchVaultStatus(),
      new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error("保管庫の状態を確認できませんでした")), 5000); })
    ]);
  } finally { clearTimeout(timer); }
}

export function fetchVaultStatus() { return session.readStatus(readStatus); }

export function runVaultMaintenance(payload: VaultMaintenancePayload) {
  return session.maintain((id) => desktop().runVaultMaintenance(payload, id), readStatus);
}

export async function cancelVaultMaintenance(sourceSessionId: string) {
  const state = await fetchVaultStatus();
  if (state.sessionId !== sourceSessionId && state.maintenance?.sourceSessionId !== sourceSessionId) return { state, requested: false };
  return { state: await session.change(() => desktop().lockVault(state.sessionId)), requested: true };
}

export function observeVaultStatus(listener: (state: VaultStatus) => void) {
  let alive = true;
  let reading = false;
  const unsubscribe = session.subscribe(listener);
  const desktopUnsubscribe = window.passwordManager?.onVaultState((state) => { session.observe(state); });
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
  return session.change((id) => desktop().setupVault(payload, id));
}
export function unlockVault(payload: VaultUnlockPayload) {
  return session.change((id) => desktop().unlockVault(payload, id));
}
export function lockVault() {
  const id = session.requireSessionId();
  session.lockLocally();
  return session.change(() => desktop().lockVault(id));
}

function run<T>(action: (sessionId: string) => Promise<T>) { return session.run(action, readStatus); }

export function recordVaultActivity() {
  return run((id) => desktop().recordVaultActivity(id));
}
export function fetchEntries() {
  return run((id) => desktop().fetchEntries(id));
}
export function fetchEntry(entryId: string) {
  return run((id) => desktop().fetchEntry(entryId, id));
}
export function createEntry(payload: VaultEntryUpsertPayload) {
  return run((id) => desktop().createEntry(payload, id));
}
export function updateEntry(entryId: string, payload: VaultEntryUpsertPayload) {
  return run((id) => desktop().updateEntry(entryId, payload, id));
}
export function deleteEntry(entryId: string) {
  return run((id) => desktop().deleteEntry(entryId, id));
}
export function setEntriesGroup(payload: EntriesGroupPayload) {
  // Rewriting a large v2 vault one entry at a time can outlast the default request timeout.
  return run((id) => desktop().setEntriesGroup(payload, id));
}
export function setEntryIcon(entryId: string, icon: EntryIcon | null) {
  return run((id) => desktop().setEntryIcon(entryId, icon, id));
}
export function generatePassword(options: PasswordGenerationOptions = {}) {
  return run((id) => desktop().generatePassword(options, id));
}
export function exportBackup(payload: BackupExportPayload) {
  return run((id) => desktop().exportBackup(payload, id));
}
export function restoreBackup(payload: BackupRestorePayload) {
  return run((id) => desktop().restoreBackup(payload, id));
}
export function auditVault() {
  return run((id) => desktop().auditVault(id));
}
export function copyText(value: string) {
  return run((id) => desktop().copyText(value, id));
}

// The title bar's window buttons. They need no session, as they never reach the vault.
export const windowControls = {
  minimize: () => desktop().minimizeWindow(),
  toggleMaximize: () => desktop().toggleMaximizeWindow(),
  close: () => desktop().closeWindow(),
  isMaximized: () => desktop().isWindowMaximized()
};
