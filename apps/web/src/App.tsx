import { useEffect, useRef, useState } from "react";
import { CLIPBOARD_CLEAR_AFTER_MS } from "@password-manager/shared";
import type { VaultEntry, VaultEntrySummary, VaultEntryUpsertPayload, VaultMaintenanceOperation, VaultStatus } from "@password-manager/shared/types";
import {
  copyText, createEntry, deleteEntry, fetchEntries, fetchEntry, generatePassword,
  lockVault, observeVaultStatus, recordVaultActivity, resetVault, setupVault, unlockVault, updateEntry, supportsLocalConnections
} from "./lib/api";
import { LockScreen } from "./pages/LockScreen";
import { VaultDashboard, type CopyNotice } from "./pages/VaultDashboard";
import { AppMenu } from "./components/AppMenu";
import { VaultSessionChangedError } from "./lib/vault-client-session";
import { VaultMaintenance } from "./components/VaultMaintenance";
import { LocalConnections } from "./components/LocalConnections";
import { LockIcon } from "./components/Icons";

type UnlockVeil = { shell: DOMRect; mark: DOMRect };
const UNLOCK_VEIL_MS = 480;

export function App() {
  const [maintenanceOpened, setMaintenanceOpened] = useState(false);
  const [maintenanceRequest, setMaintenanceRequest] = useState<VaultMaintenanceOperation | null>(null);
  const [connectionsOpened, setConnectionsOpened] = useState(false);
  const [vaultStatus, setVaultStatus] = useState<VaultStatus | null>(null);
  const [entries, setEntries] = useState<VaultEntrySummary[]>([]);
  const [selectedEntry, setSelectedEntry] = useState<VaultEntry | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isLoadingEntries, setIsLoadingEntries] = useState(false);
  const [isCreatingEntry, setIsCreatingEntry] = useState(false);
  const [isUpdatingEntry, setIsUpdatingEntry] = useState(false);
  const [isDeletingEntry, setIsDeletingEntry] = useState(false);
  const [isLoadingEntryDetail, setIsLoadingEntryDetail] = useState(false);
  const [isGeneratingPassword, setIsGeneratingPassword] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [lockNotice, setLockNotice] = useState("");
  const [copyNotice, setCopyNotice] = useState<CopyNotice | null>(null);
  const copyTimer = useRef<number | undefined>(undefined);
  const copyCount = useRef(0);
  const [unlockVeil, setUnlockVeil] = useState<UnlockVeil | null>(null);
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [isEditingEntry, setIsEditingEntry] = useState(false);
  const [isGroupedView, setIsGroupedView] = useState(false);
  const statusRef = useRef<VaultStatus | null>(null);
  const maintenanceRequired = vaultStatus?.maintenance?.state !== undefined && vaultStatus.maintenance.state !== "ready";
  useEffect(() => { if (maintenanceRequired) setMaintenanceOpened(true); }, [maintenanceRequired]);
  const viewEpoch = useRef(0);
  const submission = useRef(0);

  useEffect(() => observeVaultStatus((state) => {
    const previous = statusRef.current;
    statusRef.current = state;
    if (previous?.sessionId !== state.sessionId || previous.isUnlocked !== state.isUnlocked) {
      if (previous && !previous.isUnlocked && state.isUnlocked) showUnlockVeil();
      viewEpoch.current++;
      setEntries([]); setSelectedEntry(null); clearCopyNotice();
      setIsFormOpen(false); setIsEditingEntry(false); setHasUnsavedChanges(false);
      setConnectionsOpened(false);
      setIsLoadingEntries(false); setIsLoadingEntryDetail(false);
      setIsCreatingEntry(false); setIsUpdatingEntry(false); setIsDeletingEntry(false); setIsGeneratingPassword(false);
      setErrorMessage("");
      setLockNotice(state.lockReason === "idle" ? "5分間操作がなかったのでロックしました"
        : state.lockReason === "clock-change" ? "パソコンの時刻が変わったのでロックしました"
        : state.lockReason === "screen-lock" || state.lockReason === "screen-unlock" ? "パソコンの画面ロックに合わせてロックしました"
        : state.lockReason === "suspend" || state.lockReason === "resume" ? "スリープに合わせてロックしました" : "");
    }
    setVaultStatus(state);
  }), []);

  useEffect(() => {
    if (vaultStatus?.isUnlocked) void refreshEntries();
  }, [vaultStatus?.sessionId, vaultStatus?.isUnlocked]);

  useEffect(() => {
    if (!vaultStatus?.isUnlocked) return;
    let timer: number | undefined;
    let lastSent = -Infinity;
    let pending = false;
    const sendActivity = () => {
      timer = undefined;
      if (!pending) return;
      pending = false;
      lastSent = performance.now();
      // Only a trusted input event schedules this call; polling never renews a session.
      void recordVaultActivity().catch(() => undefined);
    };
    const activity = (event: Event) => {
      if (!event.isTrusted) return;
      pending = true;
      if (timer === undefined) timer = window.setTimeout(sendActivity, Math.max(0, 1000 - (performance.now() - lastSent)));
    };
    for (const event of ["pointerdown", "keydown", "mousemove", "scroll"]) window.addEventListener(event, activity, true);
    return () => {
      if (timer !== undefined) window.clearTimeout(timer);
      for (const event of ["pointerdown", "keydown", "mousemove", "scroll"]) window.removeEventListener(event, activity, true);
    };
  }, [vaultStatus?.sessionId, vaultStatus?.isUnlocked]);

  function isCurrent(epoch: number) {
    return epoch === viewEpoch.current && statusRef.current?.isUnlocked === true;
  }

  async function refreshEntries() {
    const epoch = viewEpoch.current;
    if (!isCurrent(epoch)) return;
    setIsLoadingEntries(true);
    try {
      const response = await fetchEntries();
      if (!isCurrent(epoch)) return;
      setEntries(response.items);
      setSelectedEntry((current) => current && response.items.some((entry) => entry.id === current.id) ? current : null);
    } catch (error) {
      if (isCurrent(epoch)) setErrorMessage(error instanceof Error ? error.message : "一覧を読み込めませんでした");
    } finally {
      if (isCurrent(epoch)) setIsLoadingEntries(false);
    }
  }

  async function handleVaultSubmit(masterPassword: string) {
    const request = ++submission.current;
    setIsSubmitting(true); setErrorMessage(""); setLockNotice("");
    try {
      if (statusRef.current?.isConfigured) await unlockVault({ masterPassword });
      else await setupVault({ masterPassword });
    } catch (error) {
      if (request === submission.current) setErrorMessage(error instanceof Error ? error.message : "保管庫を開けませんでした");
    } finally {
      if (request === submission.current) setIsSubmitting(false);
    }
  }

  async function handleLockVault() {
    if (hasUnsavedChanges && !window.confirm("保存していない変更を破棄してロックしますか？")) return;
    try { await lockVault(); }
    catch (error) {
      if (statusRef.current?.isUnlocked) setErrorMessage(error instanceof Error ? error.message : "ロックできませんでした");
    }
  }

  async function handleResetVault() {
    const request = ++submission.current;
    setIsSubmitting(true); setErrorMessage("");
    try { await resetVault({ confirmation: "RESET_ALL_DATA" }); }
    catch (error) {
      if (request === submission.current) setErrorMessage(error instanceof Error ? error.message : "保管庫をリセットできませんでした");
      throw error;
    } finally {
      if (request === submission.current) setIsSubmitting(false);
    }
  }

  async function handleCreateEntry(payload: VaultEntryUpsertPayload) {
    const epoch = viewEpoch.current;
    setIsCreatingEntry(true); setErrorMessage("");
    try {
      const created = await createEntry(payload);
      if (!isCurrent(epoch)) throw new VaultSessionChangedError();
      setSelectedEntry(created); setIsEditingEntry(false); setHasUnsavedChanges(false);
      await refreshEntries();
      if (!isCurrent(epoch)) throw new VaultSessionChangedError();
    } catch (error) {
      if (isCurrent(epoch)) setErrorMessage(error instanceof Error ? error.message : "保存できませんでした");
      throw error;
    } finally { if (isCurrent(epoch)) setIsCreatingEntry(false); }
  }

  async function handleSelectEntry(id: string) {
    const epoch = viewEpoch.current;
    setIsLoadingEntryDetail(true); setErrorMessage("");
    try {
      const entry = await fetchEntry(id);
      if (!isCurrent(epoch)) return;
      setSelectedEntry(entry); setIsFormOpen(false); setIsEditingEntry(false); setHasUnsavedChanges(false);
    } catch (error) {
      if (isCurrent(epoch)) setErrorMessage(error instanceof Error ? error.message : "項目を開けませんでした");
    } finally { if (isCurrent(epoch)) setIsLoadingEntryDetail(false); }
  }

  async function handleUpdateEntry(id: string, payload: VaultEntryUpsertPayload) {
    const epoch = viewEpoch.current;
    setIsUpdatingEntry(true); setErrorMessage("");
    try {
      const updated = await updateEntry(id, payload);
      if (!isCurrent(epoch)) throw new VaultSessionChangedError();
      setSelectedEntry(updated); setIsEditingEntry(false); setHasUnsavedChanges(false);
      await refreshEntries();
      if (!isCurrent(epoch)) throw new VaultSessionChangedError();
    } catch (error) {
      if (isCurrent(epoch)) setErrorMessage(error instanceof Error ? error.message : "保存できませんでした");
      throw error;
    } finally { if (isCurrent(epoch)) setIsUpdatingEntry(false); }
  }

  async function handleDeleteEntry(id: string) {
    const epoch = viewEpoch.current;
    setIsDeletingEntry(true); setErrorMessage("");
    try {
      await deleteEntry(id);
      if (!isCurrent(epoch)) throw new VaultSessionChangedError();
      setSelectedEntry(null); setIsEditingEntry(false); setHasUnsavedChanges(false);
      await refreshEntries();
      if (!isCurrent(epoch)) throw new VaultSessionChangedError();
    } catch (error) {
      if (isCurrent(epoch)) setErrorMessage(error instanceof Error ? error.message : "削除できませんでした");
      throw error;
    } finally { if (isCurrent(epoch)) setIsDeletingEntry(false); }
  }

  async function handleGeneratePassword() {
    const epoch = viewEpoch.current;
    setIsGeneratingPassword(true); setErrorMessage("");
    try {
      const result = await generatePassword({ length: 20, includeUppercase: true, includeLowercase: true, includeNumbers: true, includeSymbols: true });
      if (!isCurrent(epoch)) throw new Error("保管庫の状態が変わりました");
      return result.password;
    } catch (error) {
      if (isCurrent(epoch)) setErrorMessage(error instanceof Error ? error.message : "パスワードを生成できませんでした");
      throw error;
    } finally { if (isCurrent(epoch)) setIsGeneratingPassword(false); }
  }

  // Covers the lock screen's spot while its key icon opens and fades. Only positions are kept, never any field content.
  function showUnlockVeil() {
    const shell = document.querySelector(".lock-shell")?.getBoundingClientRect();
    const mark = document.querySelector(".lock-mark")?.getBoundingClientRect();
    if (!shell || !mark || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    setUnlockVeil({ shell, mark });
    window.setTimeout(() => setUnlockVeil(null), UNLOCK_VEIL_MS);
  }

  function clearCopyNotice() {
    window.clearTimeout(copyTimer.current);
    setCopyNotice(null);
  }

  async function handleCopyToClipboard(value: string, label: string) {
    const epoch = viewEpoch.current;
    try {
      await copyText(value);
      if (!isCurrent(epoch)) return;
      // The desktop app clears the clipboard, so its notice stays and counts down until then.
      const clearsInMs = window.passwordManager ? CLIPBOARD_CLEAR_AFTER_MS : null;
      window.clearTimeout(copyTimer.current);
      setCopyNotice({
        id: ++copyCount.current,
        text: `${label}をコピーしました${clearsInMs ? ` · ${clearsInMs / 1000}秒後かロック時に消えます` : ""}`,
        clearsInMs
      });
      copyTimer.current = window.setTimeout(() => { if (isCurrent(epoch)) setCopyNotice(null); }, clearsInMs ?? 2000);
    } catch (error) {
      if (isCurrent(epoch)) setErrorMessage(error instanceof Error ? error.message : "クリップボードへコピーできませんでした");
      throw error;
    }
  }

  function handleOpenCreateForm() {
    if (isFormOpen || isCreatingEntry || isUpdatingEntry || isDeletingEntry || isLoadingEntryDetail) return;
    if (hasUnsavedChanges && !window.confirm("保存していない変更を破棄して、新しい項目を作りますか？")) return;
    setHasUnsavedChanges(false);
    setIsEditingEntry(false);
    setIsFormOpen(true);
  }

  function handleEditEntry() {
    if (!selectedEntry || isFormOpen || isCreatingEntry || isUpdatingEntry || isDeletingEntry || isLoadingEntryDetail || isGeneratingPassword) return;
    setIsEditingEntry(true);
  }

  function handleOpenMaintenance(operation: VaultMaintenanceOperation) {
    if (!statusRef.current?.isUnlocked || isCreatingEntry || isUpdatingEntry || isDeletingEntry || isLoadingEntryDetail || isGeneratingPassword) return;
    if (hasUnsavedChanges && !window.confirm("保存していない変更を破棄して続けますか？")) return;
    setHasUnsavedChanges(false); setIsFormOpen(false); setIsEditingEntry(false);
    setMaintenanceRequest(operation);
    setMaintenanceOpened(true);
  }

  const menu = <AppMenu key={`menu-${vaultStatus?.sessionId ?? "initial"}`}
    isUnlocked={vaultStatus?.isUnlocked ?? false}
    isBusy={isSubmitting || isCreatingEntry || isUpdatingEntry || isDeletingEntry}
    isLoading={isLoadingEntries || isLoadingEntryDetail || isGeneratingPassword}
    hasUnsavedChanges={hasUnsavedChanges}
    entryCount={entries.length}
    selectedEntry={selectedEntry}
    isFormOpen={isFormOpen}
    isEditingEntry={isEditingEntry}
    isGroupedView={isGroupedView}
    onRefresh={refreshEntries}
    onLock={handleLockVault}
    onNewEntry={handleOpenCreateForm}
    onEditEntry={handleEditEntry}
    onGroupedViewChange={setIsGroupedView}
    vaultFormat={vaultStatus?.maintenance?.format ?? "unknown"}
    onSelectEntry={handleSelectEntry}
    onCopy={handleCopyToClipboard}
    onMaintenance={handleOpenMaintenance}
    onConnections={() => setConnectionsOpened(true)}
    connectionsAvailable={supportsLocalConnections()}
  />;

  if (vaultStatus === null) {
    return (
      <main className="app-shell">
        {menu}
        <div className="status-shell">
          <p role="status">読み込み中…</p>
          {errorMessage ? <p className="form-error">{errorMessage}</p> : null}
        </div>
      </main>
    );
  }

  return (
    <main className="app-shell">
      {menu}
      {maintenanceRequired ? <div className="status-shell"><p role="status">前回の変更を確認しています…</p></div> : vaultStatus.isUnlocked ? (
        <VaultDashboard key={`vault-${vaultStatus.sessionId}`}
          vaultFormat={vaultStatus.maintenance?.format ?? "unknown"}
          onOpenMaintenance={() => handleOpenMaintenance("migrate")}
          hasUnsavedChanges={hasUnsavedChanges}
          isFormOpen={isFormOpen}
          onFormOpenChange={setIsFormOpen}
          isEditingEntry={isEditingEntry}
          onEditingChange={setIsEditingEntry}
          onEditEntry={handleEditEntry}
          isGroupedView={isGroupedView}
          onDirtyChange={setHasUnsavedChanges}
          entries={entries}
          isLoading={isLoadingEntries}
          isCreating={isCreatingEntry}
          isUpdating={isUpdatingEntry}
          isDeleting={isDeletingEntry}
          isLoadingDetail={isLoadingEntryDetail}
          isGeneratingPassword={isGeneratingPassword}
          selectedEntry={selectedEntry}
          errorMessage={errorMessage}
          copyNotice={copyNotice}
          onLock={handleLockVault}
          onCreateEntry={handleCreateEntry}
          onSelectEntry={handleSelectEntry}
          onUpdateEntry={handleUpdateEntry}
          onDeleteEntry={handleDeleteEntry}
          onGeneratePassword={handleGeneratePassword}
          onCopyToClipboard={handleCopyToClipboard}
        />
      ) : (
        <LockScreen
          onDirtyChange={setHasUnsavedChanges}
          isConfigured={vaultStatus.isConfigured}
          allowReset={vaultStatus.maintenance?.format !== "v2"}
          isSubmitting={isSubmitting}
          errorMessage={errorMessage}
          notice={lockNotice}
          onSubmit={handleVaultSubmit}
          onReset={handleResetVault}
        />
      )}
      <VaultMaintenance status={vaultStatus} requested={maintenanceRequest} opened={maintenanceOpened || maintenanceRequired} onClose={() => setMaintenanceOpened(false)} />
      {unlockVeil && <div className="unlock-veil" aria-hidden="true"
        style={{ top: unlockVeil.shell.top, left: unlockVeil.shell.left, width: unlockVeil.shell.width, height: unlockVeil.shell.height }}>
        <div className="lock-mark" style={{ top: unlockVeil.mark.top - unlockVeil.shell.top, left: unlockVeil.mark.left - unlockVeil.shell.left }}><LockIcon /></div>
      </div>}
      <LocalConnections key={vaultStatus.sessionId} opened={connectionsOpened && vaultStatus.isUnlocked && !maintenanceRequired} onClose={() => setConnectionsOpened(false)} />
    </main>
  );
}
