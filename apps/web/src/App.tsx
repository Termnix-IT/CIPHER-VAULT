import { useEffect, useRef, useState } from "react";
import { CLIPBOARD_CLEAR_AFTER_MS } from "@password-manager/shared";
import type { PasswordEntry, PasswordEntrySummary, PasswordEntryUpsertPayload, VaultStatus } from "@password-manager/shared/types";
import {
  copyText, createEntry, deleteEntry, fetchEntries, fetchEntry, generatePassword,
  lockVault, observeVaultStatus, recordVaultActivity, resetVault, setupVault, unlockVault, updateEntry
} from "./lib/api";
import { LockScreen } from "./pages/LockScreen";
import { VaultDashboard } from "./pages/VaultDashboard";
import { AppMenu } from "./components/AppMenu";
import { VaultSessionChangedError } from "./lib/vault-client-session";

export function App() {
  const [vaultStatus, setVaultStatus] = useState<VaultStatus | null>(null);
  const [entries, setEntries] = useState<PasswordEntrySummary[]>([]);
  const [selectedEntry, setSelectedEntry] = useState<PasswordEntry | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isLoadingEntries, setIsLoadingEntries] = useState(false);
  const [isCreatingEntry, setIsCreatingEntry] = useState(false);
  const [isUpdatingEntry, setIsUpdatingEntry] = useState(false);
  const [isDeletingEntry, setIsDeletingEntry] = useState(false);
  const [isLoadingEntryDetail, setIsLoadingEntryDetail] = useState(false);
  const [isGeneratingPassword, setIsGeneratingPassword] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [copyMessage, setCopyMessage] = useState("");
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [isEditingEntry, setIsEditingEntry] = useState(false);
  const [isGroupedView, setIsGroupedView] = useState(false);
  const statusRef = useRef<VaultStatus | null>(null);
  const viewEpoch = useRef(0);
  const submission = useRef(0);

  useEffect(() => observeVaultStatus((state) => {
    const previous = statusRef.current;
    statusRef.current = state;
    if (previous?.sessionId !== state.sessionId || previous.isUnlocked !== state.isUnlocked) {
      viewEpoch.current++;
      setEntries([]); setSelectedEntry(null); setCopyMessage("");
      setIsFormOpen(false); setIsEditingEntry(false); setHasUnsavedChanges(false);
      setIsLoadingEntries(false); setIsLoadingEntryDetail(false);
      setIsCreatingEntry(false); setIsUpdatingEntry(false); setIsDeletingEntry(false); setIsGeneratingPassword(false);
      setErrorMessage(state.lockReason === "idle" ? "5分間操作がなかったため保管庫をロックしました"
        : state.lockReason === "clock-change" ? "システム時刻の変更を検出したため保管庫をロックしました"
        : state.lockReason === "screen-lock" || state.lockReason === "screen-unlock" ? "OSの画面ロックに伴い保管庫をロックしました"
        : state.lockReason === "suspend" || state.lockReason === "resume" ? "スリープ・復帰に伴い保管庫をロックしました" : "");
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
      if (isCurrent(epoch)) setErrorMessage(error instanceof Error ? error.message : "エントリ一覧を読み込めませんでした");
    } finally {
      if (isCurrent(epoch)) setIsLoadingEntries(false);
    }
  }

  async function handleVaultSubmit(masterPassword: string) {
    const request = ++submission.current;
    setIsSubmitting(true); setErrorMessage("");
    try {
      if (statusRef.current?.isConfigured) await unlockVault({ masterPassword });
      else await setupVault({ masterPassword });
    } catch (error) {
      if (request === submission.current) setErrorMessage(error instanceof Error ? error.message : "保管庫の操作に失敗しました");
    } finally {
      if (request === submission.current) setIsSubmitting(false);
    }
  }

  async function handleLockVault() {
    if (hasUnsavedChanges && !window.confirm("保存していない内容を破棄して保管庫をロックしますか？")) return;
    try { await lockVault(); }
    catch (error) {
      if (statusRef.current?.isUnlocked) setErrorMessage(error instanceof Error ? error.message : "保管庫をロックできませんでした");
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

  async function handleCreateEntry(payload: PasswordEntryUpsertPayload) {
    const epoch = viewEpoch.current;
    setIsCreatingEntry(true); setErrorMessage("");
    try {
      const created = await createEntry(payload);
      if (!isCurrent(epoch)) throw new VaultSessionChangedError();
      setSelectedEntry(created); setIsEditingEntry(false); setHasUnsavedChanges(false);
      await refreshEntries();
      if (!isCurrent(epoch)) throw new VaultSessionChangedError();
    } catch (error) {
      if (isCurrent(epoch)) setErrorMessage(error instanceof Error ? error.message : "エントリを作成できませんでした");
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
      if (isCurrent(epoch)) setErrorMessage(error instanceof Error ? error.message : "エントリ詳細を読み込めませんでした");
    } finally { if (isCurrent(epoch)) setIsLoadingEntryDetail(false); }
  }

  async function handleUpdateEntry(id: string, payload: PasswordEntryUpsertPayload) {
    const epoch = viewEpoch.current;
    setIsUpdatingEntry(true); setErrorMessage("");
    try {
      const updated = await updateEntry(id, payload);
      if (!isCurrent(epoch)) throw new VaultSessionChangedError();
      setSelectedEntry(updated); setIsEditingEntry(false); setHasUnsavedChanges(false);
      await refreshEntries();
      if (!isCurrent(epoch)) throw new VaultSessionChangedError();
    } catch (error) {
      if (isCurrent(epoch)) setErrorMessage(error instanceof Error ? error.message : "エントリを更新できませんでした");
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
      if (isCurrent(epoch)) setErrorMessage(error instanceof Error ? error.message : "エントリを削除できませんでした");
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

  async function handleCopyToClipboard(value: string, label: string) {
    const epoch = viewEpoch.current;
    try {
      await copyText(value);
      if (!isCurrent(epoch)) return;
      setCopyMessage(`${label}をコピーしました${window.passwordManager ? `（${CLIPBOARD_CLEAR_AFTER_MS / 1000}秒後またはロック時に消去）` : ""}`);
      window.setTimeout(() => { if (isCurrent(epoch)) setCopyMessage(""); }, 2000);
    } catch (error) {
      if (isCurrent(epoch)) setErrorMessage(error instanceof Error ? error.message : "クリップボードへコピーできませんでした");
      throw error;
    }
  }

  function handleOpenCreateForm() {
    if (isFormOpen || isCreatingEntry || isUpdatingEntry || isDeletingEntry || isLoadingEntryDetail) return;
    if (hasUnsavedChanges && !window.confirm("保存していない内容を破棄して新規エントリを開きますか？")) return;
    setHasUnsavedChanges(false);
    setIsEditingEntry(false);
    setIsFormOpen(true);
  }

  function handleEditEntry() {
    if (!selectedEntry || isFormOpen || isCreatingEntry || isUpdatingEntry || isDeletingEntry || isLoadingEntryDetail || isGeneratingPassword) return;
    setIsEditingEntry(true);
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
    onSelectEntry={handleSelectEntry}
    onCopy={handleCopyToClipboard}
  />;

  if (vaultStatus === null) {
    return (
      <main className="app-shell">
        {menu}
        <div className="cipher-auth-shell">
          <p className="loading-text">&gt; 保管庫を読み込み中...</p>
          {errorMessage ? <p className="form-error">{errorMessage}</p> : null}
        </div>
      </main>
    );
  }

  return (
    <main className="app-shell">
      {menu}
      {vaultStatus.isUnlocked ? (
        <VaultDashboard key={`vault-${vaultStatus.sessionId}`}
          hasUnsavedChanges={hasUnsavedChanges}
          isFormOpen={isFormOpen}
          onFormOpenChange={setIsFormOpen}
          isEditingEntry={isEditingEntry}
          onEditingChange={setIsEditingEntry}
          onEditEntry={handleEditEntry}
          isGroupedView={isGroupedView}
          onGroupedViewChange={setIsGroupedView}
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
          copyMessage={copyMessage}
          onLock={handleLockVault}
          onRefresh={refreshEntries}
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
          isSubmitting={isSubmitting}
          errorMessage={errorMessage}
          onSubmit={handleVaultSubmit}
          onReset={handleResetVault}
        />
      )}
    </main>
  );
}
