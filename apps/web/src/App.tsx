import { useEffect, useMemo, useRef, useState } from "react";
import { CLIPBOARD_CLEAR_AFTER_MS } from "@password-manager/shared";
import type { EntryIcon, VaultEntry, VaultEntrySummary, VaultEntryUpsertPayload, VaultMaintenanceOperation, VaultStatus } from "@password-manager/shared/types";
import {
  copyText, createEntry, deleteEntry, fetchEntries, fetchEntry, generatePassword, setEntryIcon, setEntryFavorite, recordEntryUse, openEntryUrl,
  lockVault, observeVaultStatus, recordVaultActivity, setEntriesGroup, setupVault, unlockVault, updateEntry, windowControls
} from "./lib/api";
import { LockScreen } from "./pages/LockScreen";
import { VaultDashboard, type CopyNotice } from "./pages/VaultDashboard";
import { CompactView } from "./pages/CompactView";
import { AppMenu } from "./components/AppMenu";
import { SettingsDialog, autoLockText } from "./components/SettingsDialog";
import { VaultSessionChangedError } from "./lib/vault-client-session";
import { applyDesignMode, readDesignMode, saveDesignMode, type DesignMode } from "./lib/design-mode";
import { VaultMaintenance } from "./components/VaultMaintenance";
import { LockIcon } from "./components/Icons";
import { Tooltip } from "./components/Tooltip";
import { readSidebarCollapsed, saveSidebarCollapsed } from "./lib/layout-prefs";
import { loginIdOf, primarySecretOf } from "./lib/entry-list";
import { shortcutOf } from "./lib/shortcuts";

type UnlockVeil = { shell: DOMRect; mark: DOMRect };
const UNLOCK_VEIL_MS = 480;
/** A use is recorded at most once a minute per entry, so copying the ID and then the password writes once. */
const USE_RECORD_INTERVAL_MS = 60_000;

export function App() {
  const [maintenanceOpened, setMaintenanceOpened] = useState(false);
  const [maintenanceRequest, setMaintenanceRequest] = useState<VaultMaintenanceOperation | null>(null);
  const [vaultStatus, setVaultStatus] = useState<VaultStatus | null>(null);
  const [entries, setEntries] = useState<VaultEntrySummary[]>([]);
  const entryIcons = useMemo(() => Object.fromEntries(entries.flatMap((entry) => entry.icon ? [[entry.id, entry.icon]] : [])) as Record<string, EntryIcon>, [entries]);
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
  const [designMode, setDesignMode] = useState<DesignMode>(readDesignMode);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(readSidebarCollapsed);
  // The compact layout and the topmost window last until the app closes; each start is normal.
  const [isCompact, setIsCompact] = useState(false);
  const [isAlwaysOnTop, setIsAlwaysOnTop] = useState(false);
  const [searchFocusRequest, setSearchFocusRequest] = useState(0);
  const [settingsOpen, setSettingsOpen] = useState(false);
  // The entry the compact view shows in full; its list highlights an entry without opening it.
  const [compactDetailId, setCompactDetailId] = useState<string | null>(null);
  // The vault refuses a second write while one runs, so the screen's writes wait for each other.
  const writeQueue = useRef<Promise<unknown>>(Promise.resolve());
  const lastUseRecord = useRef(new Map<string, number>());
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
      setIsLoadingEntries(false); setIsLoadingEntryDetail(false);
      setIsCreatingEntry(false); setIsUpdatingEntry(false); setIsDeletingEntry(false); setIsGeneratingPassword(false);
      setErrorMessage(""); setSettingsOpen(false); lastUseRecord.current.clear();
      const minutes = state.autoLockMinutes ?? previous?.autoLockMinutes;
      const idleFor = typeof minutes === "number" ? `${autoLockText(minutes)}間` : "しばらく";
      setLockNotice(state.lockReason === "idle" ? `${idleFor}操作がなかったのでロックしました`
        : state.lockReason === "clock-change" ? "パソコンの時刻が変わったのでロックしました"
        : state.lockReason === "screen-lock" || state.lockReason === "screen-unlock" ? "パソコンの画面ロックに合わせてロックしました"
        : state.lockReason === "suspend" || state.lockReason === "resume" ? "スリープに合わせてロックしました" : "");
    }
    setVaultStatus(state);
  }), []);

  useEffect(() => {
    if (vaultStatus?.isUnlocked) { void refreshEntries(); }
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
      // A pointer passing over a window kept on top, or a wheel turned over it, is not someone using the app.
      if ((event.type === "mousemove" || event.type === "wheel") && !document.hasFocus()) return;
      pending = true;
      if (timer === undefined) timer = window.setTimeout(sendActivity, Math.max(0, 1000 - (performance.now() - lastSent)));
    };
    const events = ["pointerdown", "keydown", "mousemove", "wheel"];
    for (const event of events) window.addEventListener(event, activity, { capture: true, passive: true });
    return () => {
      if (timer !== undefined) window.clearTimeout(timer);
      for (const event of events) window.removeEventListener(event, activity, true);
    };
  }, [vaultStatus?.sessionId, vaultStatus?.isUnlocked]);

  function isCurrent(epoch: number) {
    return epoch === viewEpoch.current && statusRef.current?.isUnlocked === true;
  }

  // A write still waiting when the vault locks is dropped, so it never lands in the next session.
  function serialWrite<T>(task: () => Promise<T>): Promise<T> {
    const epoch = viewEpoch.current;
    const run = () => isCurrent(epoch) ? task() : Promise.reject(new VaultSessionChangedError());
    const result = writeQueue.current.then(run, run);
    writeQueue.current = result.catch(() => undefined);
    return result;
  }

  function replaceSummary(summary: VaultEntrySummary) {
    setEntries((current) => current.map((entry) => entry.id === summary.id ? summary : entry));
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

  async function handleSetEntryIcon(id: string, icon: EntryIcon | null) {
    const epoch = viewEpoch.current;
    const summary = await serialWrite(() => setEntryIcon(id, icon));
    if (!isCurrent(epoch)) throw new VaultSessionChangedError();
    replaceSummary(summary);
    setSelectedEntry((current) => current?.id === id ? { ...current, icon: summary.icon } : current);
  }

  // Only the list changes: the open item, and a form on it, stay as they are.
  async function handleSetEntryFavorite(id: string, favorite: boolean) {
    const epoch = viewEpoch.current;
    setErrorMessage("");
    try {
      const summary = await serialWrite(() => setEntryFavorite(id, favorite));
      if (isCurrent(epoch)) replaceSummary(summary);
    } catch (error) {
      if (isCurrent(epoch)) setErrorMessage(error instanceof Error ? error.message : "お気に入りを変更できませんでした");
    }
  }

  /** Copying a value or opening the URL counts as using the entry; opening its details does not. */
  function recordUse(id: string) {
    const epoch = viewEpoch.current;
    const now = Date.now();
    if (now - (lastUseRecord.current.get(id) ?? -Infinity) < USE_RECORD_INTERVAL_MS) return;
    lastUseRecord.current.set(id, now);
    // The order of recent use is a convenience, so a failure to record it is not shown.
    void serialWrite(() => recordEntryUse(id)).then((summary) => { if (isCurrent(epoch)) replaceSummary(summary); },
      () => { lastUseRecord.current.delete(id); });
  }

  async function handleOpenUrl(id: string) {
    const epoch = viewEpoch.current;
    setErrorMessage("");
    try {
      await openEntryUrl(id);
      if (!isCurrent(epoch)) return;
      showNotice("ブラウザでURLを開きました");
      recordUse(id);
    } catch (error) {
      if (isCurrent(epoch)) setErrorMessage(error instanceof Error ? error.message : "URLを開けませんでした");
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

  async function handleCreateEntry(payload: VaultEntryUpsertPayload) {
    const epoch = viewEpoch.current;
    setIsCreatingEntry(true); setErrorMessage("");
    try {
      const created = await serialWrite(() => createEntry(payload));
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
      const updated = await serialWrite(() => updateEntry(id, payload));
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
      await serialWrite(() => deleteEntry(id));
      if (!isCurrent(epoch)) throw new VaultSessionChangedError();
      // Deleting another item from the list leaves the open one as it is.
      if (selectedEntry?.id === id) { setSelectedEntry(null); setIsEditingEntry(false); setHasUnsavedChanges(false); }
      await refreshEntries();
      if (!isCurrent(epoch)) throw new VaultSessionChangedError();
    } catch (error) {
      if (isCurrent(epoch)) setErrorMessage(error instanceof Error ? error.message : "削除できませんでした");
      throw error;
    } finally { if (isCurrent(epoch)) setIsDeletingEntry(false); }
  }

  async function handleSetEntriesGroup(ids: string[], group: string | null) {
    const epoch = viewEpoch.current;
    const openId = selectedEntry && ids.includes(selectedEntry.id) ? selectedEntry.id : null;
    // The list and the open item are re-read after a failure too, because a v2 change can stop part way.
    const reload = async () => {
      await refreshEntries();
      if (!openId || !isCurrent(epoch)) return;
      const entry = await fetchEntry(openId);
      if (isCurrent(epoch)) setSelectedEntry(entry);
    };
    setIsUpdatingEntry(true); setErrorMessage("");
    // A form left open on this item would save its old group over the new one.
    if (openId) { setIsEditingEntry(false); setHasUnsavedChanges(false); }
    try {
      const { updatedCount } = await serialWrite(() => setEntriesGroup({ ids, group }));
      if (!isCurrent(epoch)) throw new VaultSessionChangedError();
      await reload();
      if (!isCurrent(epoch)) throw new VaultSessionChangedError();
      showNotice(group === null ? "グループから削除しました" : updatedCount ? `「${group}」に${updatedCount}件追加しました` : `すでに「${group}」に入っています`);
    } catch (error) {
      if (isCurrent(epoch)) {
        setErrorMessage(error instanceof Error ? error.message : "グループを変更できませんでした");
        await reload().catch(() => undefined);
      }
      throw error;
    } finally { if (isCurrent(epoch)) setIsUpdatingEntry(false); }
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

  function showNotice(text: string) {
    window.clearTimeout(copyTimer.current);
    setCopyNotice({ id: ++copyCount.current, text, clearsInMs: null });
    copyTimer.current = window.setTimeout(() => setCopyNotice(null), 3000);
  }

  async function handleCopyToClipboard(value: string, label: string, entryId?: string) {
    const epoch = viewEpoch.current;
    try {
      await copyText(value);
      if (!isCurrent(epoch)) return;
      if (entryId) recordUse(entryId);
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

  function handleDesignModeChange(mode: DesignMode) {
    setDesignMode(mode);
    applyDesignMode(mode);
    saveDesignMode(mode);
  }

  function handleSidebarCollapsedChange(collapsed: boolean) {
    setIsSidebarCollapsed(collapsed);
    saveSidebarCollapsed(collapsed);
  }

  /** The window changes first, so a refused change leaves the screen as it was. */
  async function handleCompactChange(compact: boolean) {
    if (compact === isCompact) return true;
    if (compact && (isFormOpen || isEditingEntry)) {
      if (hasUnsavedChanges && !window.confirm("保存していない変更を破棄して、コンパクト表示にしますか？")) return false;
      setIsFormOpen(false); setIsEditingEntry(false); setHasUnsavedChanges(false);
    }
    try { await windowControls.setCompact(compact); }
    catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "表示を切り替えられませんでした");
      return false;
    }
    setIsCompact(compact);
    return true;
  }

  async function handleAlwaysOnTopChange(onTop: boolean) {
    try {
      await windowControls.setAlwaysOnTop(onTop);
      setIsAlwaysOnTop(onTop);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "最前面の表示を切り替えられませんでした");
    }
  }

  // Making and editing entries happen in the normal layout, so the compact one steps aside first.
  async function handleOpenCreateForm() {
    if (isFormOpen || isCreatingEntry || isUpdatingEntry || isDeletingEntry || isLoadingEntryDetail) return;
    if (hasUnsavedChanges && !window.confirm("保存していない変更を破棄して、新しい項目を作りますか？")) return;
    if (!await handleCompactChange(false)) return;
    setHasUnsavedChanges(false);
    setIsEditingEntry(false);
    setIsFormOpen(true);
  }

  async function handleEditEntry() {
    if (!selectedEntry || isFormOpen || isCreatingEntry || isUpdatingEntry || isDeletingEntry || isLoadingEntryDetail || isGeneratingPassword) return;
    if (!await handleCompactChange(false)) return;
    setIsEditingEntry(true);
  }

  /** The open entry for the item menu and the shortcuts, or why they cannot use it now. */
  function selectedForAction(): { entry: VaultEntry } | { refused: string } {
    if (!statusRef.current?.isUnlocked) return { refused: "保管庫がロックされています" };
    if (!selectedEntry) return { refused: "先に項目を選んでください" };
    if (isFormOpen || isEditingEntry) return { refused: "編集を終えてから使えます" };
    if (isCompact && compactDetailId !== selectedEntry.id) return { refused: "項目を開いてから使えます" };
    if (isLoadingEntryDetail || isCreatingEntry || isUpdatingEntry || isDeletingEntry) return { refused: "処理が終わってから使えます" };
    return { entry: selectedEntry };
  }
  function copySelectedLoginId() {
    const selected = selectedForAction();
    if ("refused" in selected) { showNotice(selected.refused); return; }
    const loginId = loginIdOf(selected.entry);
    if (!loginId) { showNotice("この項目にはログインIDがありません"); return; }
    void handleCopyToClipboard(loginId, `${selected.entry.serviceName}のログインID`, selected.entry.id).catch(() => undefined);
  }
  function copySelectedSecret() {
    const selected = selectedForAction();
    if ("refused" in selected) { showNotice(selected.refused); return; }
    const secret = primarySecretOf(selected.entry);
    if (!secret.value) { showNotice(`この項目には${secret.label}がありません`); return; }
    void handleCopyToClipboard(secret.value, `${selected.entry.serviceName}の${secret.label}`, selected.entry.id).catch(() => undefined);
  }
  function openSelectedUrl() {
    const selected = selectedForAction();
    if ("refused" in selected) { showNotice(selected.refused); return; }
    void handleOpenUrl(selected.entry.id);
  }
  const selectedSummary = selectedEntry ? entries.find((entry) => entry.id === selectedEntry.id) : undefined;

  // A shortcut waits while a dialog, a menu or the icon picker is open: those keep the keyboard.
  // Ctrl+Shift+M only changes the window, so it works on the lock screen too.
  const shortcut = useRef<(event: KeyboardEvent) => void>(() => undefined);
  shortcut.current = (event) => {
    const name = shortcutOf(event);
    if (!name || event.isComposing) return;
    event.preventDefault();
    if (event.repeat || document.querySelector("dialog[open], .app-menu-popup, .icon-picker")) return;
    if (name === "compact") { void handleCompactChange(!isCompact); return; }
    if (!statusRef.current?.isUnlocked || maintenanceRequired) return;
    if (name === "search") setSearchFocusRequest((count) => count + 1);
    else if (name === "new") void handleOpenCreateForm();
    else if (name === "lock") void handleLockVault();
    else if (name === "copyLoginId") copySelectedLoginId();
    else if (name === "copySecret") copySelectedSecret();
    else openSelectedUrl();
  };
  useEffect(() => {
    const listener = (event: KeyboardEvent) => shortcut.current(event);
    window.addEventListener("keydown", listener);
    return () => window.removeEventListener("keydown", listener);
  }, []);

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
    selectedFavorite={Boolean(selectedSummary?.favorite)}
    isFormOpen={isFormOpen}
    isEditingEntry={isEditingEntry}
    isGroupedView={isGroupedView}
    onRefresh={refreshEntries}
    onLock={handleLockVault}
    onNewEntry={() => { void handleOpenCreateForm(); }}
    onEditEntry={() => { void handleEditEntry(); }}
    onGroupedViewChange={setIsGroupedView}
    isSidebarCollapsed={isSidebarCollapsed}
    onSidebarCollapsedChange={handleSidebarCollapsedChange}
    designMode={designMode}
    onDesignModeChange={handleDesignModeChange}
    onSelectEntry={handleSelectEntry}
    onCopyLoginId={copySelectedLoginId}
    onCopySecret={copySelectedSecret}
    onOpenUrl={openSelectedUrl}
    onToggleFavorite={() => { if (selectedSummary) void handleSetEntryFavorite(selectedSummary.id, !selectedSummary.favorite); }}
    isCompact={isCompact}
    onCompactChange={(compact) => { void handleCompactChange(compact); }}
    isAlwaysOnTop={isAlwaysOnTop}
    onAlwaysOnTopChange={(onTop) => { void handleAlwaysOnTopChange(onTop); }}
    onOpenSettings={() => setSettingsOpen(true)}
    onMaintenance={handleOpenMaintenance}
  />;

  if (vaultStatus === null) {
    return (
      <main className="app-shell">
        {menu}
        <Tooltip />
        <div className="status-shell">
          <p role="status">読み込み中…</p>
          {errorMessage ? <p className="form-error">{errorMessage}</p> : null}
        </div>
      </main>
    );
  }

  return (
    <main className={`app-shell${isCompact ? " app-shell--compact" : ""}`}>
      {menu}
      <Tooltip />
      {maintenanceRequired ? <div className="status-shell"><p role="status">前回の変更を確認しています…</p></div> : vaultStatus.isUnlocked && isCompact ? (
        <CompactView key={`compact-${vaultStatus.sessionId}`}
          entries={entries}
          entryIcons={entryIcons}
          selectedEntry={selectedEntry}
          isLoading={isLoadingEntries}
          isLoadingDetail={isLoadingEntryDetail}
          busy={isCreatingEntry || isUpdatingEntry || isDeletingEntry}
          errorMessage={errorMessage}
          copyNotice={copyNotice}
          isAlwaysOnTop={isAlwaysOnTop}
          onAlwaysOnTopChange={(onTop) => { void handleAlwaysOnTopChange(onTop); }}
          onExitCompact={() => { void handleCompactChange(false); }}
          onSelectEntry={handleSelectEntry}
          onCopyToClipboard={handleCopyToClipboard}
          onOpenUrl={(id) => { void handleOpenUrl(id); }}
          onSetEntryFavorite={(id, favorite) => { void handleSetEntryFavorite(id, favorite); }}
          onDirtyChange={setHasUnsavedChanges}
          onDetailChange={setCompactDetailId}
          searchFocusRequest={searchFocusRequest}
        />
      ) : vaultStatus.isUnlocked ? (
        <VaultDashboard key={`vault-${vaultStatus.sessionId}`}
          hasUnsavedChanges={hasUnsavedChanges}
          isFormOpen={isFormOpen}
          onFormOpenChange={setIsFormOpen}
          isEditingEntry={isEditingEntry}
          onEditingChange={setIsEditingEntry}
          onEditEntry={() => { void handleEditEntry(); }}
          isGroupedView={isGroupedView}
          onGroupedViewChange={setIsGroupedView}
          isSidebarCollapsed={isSidebarCollapsed}
          onSidebarCollapsedChange={handleSidebarCollapsedChange}
          onDirtyChange={setHasUnsavedChanges}
          entryIcons={entryIcons}
          onSetEntryIcon={handleSetEntryIcon}
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
          onCreateEntry={handleCreateEntry}
          onSelectEntry={handleSelectEntry}
          onUpdateEntry={handleUpdateEntry}
          onDeleteEntry={handleDeleteEntry}
          onSetEntriesGroup={handleSetEntriesGroup}
          onGeneratePassword={handleGeneratePassword}
          onCopyToClipboard={handleCopyToClipboard}
          onSetEntryFavorite={(id, favorite) => { void handleSetEntryFavorite(id, favorite); }}
          onOpenUrl={(id) => { void handleOpenUrl(id); }}
          searchFocusRequest={searchFocusRequest}
        />
      ) : (
        <LockScreen
          onDirtyChange={setHasUnsavedChanges}
          isConfigured={vaultStatus.isConfigured}
          legacyVaultFound={vaultStatus.legacyVaultFound}
          isSubmitting={isSubmitting}
          errorMessage={errorMessage}
          notice={lockNotice}
          onSubmit={handleVaultSubmit}
        />
      )}
      <SettingsDialog open={settingsOpen} autoLockMinutes={vaultStatus.autoLockMinutes} onClose={() => setSettingsOpen(false)} onSaved={showNotice} />
      <VaultMaintenance status={vaultStatus} requested={maintenanceRequest} opened={maintenanceOpened || maintenanceRequired} onClose={() => setMaintenanceOpened(false)} />
      {unlockVeil && <div className="unlock-veil" aria-hidden="true"
        style={{ top: unlockVeil.shell.top, left: unlockVeil.shell.left, width: unlockVeil.shell.width, height: unlockVeil.shell.height }}>
        <div className="lock-mark" style={{ top: unlockVeil.mark.top - unlockVeil.shell.top, left: unlockVeil.mark.left - unlockVeil.shell.left }}><LockIcon /></div>
      </div>}
    </main>
  );
}
