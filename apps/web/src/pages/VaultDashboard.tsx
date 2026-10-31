import { useLayoutEffect, useMemo, useRef, useState } from "react";
import type { VaultEntry, VaultEntrySummary, VaultEntryUpsertPayload, VaultMaintenanceState } from "@password-manager/shared/types";
import { EntryEditor, entryTypeLabel } from "../components/EntryEditor";
import { ChevronIcon, CloseIcon, LockIcon, PlusIcon, SearchIcon } from "../components/Icons";

type VaultDashboardProps = {
  vaultFormat: VaultMaintenanceState["format"];
  onOpenMaintenance: () => void;
  hasUnsavedChanges: boolean;
  onDirtyChange: (dirty: boolean) => void;
  isFormOpen: boolean;
  onFormOpenChange: (open: boolean) => void;
  isEditingEntry: boolean;
  onEditingChange: (editing: boolean) => void;
  onEditEntry: () => void;
  isGroupedView: boolean;
  entries: VaultEntrySummary[];
  isLoading: boolean;
  isCreating: boolean;
  isUpdating: boolean;
  isDeleting: boolean;
  isLoadingDetail: boolean;
  isGeneratingPassword: boolean;
  selectedEntry: VaultEntry | null;
  errorMessage: string;
  copyMessage: string;
  onLock: () => Promise<void>;
  onCreateEntry: (payload: VaultEntryUpsertPayload) => Promise<void>;
  onSelectEntry: (id: string) => Promise<void>;
  onUpdateEntry: (id: string, payload: VaultEntryUpsertPayload) => Promise<void>;
  onDeleteEntry: (id: string) => Promise<void>;
  onGeneratePassword: () => Promise<string>;
  onCopyToClipboard: (value: string, label: string) => Promise<void>;
};

const UNGROUPED = "グループなし";

function entrySubtitle(entry: VaultEntrySummary) {
  return entry.type === "creditCard" ? `•••• ${entry.cardLast4}` : entry.type === "apiKey" ? "APIキー" : entry.loginId;
}

export function VaultDashboard(props: VaultDashboardProps) {
  const { entries, selectedEntry, isFormOpen, isGroupedView } = props;
  const [searchTerm, setSearchTerm] = useState("");
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const listRef = useRef<HTMLDivElement>(null);
  const markerRef = useRef<HTMLDivElement>(null);
  const detailRef = useRef<HTMLElement>(null);
  const previousSelection = useRef<string | null>(null);
  const search = searchTerm.trim().toLocaleLowerCase("ja-JP");
  const filtered = useMemo(() => entries.filter((entry) => !search ||
    [entry.serviceName, entry.loginId ?? "", entry.group ?? "", entryTypeLabel(entry.type), ...entry.tags]
      .some((field) => field.toLocaleLowerCase("ja-JP").includes(search))), [entries, search]);
  const groups = useMemo(() => {
    const result = new Map<string, VaultEntrySummary[]>();
    for (const entry of filtered) {
      const group = entry.group || UNGROUPED;
      result.set(group, [...(result.get(group) ?? []), entry]);
    }
    return [...result.entries()].sort(([a], [b]) => a === b ? 0 : a === UNGROUPED ? 1 : b === UNGROUPED ? -1 : a.localeCompare(b, "ja"));
  }, [filtered]);
  const busy = props.isCreating || props.isUpdating || props.isDeleting || props.isLoadingDetail || props.isGeneratingPassword;

  useLayoutEffect(() => {
    const list = listRef.current;
    const marker = markerRef.current;
    if (!list || !marker) return;
    const active = list.querySelector<HTMLElement>(".entry-row--active");
    if (!active) {
      marker.hidden = true;
      return;
    }
    const position = () => {
      const top = active.getBoundingClientRect().top - list.getBoundingClientRect().top;
      marker.style.transform = `translateY(${top}px)`;
      marker.style.height = `${active.offsetHeight}px`;
      marker.hidden = false;
    };
    position();
    const observer = new ResizeObserver(position);
    observer.observe(list);
    observer.observe(active);
    return () => observer.disconnect();
  }, [filtered, selectedEntry?.id, isFormOpen, isGroupedView, collapsedGroups, props.isLoading]);

  useLayoutEffect(() => {
    if (props.isLoadingDetail) return;
    const selection = isFormOpen ? "new" : selectedEntry?.id ?? null;
    const previous = previousSelection.current;
    previousSelection.current = selection;
    if (!selection || selection === previous) return;
    const form = detailRef.current?.querySelector(".entry-editor");
    const heading = detailRef.current?.querySelector(".inspector-title");
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    if (!form || reducedMotion.matches) return;
    const rows = [...(listRef.current?.querySelectorAll<HTMLElement>(".entry-row") ?? [])];
    const nextIndex = rows.findIndex((row) => row.dataset.entryId === selection);
    const oldIndex = rows.findIndex((row) => row.dataset.entryId === previous);
    const offset = oldIndex >= 0 && nextIndex >= 0 && nextIndex < oldIndex ? -8 : 8;
    // Animate only the current DOM. Never retain an outgoing editor or a snapshot of its secrets.
    const frames = [{ opacity: 0, transform: `translateY(${offset}px)` }, { opacity: 1, transform: "translateY(0)" }];
    const timing = { duration: 200, easing: "cubic-bezier(.2,.75,.25,1)" };
    const animations = [form.animate(frames, timing), heading?.animate(frames, timing)];
    const cancel = () => animations.forEach((animation) => animation?.cancel());
    const preferenceChanged = () => { if (reducedMotion.matches) cancel(); };
    reducedMotion.addEventListener("change", preferenceChanged);
    return () => { cancel(); reducedMotion.removeEventListener("change", preferenceChanged); };
  }, [selectedEntry?.id, isFormOpen, props.isLoadingDetail]);

  function canDiscard() {
    return !props.hasUnsavedChanges || window.confirm("保存していない変更を破棄しますか？");
  }
  function openCreate() {
    if (busy || isFormOpen || !canDiscard()) return;
    props.onDirtyChange(false);
    props.onEditingChange(false);
    props.onFormOpenChange(true);
  }
  function cancelEditing() {
    if (busy || !canDiscard()) return;
    props.onDirtyChange(false);
    props.onEditingChange(false);
    props.onFormOpenChange(false);
  }
  function deleteSelected() {
    if (!selectedEntry || busy) return;
    if (window.confirm(`「${selectedEntry.serviceName}」を削除しますか？元に戻せません。`)) void props.onDeleteEntry(selectedEntry.id).catch(() => {});
  }
  function renderEntry(entry: VaultEntrySummary) {
    const active = !isFormOpen && selectedEntry?.id === entry.id;
    return <button key={entry.id} type="button" data-entry-id={entry.id}
      className={`entry-row ${active ? "entry-row--active" : ""}`}
      disabled={busy} aria-current={active ? "true" : undefined}
      onClick={() => {
        if (active) return;
        if (canDiscard()) void props.onSelectEntry(entry.id);
      }}>
      <span className="entry-badge" aria-hidden="true">{entry.serviceName.charAt(0).toUpperCase()}</span>
      <span className="entry-info">
        <span className="entry-name">{entry.serviceName}</span>
        <span className="entry-login">{entrySubtitle(entry)}</span>
      </span>
    </button>;
  }
  const feedback = props.errorMessage || props.copyMessage;
  const showHeader = isFormOpen || Boolean(selectedEntry) || props.isLoadingDetail;

  return <div className="cipher-dashboard">
    <aside className="vault-sidebar" aria-label="項目の一覧">
      <div className="sidebar-head">
        <div className="search-box">
          <SearchIcon />
          <input className="search-input" type="search" aria-label="検索" placeholder="検索"
            value={searchTerm} onChange={(event) => setSearchTerm(event.target.value)} />
          {search && <span className="search-count" role="status">{filtered.length} / {entries.length}</span>}
          {searchTerm && <button className="icon-btn" type="button" aria-label="検索をクリア" onClick={() => setSearchTerm("")}><CloseIcon /></button>}
        </div>
        <button className="btn sidebar-add" type="button" aria-label="新しい項目" title="新しい項目" disabled={busy || isFormOpen} onClick={openCreate}><PlusIcon /></button>
      </div>
      <div className="entry-list">
        <div className="entry-list-content" ref={listRef}>
          <div className="entry-selection-marker" ref={markerRef} aria-hidden="true" hidden />
          {props.isLoading && <p className="empty-state-text" role="status">読み込み中…</p>}
          {!props.isLoading && search && filtered.length === 0 && <p className="empty-state-text">見つかりません</p>}
          {!props.isLoading && (isGroupedView && !search ? groups.map(([name, items]) => <div key={name}>
            <button className="group-header" type="button" aria-expanded={!collapsedGroups.has(name)} onClick={() => setCollapsedGroups((current) => {
              const next = new Set(current); if (next.has(name)) next.delete(name); else next.add(name); return next;
            })}>
              <ChevronIcon />
              <span className="group-header-name">{name}</span><span className="group-header-count">{items.length}</span>
            </button>
            {!collapsedGroups.has(name) && items.map(renderEntry)}
          </div>) : filtered.map(renderEntry))}
        </div>
      </div>
      <div className="sidebar-foot">
        <button className="btn sidebar-lock" type="button" disabled={busy || props.isLoading} onClick={() => { void props.onLock(); }}><LockIcon />ロック</button>
      </div>
    </aside>
    <section className="vault-detail" ref={detailRef} aria-label={isFormOpen ? "新しい項目" : props.isEditingEntry ? "項目の編集" : "項目の詳細"}>
      {showHeader && <div className="inspector-header">
        <h1 className="inspector-title">{isFormOpen ? "新しい項目" : selectedEntry?.serviceName ?? ""}</h1>
        {selectedEntry && !isFormOpen && !props.isEditingEntry && <div className="inspector-actions"><button className="btn" type="button" disabled={busy} onClick={props.onEditEntry}>編集</button></div>}
      </div>}
      {props.isLoadingDetail ? <p className="empty-state-text" role="status">開いています…</p> : isFormOpen || selectedEntry ?
        <EntryEditor key={isFormOpen ? "new" : selectedEntry!.id}
          vaultFormat={props.vaultFormat} onOpenMaintenance={props.onOpenMaintenance}
          entry={isFormOpen ? null : selectedEntry} isEditing={isFormOpen || props.isEditingEntry} busy={busy} isSaving={props.isCreating || props.isUpdating}
          isGenerating={props.isGeneratingPassword} onDirtyChange={props.onDirtyChange}
          onGenerate={props.onGeneratePassword} onCopy={props.onCopyToClipboard}
          onSave={async (payload) => {
            if (isFormOpen) { await props.onCreateEntry(payload); props.onFormOpenChange(false); }
            else if (selectedEntry) await props.onUpdateEntry(selectedEntry.id, payload);
          }}
          onDelete={isFormOpen ? undefined : deleteSelected}
          onCancel={cancelEditing} /> :
        !props.isLoading && entries.length === 0 ? <div className="inspector-empty">
          <h2>最初のパスワードを追加しましょう</h2>
          <button className="btn btn--primary" type="button" disabled={busy} onClick={openCreate}><PlusIcon />追加</button>
        </div> : <div className="inspector-empty"><p>項目を選ぶと、ここに表示されます</p></div>}
      <div className="toast-region">
        {feedback && <p key={feedback} className={`toast ${props.errorMessage ? "toast--error" : ""}`} role={props.errorMessage ? "alert" : "status"}>{feedback}</p>}
      </div>
    </section>
  </div>;
}
