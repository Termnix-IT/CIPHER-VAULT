import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { PasswordEntry, PasswordEntrySummary, PasswordEntryUpsertPayload } from "@password-manager/shared/types";
import { EntryEditor } from "../components/EntryEditor";

type VaultDashboardProps = {
  hasUnsavedChanges: boolean;
  onDirtyChange: (dirty: boolean) => void;
  isFormOpen: boolean;
  onFormOpenChange: (open: boolean) => void;
  isEditingEntry: boolean;
  onEditingChange: (editing: boolean) => void;
  onEditEntry: () => void;
  isGroupedView: boolean;
  onGroupedViewChange: (grouped: boolean) => void;
  entries: PasswordEntrySummary[];
  isLoading: boolean;
  isCreating: boolean;
  isUpdating: boolean;
  isDeleting: boolean;
  isLoadingDetail: boolean;
  isGeneratingPassword: boolean;
  selectedEntry: PasswordEntry | null;
  errorMessage: string;
  copyMessage: string;
  onLock: () => Promise<void>;
  onRefresh: () => Promise<void>;
  onCreateEntry: (payload: PasswordEntryUpsertPayload) => Promise<void>;
  onSelectEntry: (id: string) => Promise<void>;
  onUpdateEntry: (id: string, payload: PasswordEntryUpsertPayload) => Promise<void>;
  onDeleteEntry: (id: string) => Promise<void>;
  onGeneratePassword: () => Promise<string>;
  onCopyToClipboard: (value: string, label: string) => Promise<void>;
};

export function VaultDashboard(props: VaultDashboardProps) {
  const { entries, selectedEntry, isFormOpen, isGroupedView } = props;
  const [searchTerm, setSearchTerm] = useState("");
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const [moreOpen, setMoreOpen] = useState(false);
  const moreRef = useRef<HTMLDivElement>(null);
  const moreButtonRef = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const markerRef = useRef<HTMLDivElement>(null);
  const detailRef = useRef<HTMLElement>(null);
  const previousSelection = useRef<string | null>(null);
  const search = searchTerm.trim().toLocaleLowerCase("ja-JP");
  const filtered = useMemo(() => entries.filter((entry) => !search ||
    [entry.serviceName, entry.loginId, entry.group ?? "", ...entry.tags]
      .some((field) => field.toLocaleLowerCase("ja-JP").includes(search))), [entries, search]);
  const groups = useMemo(() => {
    const result = new Map<string, PasswordEntrySummary[]>();
    for (const entry of filtered) {
      const group = entry.group || "未分類";
      result.set(group, [...(result.get(group) ?? []), entry]);
    }
    return [...result.entries()].sort(([a], [b]) => a === b ? 0 : a === "未分類" ? 1 : b === "未分類" ? -1 : a.localeCompare(b, "ja"));
  }, [filtered]);
  const busy = props.isCreating || props.isUpdating || props.isDeleting || props.isLoadingDetail || props.isGeneratingPassword;

  useEffect(() => { setMoreOpen(false); }, [selectedEntry?.id, isFormOpen, props.isEditingEntry]);
  useEffect(() => {
    if (!moreOpen) return;
    const outside = (event: PointerEvent) => {
      if (event.target instanceof Node && !moreRef.current?.contains(event.target)) setMoreOpen(false);
    };
    const escape = (event: KeyboardEvent) => {
      if (event.key === "Escape") { setMoreOpen(false); moreButtonRef.current?.focus(); }
    };
    document.addEventListener("pointerdown", outside);
    document.addEventListener("keydown", escape);
    return () => { document.removeEventListener("pointerdown", outside); document.removeEventListener("keydown", escape); };
  }, [moreOpen]);

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
    const offset = oldIndex >= 0 && nextIndex >= 0 && nextIndex < oldIndex ? -12 : 12;
    // Animate only the current DOM. Never retain an outgoing editor or a snapshot of its secrets.
    const frames = [{ opacity: 0, transform: `translateY(${offset}px)` }, { opacity: 1, transform: "translateY(0)" }];
    const timing = { duration: 240, easing: "cubic-bezier(.2,.75,.25,1)" };
    const animations = [form.animate(frames, timing), heading?.animate(frames, timing)];
    const cancel = () => animations.forEach((animation) => animation?.cancel());
    const preferenceChanged = () => { if (reducedMotion.matches) cancel(); };
    reducedMotion.addEventListener("change", preferenceChanged);
    return () => { cancel(); reducedMotion.removeEventListener("change", preferenceChanged); };
  }, [selectedEntry?.id, isFormOpen, props.isLoadingDetail]);

  function canDiscard() {
    return !props.hasUnsavedChanges || window.confirm("未保存の変更を破棄しますか？");
  }
  function toggleCreate() {
    if (busy || !canDiscard()) return;
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
  function renderEntry(entry: PasswordEntrySummary) {
    return <button key={entry.id} type="button" data-entry-id={entry.id}
      className={`entry-row ${!isFormOpen && selectedEntry?.id === entry.id ? "entry-row--active" : ""}`}
      disabled={busy} aria-current={!isFormOpen && selectedEntry?.id === entry.id ? "true" : undefined}
      onClick={() => {
        if (!isFormOpen && selectedEntry?.id === entry.id) return;
        if (canDiscard()) void props.onSelectEntry(entry.id);
      }}>
      <span className="entry-badge" aria-hidden="true">{entry.serviceName.charAt(0).toUpperCase()}</span>
      <span className="entry-info">
        <span className="entry-name">{entry.serviceName}</span>
        <span className="entry-login">{entry.loginId}</span>
      </span>
    </button>;
  }
  return <div className="cipher-dashboard">
    <div className="dashboard-body">
      <aside className="vault-sidebar" aria-label="エントリ一覧">
        <div className="sidebar-head">
          <div className="sidebar-heading"><h2>保管庫 <span className="sidebar-count" role="status">{search ? `${filtered.length} / ${entries.length}件` : `${entries.length}件`}</span></h2>
            <button className="cipher-btn sidebar-add" type="button" disabled={busy || isFormOpen} onClick={toggleCreate}>＋ 新規追加</button>
          </div>
          <div className="search-prompt">
            <input className="search-input" type="search" aria-label="サービス名・ID・グループ・タグで検索" placeholder="検索"
              value={searchTerm} onChange={(event) => setSearchTerm(event.target.value)} />
            {searchTerm && <button className="search-clear-btn" type="button" aria-label="検索条件をクリア" onClick={() => setSearchTerm("")}>×</button>}
          </div>
        </div>
        <select className="sidebar-view-select" aria-label="一覧の表示方法" value={isGroupedView ? "grouped" : "all"}
          onChange={(event) => props.onGroupedViewChange(event.target.value === "grouped")}><option value="all">すべて</option><option value="grouped">グループ別</option></select>
        <div className="entry-list">
          <div className="entry-list-content" ref={listRef}>
            <div className="entry-selection-marker" ref={markerRef} aria-hidden="true" hidden />
            {props.isLoading && <p className="empty-state-text" role="status">読み込み中…</p>}
            {!props.isLoading && filtered.length === 0 && <p className="empty-state-text">{search ? "該当なし" : "エントリがありません"}</p>}
            {!props.isLoading && (isGroupedView && !search ? groups.map(([name, items]) => <div key={name}>
              <button className="group-header" type="button" aria-expanded={!collapsedGroups.has(name)} onClick={() => setCollapsedGroups((current) => {
                const next = new Set(current); if (next.has(name)) next.delete(name); else next.add(name); return next;
              })}>
                <span className="group-header-arrow" aria-hidden="true">{collapsedGroups.has(name) ? "▸" : "▾"}</span>
                <span className="group-header-name">{name}</span><span className="group-header-count">{items.length}件</span>
              </button>
              {!collapsedGroups.has(name) && items.map(renderEntry)}
            </div>) : filtered.map(renderEntry))}
          </div>
        </div>
        <button className="cipher-btn sidebar-lock" type="button" disabled={busy || props.isLoading} onClick={() => { void props.onLock(); }}>保管庫をロック</button>
      </aside>
      <section className="vault-detail" ref={detailRef} aria-label={isFormOpen ? "新規エントリ" : props.isEditingEntry ? "エントリの編集" : "エントリの詳細"}>
        <div className="inspector-header">
          <h1 className="inspector-title">{isFormOpen ? "新規エントリ" : selectedEntry?.serviceName ?? "エントリを選択"}</h1>
          {selectedEntry && !isFormOpen && !props.isEditingEntry && <div className="inspector-actions">
            <button className="cipher-btn cipher-btn--primary" type="button" disabled={busy} onClick={props.onEditEntry}>編集する</button>
            <div className="inspector-more" ref={moreRef} onBlur={(event) => { if (!event.currentTarget.contains(event.relatedTarget)) setMoreOpen(false); }}>
              <button className="cipher-btn inspector-more-trigger" ref={moreButtonRef} type="button" disabled={busy} aria-label="その他の操作" aria-expanded={moreOpen} aria-controls="entry-more-actions" onClick={() => setMoreOpen(!moreOpen)}>⋯</button>
              {moreOpen && <div className="app-menu-popup" id="entry-more-actions"><button className="app-menu-item entry-delete" type="button" disabled={busy} onClick={() => {
                setMoreOpen(false); moreButtonRef.current?.focus();
                if (window.confirm(`「${selectedEntry.serviceName}」を削除しますか？`)) void props.onDeleteEntry(selectedEntry.id).catch(() => {});
              }}>削除</button></div>}
            </div>
          </div>}
        </div>
        {(props.errorMessage || props.copyMessage) && <p key={props.errorMessage || props.copyMessage} className={`inspector-feedback status-msg ${props.errorMessage ? "status-msg--error" : "status-msg--copy"}`} role={props.errorMessage ? "alert" : "status"}>
            {props.errorMessage || props.copyMessage}
        </p>}
        {props.isLoadingDetail ? <p className="empty-state-text" role="status">復号中…</p> : isFormOpen || selectedEntry ?
          <EntryEditor key={isFormOpen ? "new" : selectedEntry!.id}
            entry={isFormOpen ? null : selectedEntry} isEditing={isFormOpen || props.isEditingEntry} busy={busy} isSaving={props.isCreating || props.isUpdating}
            isGenerating={props.isGeneratingPassword} onDirtyChange={props.onDirtyChange}
            onGenerate={props.onGeneratePassword} onCopy={props.onCopyToClipboard}
            onSave={async (payload) => {
              if (isFormOpen) { await props.onCreateEntry(payload); props.onFormOpenChange(false); }
              else if (selectedEntry) await props.onUpdateEntry(selectedEntry.id, payload);
            }}
            onCancel={cancelEditing} /> :
          <div className="inspector-empty"><h2>← エントリを選択</h2></div>}
      </section>
    </div>
  </div>;
}
