import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { VaultEntry, VaultEntrySummary, VaultEntryType, VaultEntryUpsertPayload, VaultMaintenanceState } from "@password-manager/shared/types";
import { EntryEditor, entryTypeLabel } from "../components/EntryEditor";
import { ChevronIcon, CloseIcon, LockIcon, PlusIcon, SearchIcon } from "../components/Icons";

export type CopyNotice = { id: number; text: string; clearsInMs: number | null };

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
  /** clearsInMs is how long until the desktop app clears the copied value, or null when nothing clears it. */
  copyNotice: CopyNotice | null;
  onLock: () => Promise<void>;
  onCreateEntry: (payload: VaultEntryUpsertPayload) => Promise<void>;
  onSelectEntry: (id: string) => Promise<void>;
  onUpdateEntry: (id: string, payload: VaultEntryUpsertPayload) => Promise<void>;
  onDeleteEntry: (id: string) => Promise<void>;
  onGeneratePassword: () => Promise<string>;
  onCopyToClipboard: (value: string, label: string) => Promise<void>;
};

const UNGROUPED = "グループなし";
const TYPE_FILTERS: { type: VaultEntryType; label: string }[] = [{ type: "login", label: "ログイン" }, { type: "apiKey", label: "APIキー" }, { type: "creditCard", label: "カード" }];
const KANA_ROWS = ["あ", "か", "さ", "た", "な", "は", "ま", "や", "ら", "わ"];
const DAY_MS = 24 * 60 * 60 * 1000;
type SortOrder = "name" | "updated";

const entryType = (entry: VaultEntrySummary): VaultEntryType => entry.type ?? "login";
const byName = (a: VaultEntrySummary, b: VaultEntrySummary) => a.serviceName.localeCompare(b.serviceName, "ja", { numeric: true, sensitivity: "base" });
const byUpdated = (a: VaultEntrySummary, b: VaultEntrySummary) => b.updatedAt.localeCompare(a.updatedAt) || byName(a, b);

/** Index heading for name order: Latin initial, kana row, kanji, or "#" for digits and symbols. */
function nameSection(name: string) {
  const first = name.trim().normalize("NFKC").charAt(0);
  if (/[a-z]/i.test(first)) return first.toUpperCase();
  // Katakana to hiragana, then drop voicing marks so が falls under か.
  const kana = first.replace(/[ァ-ヶ]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 0x60)).normalize("NFD").charAt(0);
  if (/[ぁ-ゖ]/.test(kana)) return `${[...KANA_ROWS].reverse().find((row) => row <= kana) ?? "あ"}行`;
  if (/\p{Script=Han}/u.test(first)) return "漢字";
  return "#";
}
function updatedSection(updatedAt: string, now: number) {
  const age = now - new Date(updatedAt).getTime();
  return age < DAY_MS ? "24時間以内" : age < 7 * DAY_MS ? "7日以内" : age < 30 * DAY_MS ? "30日以内" : "それ以前";
}
function sections(items: VaultEntrySummary[], label: (entry: VaultEntrySummary) => string) {
  const result = new Map<string, VaultEntrySummary[]>();
  for (const entry of items) { const key = label(entry); result.set(key, [...(result.get(key) ?? []), entry]); }
  return [...result.entries()];
}

function entrySubtitle(entry: VaultEntrySummary) {
  return entry.type === "creditCard" ? `•••• ${entry.cardLast4}` : entry.type === "apiKey" ? "APIキー" : entry.loginId;
}

export function VaultDashboard(props: VaultDashboardProps) {
  const { entries, selectedEntry, isFormOpen, isGroupedView } = props;
  const [searchTerm, setSearchTerm] = useState("");
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const [typeFilter, setTypeFilter] = useState<VaultEntryType | "all">("all");
  const [sortOrder, setSortOrder] = useState<SortOrder>("name");
  const [savedNotice, setSavedNotice] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);
  const highlightRef = useRef<HTMLDivElement>(null);
  const detailRef = useRef<HTMLElement>(null);
  const previousSelection = useRef<string | null>(null);
  const search = searchTerm.trim().toLocaleLowerCase("ja-JP");
  const presentTypes = useMemo(() => TYPE_FILTERS.filter(({ type }) => entries.some((entry) => entryType(entry) === type)), [entries]);
  // A filter for a type that no longer exists falls back to all items instead of showing an empty list.
  const activeType = presentTypes.length > 1 && presentTypes.some(({ type }) => type === typeFilter) ? typeFilter : "all";
  const filtered = useMemo(() => entries.filter((entry) => (activeType === "all" || entryType(entry) === activeType) && (!search ||
    [entry.serviceName, entry.loginId ?? "", entry.group ?? "", entryTypeLabel(entry.type), ...entry.tags]
      .some((field) => field.toLocaleLowerCase("ja-JP").includes(search)))).sort(sortOrder === "name" ? byName : byUpdated), [entries, search, activeType, sortOrder]);
  const listSections = useMemo(() => {
    const now = Date.now();
    return sections(filtered, sortOrder === "name" ? (entry) => nameSection(entry.serviceName) : (entry) => updatedSection(entry.updatedAt, now));
  }, [filtered, sortOrder]);
  const groups = useMemo(() => {
    const result = new Map<string, VaultEntrySummary[]>();
    for (const entry of filtered) {
      const group = entry.group || UNGROUPED;
      result.set(group, [...(result.get(group) ?? []), entry]);
    }
    return [...result.entries()].sort(([a], [b]) => a === b ? 0 : a === UNGROUPED ? 1 : b === UNGROUPED ? -1 : a.localeCompare(b, "ja"));
  }, [filtered]);
  const busy = props.isCreating || props.isUpdating || props.isDeleting || props.isLoadingDetail || props.isGeneratingPassword;

  useEffect(() => {
    if (!savedNotice) return;
    const timer = window.setTimeout(() => setSavedNotice(false), 1600);
    return () => window.clearTimeout(timer);
  }, [savedNotice]);
  useEffect(() => { if (props.isEditingEntry || isFormOpen) setSavedNotice(false); }, [props.isEditingEntry, isFormOpen]);

  // One shared highlight slides between rows; it jumps without sliding when it was hidden before.
  useLayoutEffect(() => {
    const list = listRef.current;
    const highlight = highlightRef.current;
    if (!list || !highlight) return;
    const active = list.querySelector<HTMLElement>(".entry-row--active");
    if (!active) {
      highlight.hidden = true;
      list.classList.remove("entry-list-content--highlighted");
      return;
    }
    const position = () => {
      const top = active.getBoundingClientRect().top - list.getBoundingClientRect().top;
      highlight.style.transform = `translateY(${top}px)`;
      highlight.style.height = `${active.offsetHeight}px`;
    };
    if (highlight.hidden) {
      highlight.style.transition = "none";
      position();
      highlight.hidden = false;
      void highlight.offsetHeight;
      highlight.style.transition = "";
    } else position();
    list.classList.add("entry-list-content--highlighted");
    const observer = new ResizeObserver(position);
    observer.observe(list);
    observer.observe(active);
    return () => observer.disconnect();
  }, [filtered, listSections, selectedEntry?.id, isFormOpen, isGroupedView, collapsedGroups, props.isLoading]);

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
    const offset = oldIndex >= 0 && nextIndex >= 0 && nextIndex < oldIndex ? -4 : 4;
    // Animate only the current DOM. Never retain an outgoing editor or a snapshot of its secrets.
    const frames = [{ opacity: 0, transform: `translateY(${offset}px)` }, { opacity: 1, transform: "translateY(0)" }];
    const timing = { duration: 160, easing: "cubic-bezier(.2,.75,.25,1)" };
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
        if (canDiscard()) { setSavedNotice(false); void props.onSelectEntry(entry.id); }
      }}>
      <span className="entry-badge" aria-hidden="true">{entry.serviceName.charAt(0).toUpperCase()}</span>
      <span className="entry-info">
        <span className="entry-name">{entry.serviceName}</span>
        <span className="entry-login">{entrySubtitle(entry)}</span>
      </span>
    </button>;
  }
  const feedback = props.errorMessage || props.copyNotice?.text;
  const showHeader = isFormOpen || Boolean(selectedEntry) || props.isLoadingDetail;
  const renderSection = ([name, items]: [string, VaultEntrySummary[]]) => <div key={name} role="group" aria-label={name}>
    <p className="list-section" aria-hidden="true">{name}</p>
    {items.map(renderEntry)}
  </div>;

  return <div className="cipher-dashboard">
    <aside className="vault-sidebar" aria-label="項目の一覧">
      <div className="sidebar-controls">
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
        {presentTypes.length > 1 && <div className="list-filter" role="group" aria-label="種類で絞り込み">
          <button type="button" aria-pressed={activeType === "all"} onClick={() => setTypeFilter("all")}>すべて</button>
          {presentTypes.map(({ type, label }) => <button key={type} type="button" aria-pressed={activeType === type} onClick={() => setTypeFilter(type)}>{label}</button>)}
        </div>}
        {entries.length > 0 && <div className="list-meta">
          <span>{filtered.length}件</span>
          <select className="list-sort" aria-label="並び順" value={sortOrder} onChange={(event) => setSortOrder(event.target.value as SortOrder)}>
            <option value="name">名前順</option>
            <option value="updated">更新順</option>
          </select>
        </div>}
      </div>
      <div className="entry-list">
        <div className="entry-list-content" ref={listRef}>
          <div className="entry-highlight" ref={highlightRef} aria-hidden="true" hidden />
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
          </div>) : listSections.map(renderSection))}
        </div>
      </div>
      <div className="sidebar-foot">
        <button className="btn sidebar-lock" type="button" disabled={busy || props.isLoading} onClick={() => { void props.onLock(); }}><LockIcon />ロック</button>
      </div>
    </aside>
    <section className="vault-detail" ref={detailRef} aria-label={isFormOpen ? "新しい項目" : props.isEditingEntry ? "項目の編集" : "項目の詳細"}>
      {showHeader && <div className="inspector-header">
        <div className="inspector-heading">
          <h1 className="inspector-title">{isFormOpen ? "新しい項目" : selectedEntry?.serviceName ?? ""}</h1>
          {selectedEntry && !isFormOpen && <p className="inspector-meta">
            {entryTypeLabel(selectedEntry.type)} · 更新 {new Date(selectedEntry.updatedAt).toLocaleDateString("ja-JP")}
            <span className="inspector-saved" role="status">{savedNotice ? "保存しました" : ""}</span>
          </p>}
        </div>
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
            setSavedNotice(true);
          }}
          onDelete={isFormOpen ? undefined : deleteSelected}
          onCancel={cancelEditing} /> :
        !props.isLoading && entries.length === 0 ? <div className="inspector-empty">
          <h2>最初のパスワードを追加しましょう</h2>
          <button className="btn btn--primary" type="button" disabled={busy} onClick={openCreate}><PlusIcon />追加</button>
        </div> : <div className="inspector-empty"><p>項目を選ぶと、ここに表示されます</p></div>}
      <div className="toast-region">
        {feedback && <p key={props.errorMessage || props.copyNotice?.id} className={`toast ${props.errorMessage ? "toast--error" : "toast--copy"}`} role={props.errorMessage ? "alert" : "status"}>
          {!props.errorMessage && (props.copyNotice?.clearsInMs ?? 0) > 0 && <svg className="copy-ring" viewBox="0 0 16 16" aria-hidden="true" style={{ ["--clear-ms" as string]: `${props.copyNotice?.clearsInMs}ms` }}>
            <circle cx="8" cy="8" r="6" /><circle className="copy-ring-remaining" cx="8" cy="8" r="6" pathLength="100" />
          </svg>}
          {feedback}
        </p>}
      </div>
    </section>
  </div>;
}
