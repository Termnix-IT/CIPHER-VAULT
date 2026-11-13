import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent, type MouseEvent, type PointerEvent } from "react";
import { UNGROUPED_GROUP_NAME as UNGROUPED } from "@password-manager/shared";
import type { EntryIcon, VaultEntry, VaultEntrySummary, VaultEntryType, VaultEntryUpsertPayload } from "@password-manager/shared/types";
import { EntryContextMenu } from "../components/EntryContextMenu";
import { EntryEditor, entryTypeLabel } from "../components/EntryEditor";
import { GroupDialog } from "../components/GroupDialog";
import { EntryIconBadge } from "../components/EntryIconBadge";
import { EntryIconPicker } from "../components/EntryIconPicker";
import { SIDEBAR_DEFAULT_WIDTH, clampSidebarWidth, readSidebarWidth, saveSidebarWidth } from "../lib/layout-prefs";
import { ChevronIcon, CloseIcon, FolderPlusIcon, PlusIcon, SearchIcon } from "../components/Icons";

export type CopyNotice = { id: number; text: string; clearsInMs: number | null };

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
  isSidebarCollapsed: boolean;
  onSidebarCollapsedChange: (collapsed: boolean) => void;
  entryIcons: Record<string, EntryIcon>;
  onSetEntryIcon: (id: string, icon: EntryIcon | null) => Promise<void>;
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
  onCreateEntry: (payload: VaultEntryUpsertPayload) => Promise<void>;
  onSelectEntry: (id: string) => Promise<void>;
  onUpdateEntry: (id: string, payload: VaultEntryUpsertPayload) => Promise<void>;
  onDeleteEntry: (id: string) => Promise<void>;
  onSetEntriesGroup: (ids: string[], group: string | null) => Promise<void>;
  onGeneratePassword: () => Promise<string>;
  onCopyToClipboard: (value: string, label: string) => Promise<void>;
};

const TYPE_FILTERS: { type: VaultEntryType; label: string }[] = [{ type: "login", label: "ログイン" }, { type: "apiKey", label: "APIキー" }, { type: "creditCard", label: "カード" }, { type: "financial", label: "銀行/証券" }];
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
  return entry.type === "creditCard" ? `•••• ${entry.cardLast4}` : entry.type === "apiKey" || entry.type === "financial" ? entryTypeLabel(entry.type) : entry.loginId;
}

export function VaultDashboard(props: VaultDashboardProps) {
  const { entries, selectedEntry, isFormOpen, isGroupedView, isSidebarCollapsed: collapsed, entryIcons } = props;
  const [sidebarWidth, setSidebarWidth] = useState(readSidebarWidth);
  const [resizing, setResizing] = useState(false);
  const [iconPicker, setIconPicker] = useState<{ id: string; x: number; y: number; opener: HTMLElement | null } | null>(null);
  const dashboardRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const focusSearch = useRef(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const [typeFilter, setTypeFilter] = useState<VaultEntryType | "all">("all");
  const [sortOrder, setSortOrder] = useState<SortOrder>("name");
  const [savedNotice, setSavedNotice] = useState(false);
  const [entryMenu, setEntryMenu] = useState<{ id: string; x: number; y: number } | null>(null);
  const [groupDialogIds, setGroupDialogIds] = useState<string[] | null>(null);
  const entryMenuRow = useRef<HTMLElement | null>(null);
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
  const groupNames = useMemo(() => [...new Set(entries.map((entry) => entry.group ?? "").filter((group) => group && group !== UNGROUPED))]
    .sort((a, b) => a.localeCompare(b, "ja")), [entries]);
  const menuEntry = entryMenu && entries.find((entry) => entry.id === entryMenu.id);
  const busy = props.isCreating || props.isUpdating || props.isDeleting || props.isLoadingDetail || props.isGeneratingPassword;
  const closeEntryMenu = useCallback((restoreFocus: boolean) => {
    if (restoreFocus) entryMenuRow.current?.focus();
    setEntryMenu(null);
  }, []);

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
  }, [filtered, listSections, selectedEntry?.id, isFormOpen, isGroupedView, collapsedGroups, props.isLoading, collapsed]);

  useEffect(() => {
    if (!collapsed && focusSearch.current) { focusSearch.current = false; searchRef.current?.focus(); }
  }, [collapsed]);

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
  /** Asks before an action that would drop unsaved input, and leaves the form only when there was some. */
  function confirmDiscard() {
    if (!canDiscard()) return false;
    if (props.hasUnsavedChanges) {
      props.onDirtyChange(false);
      props.onEditingChange(false);
      props.onFormOpenChange(false);
    }
    return true;
  }
  function deleteTarget(target: Pick<VaultEntrySummary, "id" | "serviceName">) {
    if (busy || !window.confirm(`「${target.serviceName}」を削除しますか？元に戻せません。`)) return;
    // Deleting the item being edited already answers what happens to its edits.
    if (!(props.isEditingEntry && selectedEntry?.id === target.id) && !confirmDiscard()) return;
    void props.onDeleteEntry(target.id).catch(() => {});
  }
  function deleteSelected() {
    if (selectedEntry) deleteTarget(selectedEntry);
  }
  function setGroup(id: string, group: string | null) {
    if (!busy && confirmDiscard()) void props.onSetEntriesGroup([id], group).catch(() => {});
  }
  function openGroupDialog(initialIds: string[]) {
    if (!busy && confirmDiscard()) setGroupDialogIds(initialIds);
  }
  async function submitGroup(ids: string[], group: string) {
    await props.onSetEntriesGroup(ids, group);
    // Show the result: a search would hide the group headings, and the group could be collapsed.
    setSearchTerm("");
    setCollapsedGroups((current) => { const next = new Set(current); next.delete(group); return next; });
    props.onGroupedViewChange(true);
  }
  function openEntryMenu(event: MouseEvent<HTMLButtonElement>, id: string) {
    event.preventDefault();
    if (busy) return;
    // The menu key has no pointer position, so its menu opens under the row.
    const rect = event.currentTarget.getBoundingClientRect(), fromPointer = event.button === 2;
    entryMenuRow.current = event.currentTarget;
    setEntryMenu({ id, x: fromPointer ? event.clientX : rect.left + 16, y: fromPointer ? event.clientY : rect.bottom });
  }
  function openIconPicker(id: string, opener: HTMLElement | null, x: number, y: number) {
    if (!busy) setIconPicker({ id, x, y, opener });
  }
  const closeIconPicker = useCallback(() => {
    setIconPicker((current) => { current?.opener?.focus(); return null; });
  }, []);

  // The pane's edge follows the pointer directly; the width is kept once the drag ends.
  function startResize(event: PointerEvent<HTMLDivElement>) {
    if (event.button !== 0) return;
    event.preventDefault();
    const handle = event.currentTarget, start = event.clientX, from = sidebarWidth;
    handle.setPointerCapture(event.pointerId);
    setResizing(true);
    let width = from;
    const move = (next: globalThis.PointerEvent) => {
      width = clampSidebarWidth(from + next.clientX - start);
      dashboardRef.current?.style.setProperty("--sidebar-width", `${width}px`);
    };
    const end = () => {
      handle.removeEventListener("pointermove", move);
      handle.removeEventListener("pointerup", end);
      handle.removeEventListener("pointercancel", end);
      setResizing(false); setSidebarWidth(width); saveSidebarWidth(width);
    };
    handle.addEventListener("pointermove", move);
    handle.addEventListener("pointerup", end);
    handle.addEventListener("pointercancel", end);
  }
  function resizeByKey(event: KeyboardEvent<HTMLDivElement>) {
    const step = event.shiftKey ? 48 : 16;
    const next = event.key === "ArrowLeft" ? sidebarWidth - step : event.key === "ArrowRight" ? sidebarWidth + step
      : event.key === "Home" ? 0 : event.key === "End" ? Infinity : event.key === "Enter" ? SIDEBAR_DEFAULT_WIDTH : null;
    if (next === null) return;
    event.preventDefault();
    const width = clampSidebarWidth(next);
    setSidebarWidth(width); saveSidebarWidth(width);
  }

  function renderEntry(entry: VaultEntrySummary) {
    const active = !isFormOpen && selectedEntry?.id === entry.id;
    return <button key={entry.id} type="button" data-entry-id={entry.id}
      className={`entry-row ${active ? "entry-row--active" : ""} ${entryMenu?.id === entry.id ? "entry-row--menu" : ""}`}
      disabled={busy} aria-current={active ? "true" : undefined}
      aria-label={collapsed ? entry.serviceName : undefined} data-tooltip={collapsed ? entry.serviceName : undefined} data-tooltip-side="right"
      onContextMenu={(event) => openEntryMenu(event, entry.id)}
      onClick={() => {
        if (active) return;
        if (canDiscard()) { setSavedNotice(false); void props.onSelectEntry(entry.id); }
      }}>
      <EntryIconBadge name={entry.serviceName} icon={entryIcons[entry.id]} />
      {!collapsed && <span className="entry-info">
        <span className="entry-name">{entry.serviceName}</span>
        <span className="entry-login">{entrySubtitle(entry)}</span>
      </span>}
    </button>;
  }
  const feedback = props.errorMessage || props.copyNotice?.text;
  const showHeader = isFormOpen || Boolean(selectedEntry) || props.isLoadingDetail;
  const renderSection = ([name, items]: [string, VaultEntrySummary[]]) => <div key={name} role="group" aria-label={name}>
    <p className="list-section" aria-hidden="true">{name}</p>
    {items.map(renderEntry)}
  </div>;

  const pickerEntry = iconPicker && entries.find((entry) => entry.id === iconPicker.id);
  const searchLabel = search ? `検索（「${searchTerm.trim()}」で絞り込み中）` : "検索";

  return <div className={`cipher-dashboard ${collapsed ? "cipher-dashboard--collapsed" : ""} ${resizing ? "cipher-dashboard--resizing" : ""}`} ref={dashboardRef}
    style={{ ["--sidebar-width" as string]: `${sidebarWidth}px` }} aria-busy={busy || props.isLoading}>
    <aside className="vault-sidebar" aria-label="項目の一覧">
      {collapsed ? <div className="sidebar-controls sidebar-rail">
        <button className={`icon-btn ${search ? "sidebar-rail-search--active" : ""}`} type="button"
          aria-label={searchLabel} data-tooltip={searchLabel} data-tooltip-side="right"
          onClick={() => { focusSearch.current = true; props.onSidebarCollapsedChange(false); }}><SearchIcon /></button>
        <button className="icon-btn" type="button" aria-label="新しい項目" data-tooltip="新しい項目" data-tooltip-side="right" disabled={busy || isFormOpen} onClick={openCreate}><PlusIcon /></button>
      </div> : <div className="sidebar-controls">
        <div className="sidebar-head">
          <div className="search-box">
            <SearchIcon />
            <input className="search-input" type="search" aria-label="検索" placeholder="検索" ref={searchRef}
              value={searchTerm} onChange={(event) => setSearchTerm(event.target.value)} />
            {search && <span className="search-count" role="status">{filtered.length} / {entries.length}</span>}
            {searchTerm && <button className="icon-btn" type="button" aria-label="検索をクリア" onClick={() => setSearchTerm("")}><CloseIcon /></button>}
          </div>
          <button className="btn sidebar-add" type="button" aria-label="新しい項目" data-tooltip="新しい項目" disabled={busy || isFormOpen} onClick={openCreate}><PlusIcon /></button>
          <button className="btn sidebar-group-add" type="button" aria-label="新しいグループ" data-tooltip="新しいグループ" disabled={busy || entries.length === 0} onClick={() => openGroupDialog([])}><FolderPlusIcon /></button>
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
      </div>}
      <div className="entry-list">
        <div className="entry-list-content" ref={listRef}>
          <div className="entry-highlight" ref={highlightRef} aria-hidden="true" hidden />
          {props.isLoading && <p className="empty-state-text" role="status">読み込み中…</p>}
          {!props.isLoading && search && filtered.length === 0 && <p className="empty-state-text">見つかりません</p>}
          {!props.isLoading && collapsed && (isGroupedView && !search
            ? groups.map(([name, items]) => <div key={name} className="rail-group" role="group" aria-label={name}>{items.map(renderEntry)}</div>)
            : filtered.map(renderEntry))}
          {!props.isLoading && !collapsed && (isGroupedView && !search ? groups.map(([name, items]) => <div key={name}>
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
    </aside>
    {!collapsed && <div className="pane-resizer" role="separator" aria-orientation="vertical" aria-label="一覧の幅" tabIndex={0}
      aria-valuemin={clampSidebarWidth(0)} aria-valuemax={clampSidebarWidth(Infinity)} aria-valuenow={sidebarWidth}
      onPointerDown={startResize} onKeyDown={resizeByKey} onDoubleClick={() => { setSidebarWidth(SIDEBAR_DEFAULT_WIDTH); saveSidebarWidth(SIDEBAR_DEFAULT_WIDTH); }} />}
    <section className="vault-detail" ref={detailRef} aria-label={isFormOpen ? "新しい項目" : props.isEditingEntry ? "項目の編集" : "項目の詳細"}>
      {showHeader && <div className="inspector-header">
        {selectedEntry && !isFormOpen && <button className="inspector-icon" type="button" disabled={busy}
          aria-label="アイコンを編集" data-tooltip="アイコンを編集" aria-haspopup="dialog" aria-expanded={iconPicker?.id === selectedEntry.id}
          onClick={(event) => { const rect = event.currentTarget.getBoundingClientRect(); openIconPicker(selectedEntry.id, event.currentTarget, rect.left, rect.bottom + 6); }}>
          <EntryIconBadge name={selectedEntry.serviceName} icon={entryIcons[selectedEntry.id]} className="entry-badge--large" />
        </button>}
        <div className="inspector-heading">
          <h1 className="inspector-title">{isFormOpen ? "新しい項目" : selectedEntry?.serviceName ?? ""}</h1>
          {selectedEntry && !isFormOpen && <p className="inspector-meta">
            {entryTypeLabel(selectedEntry.type)} · 更新 {new Date(selectedEntry.updatedAt).toLocaleDateString("ja-JP")}
            <span className="inspector-saved" role="status">{savedNotice ? "保存しました" : ""}</span>
          </p>}
        </div>
        {selectedEntry && !isFormOpen && !props.isEditingEntry && <div className="inspector-actions">
          <button className="btn" type="button" disabled={busy} onClick={props.onEditEntry}>編集</button>
          <button className="btn btn--danger" type="button" disabled={busy} onClick={deleteSelected}>削除</button>
        </div>}
      </div>}
      {props.isLoadingDetail ? <p className="empty-state-text" role="status">開いています…</p> : isFormOpen || selectedEntry ?
        <EntryEditor key={isFormOpen ? "new" : selectedEntry!.id}
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
    {entryMenu && menuEntry && <EntryContextMenu key={menuEntry.id} entry={menuEntry} x={entryMenu.x} y={entryMenu.y} groupNames={groupNames} onClose={closeEntryMenu}
      onAddToGroup={(group) => setGroup(menuEntry.id, group)} onNewGroup={() => openGroupDialog([menuEntry.id])}
      onRemoveFromGroup={() => setGroup(menuEntry.id, null)} onDelete={() => deleteTarget(menuEntry)}
      onChangeIcon={() => openIconPicker(menuEntry.id, entryMenuRow.current, entryMenu.x, entryMenu.y)} />}
    {iconPicker && pickerEntry && <EntryIconPicker key={pickerEntry.id} name={pickerEntry.serviceName} icon={entryIcons[pickerEntry.id] ?? null}
      x={iconPicker.x} y={iconPicker.y} onClose={closeIconPicker} onSave={(icon) => props.onSetEntryIcon(pickerEntry.id, icon)} />}
    {groupDialogIds && <GroupDialog entries={entries} groupNames={groupNames} initialIds={groupDialogIds} onSubmit={submitGroup} onClose={() => setGroupDialogIds(null)} />}
  </div>;
}
