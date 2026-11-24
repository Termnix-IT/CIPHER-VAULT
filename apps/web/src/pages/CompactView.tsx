import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import type { EntryIcon, VaultEntry, VaultEntrySummary } from "@password-manager/shared/types";
import { EntryEditor } from "../components/EntryEditor";
import { EntryIconBadge } from "../components/EntryIconBadge";
import { FeedbackToast } from "../components/FeedbackToast";
import { BackIcon, CloseIcon, ExpandIcon, PinIcon, SearchIcon, StarIcon } from "../components/Icons";
import { byLastUsed, byName, entrySubtitle, entryTypeLabel, matchesSearch, normalizeSearch } from "../lib/entry-list";
import type { CopyNotice } from "./VaultDashboard";

/** How many recently used entries the compact list shows above the rest. */
const RECENT_LIMIT = 8;

type CompactViewProps = {
  entries: VaultEntrySummary[];
  entryIcons: Record<string, EntryIcon>;
  selectedEntry: VaultEntry | null;
  isLoading: boolean;
  isLoadingDetail: boolean;
  busy: boolean;
  errorMessage: string;
  copyNotice: CopyNotice | null;
  isAlwaysOnTop: boolean;
  onAlwaysOnTopChange: (onTop: boolean) => void;
  onExitCompact: () => void;
  onSelectEntry: (id: string) => Promise<void>;
  onCopyToClipboard: (value: string, label: string, entryId?: string) => Promise<void>;
  onOpenUrl: (id: string) => void;
  onSetEntryFavorite: (id: string, favorite: boolean) => void;
  onDirtyChange: (dirty: boolean) => void;
  /** The entry shown in full, or null for the list. The shortcuts act only on this one. */
  onDetailChange: (id: string | null) => void;
  searchFocusRequest: number;
};

const noGeneration = () => Promise.reject(new Error("コンパクト表示では生成できません"));
const noSave = async () => undefined;
const noCancel = () => undefined;

/**
 * One narrow column for signing in: find an entry, then copy its ID and secret or open its URL.
 * Notes, tags and groups stay in the normal view, and so does editing. Secrets keep the normal
 * view's rules: two clicks to show, hidden again on any change, and copies that expire.
 */
export function CompactView(props: CompactViewProps) {
  const { entries, entryIcons, selectedEntry } = props;
  const [searchTerm, setSearchTerm] = useState("");
  const [favoritesOnly, setFavoritesOnly] = useState(false);
  // The entry this view shows. It starts on the entry the normal view had open.
  const [detailId, setDetailId] = useState<string | null>(() => selectedEntry?.id ?? null);
  const searchRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const search = normalizeSearch(searchTerm);

  const groups = useMemo(() => {
    const matching = entries.filter((entry) => (!favoritesOnly || entry.favorite) && matchesSearch(entry, search));
    if (search) return [{ name: "検索結果", items: [...matching].sort((a, b) => Number(Boolean(b.favorite)) - Number(Boolean(a.favorite)) || byLastUsed(a, b)) }];
    const favorites = matching.filter((entry) => entry.favorite).sort(byName);
    if (favoritesOnly) return [{ name: "お気に入り", items: favorites }];
    const recent = matching.filter((entry) => !entry.favorite && entry.lastUsedAt).sort(byLastUsed).slice(0, RECENT_LIMIT);
    const shown = new Set([...favorites, ...recent].map((entry) => entry.id));
    const rest = matching.filter((entry) => !shown.has(entry.id)).sort(byName);
    return [{ name: "お気に入り", items: favorites }, { name: "最近使用", items: recent },
      { name: favorites.length || recent.length ? "そのほか" : "すべて", items: rest }].filter((group) => group.items.length > 0);
  }, [entries, search, favoritesOnly]);
  const firstMatch = groups[0]?.items[0];
  const detailSummary = detailId ? entries.find((entry) => entry.id === detailId) : undefined;
  const showingDetail = Boolean(detailId && detailSummary);

  useEffect(() => { if (!showingDetail) searchRef.current?.focus(); }, []);
  useEffect(() => {
    props.onDetailChange(showingDetail ? detailId : null);
    return () => props.onDetailChange(null);
  }, [showingDetail, detailId]);
  // Only a request made while this view is shown; one made before it opened was for the normal view.
  const handledFocusRequest = useRef(props.searchFocusRequest);
  useEffect(() => {
    if (props.searchFocusRequest === handledFocusRequest.current) return;
    handledFocusRequest.current = props.searchFocusRequest;
    setDetailId(null);
    searchRef.current?.focus(); searchRef.current?.select();
  }, [props.searchFocusRequest]);
  // An entry deleted or locked away elsewhere leaves the list on screen.
  useEffect(() => { if (detailId && !detailSummary && !props.isLoading) setDetailId(null); }, [detailId, detailSummary, props.isLoading]);

  function open(id: string) {
    setDetailId(id);
    if (selectedEntry?.id !== id) void props.onSelectEntry(id);
  }
  function backToList() {
    const id = detailId;
    setDetailId(null);
    // The row the entry came from keeps the place, so the arrow keys go on from there.
    window.setTimeout(() => (listRef.current?.querySelector<HTMLElement>(`[data-entry-id="${CSS.escape(id ?? "")}"]`) ?? searchRef.current)?.focus(), 0);
  }
  function moveFocus(event: KeyboardEvent<HTMLElement>) {
    if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
    const rows = [...(listRef.current?.querySelectorAll<HTMLButtonElement>(".entry-row:not(:disabled)") ?? [])];
    if (!rows.length) return;
    event.preventDefault();
    const current = rows.indexOf(document.activeElement as HTMLButtonElement);
    const next = current < 0 ? (event.key === "ArrowDown" ? 0 : rows.length - 1)
      : event.key === "ArrowDown" ? Math.min(rows.length - 1, current + 1) : current - 1;
    if (next < 0) searchRef.current?.focus();
    else rows[next].focus();
  }
  function favoriteButton(entry: VaultEntrySummary) {
    const label = entry.favorite ? "お気に入りから外す" : "お気に入りに追加";
    return <button className={`icon-btn favorites-toggle ${entry.favorite ? "favorites-toggle--on" : ""}`} type="button" aria-pressed={Boolean(entry.favorite)}
      aria-label={label} data-tooltip={label} onClick={() => props.onSetEntryFavorite(entry.id, !entry.favorite)}><StarIcon filled={entry.favorite} /></button>;
  }

  const favoritesLabel = favoritesOnly ? "すべての項目を表示" : "お気に入りだけを表示";
  const pinLabel = props.isAlwaysOnTop ? "最前面の表示をやめる" : "常に手前に表示";
  return <div className="compact-view" aria-busy={props.busy || props.isLoading}>
    <div className="compact-head">
      <div className="search-box">
        <SearchIcon />
        <input className="search-input" type="search" aria-label="検索" placeholder="検索（Ctrl+F）" ref={searchRef} value={searchTerm}
          onChange={(event) => { setSearchTerm(event.target.value); setDetailId(null); }}
          onKeyDown={(event) => {
            if (event.key === "Enter" && firstMatch) { event.preventDefault(); open(firstMatch.id); }
            else if (event.key === "ArrowDown") moveFocus(event);
          }} />
        {searchTerm && <button className="icon-btn" type="button" aria-label="検索をクリア" onClick={() => { setSearchTerm(""); searchRef.current?.focus(); }}><CloseIcon /></button>}
      </div>
      <button className={`icon-btn favorites-toggle ${favoritesOnly ? "favorites-toggle--on" : ""}`} type="button" aria-pressed={favoritesOnly}
        aria-label={favoritesLabel} data-tooltip={favoritesLabel} onClick={() => { setFavoritesOnly(!favoritesOnly); setDetailId(null); }}><StarIcon filled={favoritesOnly} /></button>
      <button className={`icon-btn compact-pin ${props.isAlwaysOnTop ? "compact-pin--on" : ""}`} type="button" aria-pressed={props.isAlwaysOnTop}
        aria-label={pinLabel} data-tooltip={pinLabel} onClick={() => props.onAlwaysOnTopChange(!props.isAlwaysOnTop)}><PinIcon pinned={props.isAlwaysOnTop} /></button>
      <button className="icon-btn" type="button" aria-label="通常表示に戻す" data-tooltip="通常表示に戻す（Ctrl+Shift+M）" onClick={props.onExitCompact}><ExpandIcon /></button>
    </div>
    {showingDetail && detailSummary ? <section className="compact-detail" aria-label="項目の詳細"
      onKeyDown={(event) => { if (event.key === "Escape") { event.preventDefault(); backToList(); } }}>
      <div className="compact-detail-head">
        <button className="icon-btn" type="button" aria-label="一覧に戻る" data-tooltip="一覧に戻る（Esc）" onClick={backToList}><BackIcon /></button>
        <EntryIconBadge name={detailSummary.serviceName} icon={entryIcons[detailSummary.id]} />
        <div className="compact-detail-heading">
          <h1 className="compact-detail-title">{detailSummary.serviceName}</h1>
          <p className="inspector-meta">{entryTypeLabel(detailSummary.type)}</p>
        </div>
        {favoriteButton(detailSummary)}
      </div>
      {props.isLoadingDetail || selectedEntry?.id !== detailSummary.id ? <p className="empty-state-text" role="status">開いています…</p> :
        <EntryEditor key={selectedEntry.id} compact entry={selectedEntry} isEditing={false} busy={props.busy} isSaving={false} isGenerating={false}
          onDirtyChange={props.onDirtyChange} onGenerate={noGeneration} onSave={noSave} onCancel={noCancel}
          onCopy={(value, label) => props.onCopyToClipboard(value, label, selectedEntry.id)}
          onOpenUrl={() => props.onOpenUrl(selectedEntry.id)} />}
    </section> : <div className="entry-list compact-list" ref={listRef} onKeyDown={moveFocus}>
      {props.isLoading && <p className="empty-state-text" role="status">読み込み中…</p>}
      {!props.isLoading && groups.length === 0 && <p className="empty-state-text">
        {search ? "見つかりません" : favoritesOnly ? "お気に入りはまだありません" : "項目がありません。通常表示で追加できます"}</p>}
      {!props.isLoading && groups.map((group) => <div key={group.name} role="group" aria-label={group.name}>
        <p className="list-section" aria-hidden="true">{group.name}</p>
        {group.items.map((entry) => <button key={entry.id} type="button" data-entry-id={entry.id} disabled={props.busy}
          className={`entry-row ${selectedEntry?.id === entry.id ? "entry-row--active" : ""}`} onClick={() => open(entry.id)}>
          <EntryIconBadge name={entry.serviceName} icon={entryIcons[entry.id]} />
          <span className="entry-info">
            <span className="entry-name">{entry.serviceName}</span>
            <span className="entry-login">{entrySubtitle(entry)}</span>
          </span>
          {entry.favorite && <span className="entry-favorite" role="img" aria-label="お気に入り"><StarIcon filled /></span>}
        </button>)}
      </div>)}
    </div>}
    <FeedbackToast errorMessage={props.errorMessage} copyNotice={props.copyNotice} />
  </div>;
}
