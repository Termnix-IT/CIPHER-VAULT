import { useMemo, useState } from "react";
import type { PasswordEntry, PasswordEntrySummary, PasswordEntryUpsertPayload } from "@password-manager/shared/types";
import { EntryEditor } from "../components/EntryEditor";

type VaultDashboardProps = {
  hasUnsavedChanges: boolean;
  onDirtyChange: (dirty: boolean) => void;
  isFormOpen: boolean;
  onFormOpenChange: (open: boolean) => void;
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

  function canDiscard() {
    return !props.hasUnsavedChanges || window.confirm("未保存の変更を破棄しますか？");
  }
  function toggleCreate() {
    if (busy || !canDiscard()) return;
    props.onFormOpenChange(!isFormOpen);
  }
  function renderEntry(entry: PasswordEntrySummary) {
    return <button key={entry.id} type="button"
      className={`entry-row ${!isFormOpen && selectedEntry?.id === entry.id ? "entry-row--active" : ""}`}
      disabled={busy} aria-current={!isFormOpen && selectedEntry?.id === entry.id ? "true" : undefined}
      onClick={() => {
        if (!isFormOpen && selectedEntry?.id === entry.id) return;
        if (canDiscard()) void props.onSelectEntry(entry.id);
      }}>
      <span className="entry-cursor" aria-hidden="true">&gt;</span>
      <span className="entry-badge" aria-hidden="true">{entry.serviceName.charAt(0).toUpperCase()}</span>
      <span className="entry-info">
        <span className="entry-name">{entry.serviceName}</span>
        <span className="entry-login">{entry.loginId}</span>
        {entry.tags.length > 0 && <span className="entry-tags">{entry.tags.map((tag, index) => <span key={`${tag}-${index}`} className="tag-chip">{tag}</span>)}</span>}
      </span>
      <span className="entry-date">{new Date(entry.updatedAt).toLocaleDateString("ja-JP")}</span>
    </button>;
  }
  return <div className="cipher-dashboard">
    <div className="dashboard-body">
      <aside className="vault-sidebar" aria-label="エントリ一覧">
        <div className="sidebar-head">
          <p className="sidebar-count" role="status">{search ? <>検索結果 <strong>{filtered.length}件</strong> / 全{entries.length}件</> : <>登録済み <strong>{entries.length}件</strong></>}</p>
          <div className="search-prompt">
            <span className="search-prompt-char" aria-hidden="true">&gt;</span>
            <input className="search-input" type="search" aria-label="エントリを検索" placeholder="サービス名・ID・グループ・タグで検索"
              value={searchTerm} onChange={(event) => setSearchTerm(event.target.value)} />
            {searchTerm && <button className="search-clear-btn" type="button" aria-label="検索条件をクリア" onClick={() => setSearchTerm("")}>×</button>}
          </div>
        </div>
        <div className="sidebar-actions">
          <button className="cipher-btn" type="button" disabled={busy} onClick={toggleCreate}>{isFormOpen ? "キャンセル" : "+ 新規追加"}</button>
          <button className={`cipher-btn ${isGroupedView ? "cipher-btn--primary" : ""}`} type="button" aria-pressed={isGroupedView}
            onClick={() => props.onGroupedViewChange(!isGroupedView)}>{isGroupedView ? "全件表示" : "グループ"}</button>
        </div>
        <div className="entry-list">
          {props.isLoading && <p className="empty-state-text" role="status">読み込み中…</p>}
          {!props.isLoading && filtered.length === 0 && <p className="empty-state-text">{search ? "一致するエントリがありません。" : "新規追加からエントリを登録してください。"}</p>}
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
      </aside>
      <section className="vault-detail" aria-label={isFormOpen ? "新規エントリ" : "エントリの詳細と編集"}>
        <div className="inspector-header">
          <h1 className="inspector-title">{isFormOpen ? "新規エントリ" : selectedEntry?.serviceName ?? "エントリを選択"}</h1>
          {(props.errorMessage || props.copyMessage) && <p className={`status-msg ${props.errorMessage ? "status-msg--error" : "status-msg--copy"}`} role={props.errorMessage ? "alert" : "status"}>
            {props.errorMessage || props.copyMessage}
          </p>}
        </div>
        {props.isLoadingDetail ? <p className="empty-state-text" role="status">復号中…</p> : isFormOpen || selectedEntry ?
          <EntryEditor key={isFormOpen ? "new" : selectedEntry!.id}
            entry={isFormOpen ? null : selectedEntry} busy={busy} isSaving={props.isCreating || props.isUpdating}
            isGenerating={props.isGeneratingPassword} onDirtyChange={props.onDirtyChange}
            onGenerate={props.onGeneratePassword} onCopy={props.onCopyToClipboard}
            onSave={async (payload) => {
              if (isFormOpen) { await props.onCreateEntry(payload); props.onFormOpenChange(false); }
              else if (selectedEntry) await props.onUpdateEntry(selectedEntry.id, payload);
            }}
            onDelete={async () => {
              if (selectedEntry && window.confirm(`「${selectedEntry.serviceName}」を削除しますか？`)) await props.onDeleteEntry(selectedEntry.id);
            }} onCancel={toggleCreate} /> :
          <div className="inspector-empty"><h2>左の一覧からエントリを選択</h2><p>ログイン情報の確認・コピー・編集ができます。</p></div>}
      </section>
    </div>
  </div>;
}
