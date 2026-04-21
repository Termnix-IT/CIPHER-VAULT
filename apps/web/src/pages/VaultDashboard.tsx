import type { FormEvent } from "react";
import { useEffect, useRef, useState } from "react";
import type {
  PasswordEntry,
  PasswordEntrySummary,
  PasswordEntryUpsertPayload,
} from "@password-manager/shared/types";

type VaultDashboardProps = {
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

function useUptime(): string {
  const startRef = useRef(Date.now());
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const id = setInterval(() => {
      setElapsed(Date.now() - startRef.current);
    }, 1000);
    return () => clearInterval(id);
  }, []);

  const totalSec = Math.floor(elapsed / 1000);
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

export function VaultDashboard({
  entries,
  isLoading,
  isCreating,
  isUpdating,
  isDeleting,
  isLoadingDetail,
  isGeneratingPassword,
  selectedEntry,
  errorMessage,
  copyMessage,
  onLock,
  onRefresh,
  onCreateEntry,
  onSelectEntry,
  onUpdateEntry,
  onDeleteEntry,
  onGeneratePassword,
  onCopyToClipboard,
}: VaultDashboardProps) {
  const uptime = useUptime();
  const [searchTerm, setSearchTerm] = useState("");
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [isGroupedView, setIsGroupedView] = useState(false);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());

  // Create form state
  const [serviceName, setServiceName] = useState("");
  const [loginId, setLoginId] = useState("");
  const [password, setPassword] = useState("");
  const [url, setUrl] = useState("");
  const [notes, setNotes] = useState("");
  const [tagInput, setTagInput] = useState("");
  const [groupInput, setGroupInput] = useState("");

  // Edit form state
  const [editServiceName, setEditServiceName] = useState("");
  const [editLoginId, setEditLoginId] = useState("");
  const [editPassword, setEditPassword] = useState("");
  const [editUrl, setEditUrl] = useState("");
  const [editNotes, setEditNotes] = useState("");
  const [editTagInput, setEditTagInput] = useState("");
  const [editGroupInput, setEditGroupInput] = useState("");

  // Copy glitch state
  const [glitchField, setGlitchField] = useState<string | null>(null);
  const glitchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!selectedEntry) {
      setEditServiceName("");
      setEditLoginId("");
      setEditPassword("");
      setEditUrl("");
      setEditNotes("");
      setEditTagInput("");
      setEditGroupInput("");
      return;
    }
    setEditServiceName(selectedEntry.serviceName);
    setEditLoginId(selectedEntry.loginId);
    setEditPassword(selectedEntry.password);
    setEditUrl(selectedEntry.url);
    setEditNotes(selectedEntry.notes);
    setEditTagInput(selectedEntry.tags.join(", "));
    setEditGroupInput(selectedEntry.group ?? "");
  }, [selectedEntry]);

  useEffect(() => {
    return () => {
      if (glitchTimerRef.current !== null) clearTimeout(glitchTimerRef.current);
    };
  }, []);

  const normalized = searchTerm.trim().toLowerCase();
  const filteredEntries = !normalized
    ? entries
    : entries.filter(
        (entry) =>
          entry.serviceName.toLowerCase().includes(normalized) ||
          entry.loginId.toLowerCase().includes(normalized) ||
          entry.tags.some((tag) => tag.toLowerCase().includes(normalized))
      );

  // Group entries by group field (only used when isGroupedView and no search)
  const groupedEntries = (() => {
    const map = new Map<string, typeof entries>();
    for (const entry of filteredEntries) {
      const key = entry.group || "未分類";
      const list = map.get(key) ?? [];
      list.push(entry);
      map.set(key, list);
    }
    return Array.from(map.entries())
      .map(([name, items]) => ({ name, items }))
      .sort((a, b) => {
        if (a.name === "未分類") return 1;
        if (b.name === "未分類") return -1;
        return a.name.localeCompare(b.name, "ja");
      });
  })();

  function toggleGroup(name: string) {
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }

  async function handleCopyWithGlitch(value: string, label: string, field: string) {
    setGlitchField(field);
    await onCopyToClipboard(value, label);
    if (glitchTimerRef.current !== null) clearTimeout(glitchTimerRef.current);
    glitchTimerRef.current = setTimeout(() => setGlitchField(null), 400);
  }

  async function handleSubmitCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await onCreateEntry({
      serviceName,
      loginId,
      password,
      url,
      notes,
      tags: tagInput.split(",").map((t) => t.trim()).filter(Boolean),
      group: groupInput.trim() || undefined,
    });
    setServiceName("");
    setLoginId("");
    setPassword("");
    setUrl("");
    setNotes("");
    setTagInput("");
    setGroupInput("");
    setIsFormOpen(false);
  }

  async function handleSubmitUpdate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedEntry) return;
    await onUpdateEntry(selectedEntry.id, {
      serviceName: editServiceName,
      loginId: editLoginId,
      password: editPassword,
      url: editUrl,
      notes: editNotes,
      tags: editTagInput.split(",").map((t) => t.trim()).filter(Boolean),
      group: editGroupInput.trim() || undefined,
    });
  }

  async function handleDeleteEntry() {
    if (!selectedEntry) return;
    await onDeleteEntry(selectedEntry.id);
    setEditServiceName("");
    setEditLoginId("");
    setEditPassword("");
    setEditUrl("");
    setEditNotes("");
    setEditTagInput("");
  }

  async function handleGenerateForCreate() {
    const next = await onGeneratePassword();
    setPassword(next);
  }

  async function handleGenerateForEdit() {
    const next = await onGeneratePassword();
    setEditPassword(next);
  }

  return (
    <div className="cipher-dashboard">
      {/* ── Header ── */}
      <header className="cipher-header">
        <div className="header-left">
          <span className="header-logo">
            <span className="header-logo-type">VAULT</span>
            <span className="header-logo-sep">://</span>
            <span className="header-logo-name">SECURE</span>
          </span>
          <span className="secure-indicator">
            <span className="secure-dot" aria-hidden="true" />
            <span>接続中</span>
          </span>
        </div>

        <div className="header-status">
          <span>
            エントリ数:{" "}
            <span className="uptime-value">{entries.length}</span>
          </span>
          <span className="status-sep">|</span>
          <span>
            稼働時間: <span className="uptime-value">{uptime}</span>
          </span>
          {selectedEntry ? (
            <>
              <span className="status-sep">|</span>
              <span>
                選択中:{" "}
                <span className="selected-label">{selectedEntry.serviceName}</span>
              </span>
            </>
          ) : null}
        </div>

        <div style={{ display: "flex", gap: "8px", flexShrink: 0 }}>
          <button
            className="cipher-btn"
            type="button"
            onClick={() => void onRefresh()}
          >
            [ 更新 ]
          </button>
          <button
            className="cipher-btn cipher-btn--primary"
            type="button"
            onClick={() => void onLock()}
          >
            [ ロック ]
          </button>
        </div>
      </header>

      {/* ── Body ── */}
      <div className="dashboard-body">
        {/* ── Sidebar ── */}
        <aside className="vault-sidebar">
          <div className="sidebar-head">
            <p className="sidebar-eyebrow">// エントリ一覧</p>
            <div className="search-prompt">
              <span className="search-prompt-char">&gt;</span>
              <input
                className="search-input"
                type="search"
                placeholder="サービス名・ID・タグで検索_"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          </div>

          <div className="sidebar-actions">
            <button
              className="cipher-btn"
              type="button"
              onClick={() => setIsFormOpen((v) => !v)}
            >
              {isFormOpen ? "[ キャンセル ]" : "[+ 新規追加 ]"}
            </button>
            <button
              className={`cipher-btn ${isGroupedView ? "cipher-btn--primary" : ""}`}
              type="button"
              onClick={() => setIsGroupedView((v) => !v)}
              title={isGroupedView ? "全件表示に切り替え" : "グループ表示に切り替え"}
            >
              {isGroupedView ? "[ 全件 ]" : "[ グループ ]"}
            </button>
          </div>

          {/* New entry form */}
          {isFormOpen ? (
            <div className="new-entry-form">
              <form className="new-entry-form-inner" onSubmit={handleSubmitCreate}>
                <p className="form-section-title">&gt;_ 新規エントリ</p>

                <div className="form-field">
                  <span className="form-label">サービス</span>
                  <input
                    className="form-input"
                    value={serviceName}
                    onChange={(e) => setServiceName(e.target.value)}
                    required
                    placeholder="github.com_"
                  />
                </div>

                <div className="form-field">
                  <span className="form-label">ログインID</span>
                  <input
                    className="form-input"
                    value={loginId}
                    onChange={(e) => setLoginId(e.target.value)}
                    required
                    placeholder="user@email.com_"
                  />
                </div>

                <div className="form-field">
                  <span className="form-label">パスワード</span>
                  <div className="form-inline">
                    <input
                      className="form-input"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      placeholder="••••••••••••_"
                    />
                    <button
                      className="cipher-btn"
                      type="button"
                      onClick={() => void handleGenerateForCreate()}
                    >
                      {isGeneratingPassword ? "[...]" : "[生成]"}
                    </button>
                  </div>
                </div>

                <div className="form-field">
                  <span className="form-label">URL</span>
                  <input
                    className="form-input"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://_"
                  />
                </div>

                <div className="form-field">
                  <span className="form-label">グループ</span>
                  <input
                    className="form-input"
                    value={groupInput}
                    onChange={(e) => setGroupInput(e.target.value)}
                    placeholder="仕事_"
                  />
                </div>

                <div className="form-field">
                  <span className="form-label">タグ</span>
                  <input
                    className="form-input"
                    value={tagInput}
                    onChange={(e) => setTagInput(e.target.value)}
                    placeholder="仕事, 金融, メール_"
                  />
                </div>

                <div className="form-field">
                  <span className="form-label">メモ</span>
                  <textarea
                    className="form-textarea"
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    rows={3}
                    placeholder="_"
                  />
                </div>

                <div className="form-btn-row">
                  <button
                    className="cipher-btn cipher-btn--primary"
                    type="submit"
                    disabled={isCreating}
                  >
                    {isCreating ? "[ 保存中... ]" : "[ 保存 ]"}
                  </button>
                </div>
              </form>
            </div>
          ) : null}

          {/* Entry list */}
          <div className="entry-list" role="list">
            {isLoading ? (
              <p className="loading-text" style={{ padding: "16px" }}>
                &gt; 読み込み中...
              </p>
            ) : null}

            {!isLoading && filteredEntries.length === 0 ? (
              <p className="empty-state-text">
                &gt; エントリが見つかりません。上から追加してください。
              </p>
            ) : null}

            {/* Grouped view (only when no search term) */}
            {!isLoading && isGroupedView && !normalized
              ? groupedEntries.map((group) => (
                  <div key={group.name}>
                    <button
                      className="group-header"
                      type="button"
                      onClick={() => toggleGroup(group.name)}
                    >
                      <span className="group-header-arrow">
                        {collapsedGroups.has(group.name) ? "▶" : "▼"}
                      </span>
                      <span className="group-header-name">{group.name}</span>
                      <span className="group-header-count">[{group.items.length}]</span>
                    </button>
                    {!collapsedGroups.has(group.name)
                      ? group.items.map((entry, index) => (
                          <article
                            key={entry.id}
                            className={`entry-row ${
                              selectedEntry?.id === entry.id ? "entry-row--active" : ""
                            }`}
                            style={{ animationDelay: `${index * 40}ms` }}
                            role="button"
                            tabIndex={0}
                            onClick={() => void onSelectEntry(entry.id)}
                            onKeyDown={(e) => {
                              if (e.key === "Enter" || e.key === " ") {
                                e.preventDefault();
                                void onSelectEntry(entry.id);
                              }
                            }}
                          >
                            <span className="entry-cursor" aria-hidden="true">&gt;</span>
                            <div className="entry-badge" aria-hidden="true">
                              {entry.serviceName.charAt(0).toUpperCase()}
                            </div>
                            <div className="entry-info">
                              <p className="entry-name">{entry.serviceName}</p>
                              <p className="entry-login">{entry.loginId}</p>
                              {entry.tags.length > 0 ? (
                                <div className="entry-tags">
                                  {entry.tags.map((tag) => (
                                    <span key={tag} className="tag-chip">{tag}</span>
                                  ))}
                                </div>
                              ) : null}
                            </div>
                            <span className="entry-date">
                              {new Date(entry.updatedAt).toLocaleDateString("ja-JP")}
                            </span>
                          </article>
                        ))
                      : null}
                  </div>
                ))
              : null}

            {/* Flat view (default, or when searching) */}
            {!isLoading && (!isGroupedView || normalized)
              ? filteredEntries.map((entry, index) => (
                  <article
                    key={entry.id}
                    className={`entry-row ${
                      selectedEntry?.id === entry.id ? "entry-row--active" : ""
                    }`}
                    style={{ animationDelay: `${index * 40}ms` }}
                    role="button"
                    tabIndex={0}
                    onClick={() => void onSelectEntry(entry.id)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        void onSelectEntry(entry.id);
                      }
                    }}
                  >
                    <span className="entry-cursor" aria-hidden="true">
                      &gt;
                    </span>
                    <div className="entry-badge" aria-hidden="true">
                      {entry.serviceName.charAt(0).toUpperCase()}
                    </div>
                    <div className="entry-info">
                      <p className="entry-name">{entry.serviceName}</p>
                      <p className="entry-login">{entry.loginId}</p>
                      {entry.tags.length > 0 ? (
                        <div className="entry-tags">
                          {entry.tags.map((tag) => (
                            <span key={tag} className="tag-chip">
                              {tag}
                            </span>
                          ))}
                        </div>
                      ) : null}
                    </div>
                    <span className="entry-date">
                      {new Date(entry.updatedAt).toLocaleDateString("ja-JP")}
                    </span>
                  </article>
                ))
              : null}
          </div>
        </aside>

        {/* ── Detail Panel ── */}
        <section className="vault-detail">
          <div className="inspector-header">
            <p className="inspector-eyebrow">// 詳細</p>

            {selectedEntry ? (
              <div className="inspector-quick-copy">
                <button
                  className="cipher-btn"
                  type="button"
                  style={{ fontSize: "0.75rem", padding: "6px 12px" }}
                  onClick={() =>
                    void handleCopyWithGlitch(
                      selectedEntry.loginId,
                      "ログインID",
                      "loginId-quick"
                    )
                  }
                >
                  [ IDをコピー ]
                </button>
                <button
                  className="cipher-btn cipher-btn--primary"
                  type="button"
                  style={{ fontSize: "0.75rem", padding: "6px 12px" }}
                  onClick={() =>
                    void handleCopyWithGlitch(
                      selectedEntry.password,
                      "パスワード",
                      "password-quick"
                    )
                  }
                >
                  [ パスワードをコピー ]
                </button>
              </div>
            ) : null}
          </div>

          <div className="inspector-body">
            {/* Status messages */}
            {copyMessage ? (
              <p className="status-msg status-msg--copy">&gt; {copyMessage}</p>
            ) : null}
            {errorMessage ? (
              <p className="status-msg status-msg--error">
                ! ERR: {errorMessage}
              </p>
            ) : null}

            {isLoadingDetail ? (
              <p className="loading-text">&gt; 復号中...</p>
            ) : null}

            {/* Empty state */}
            {!isLoadingDetail && !selectedEntry ? (
              <div className="inspector-empty">
                <span className="inspector-empty-tag">選択待ち</span>
                <h3>左一覧からエントリを選択</h3>
                <p>
                  サービス名・ログイン情報・メモ・タグ・コピー操作・編集フォームがここに表示されます。
                </p>
                <div className="inspector-empty-grid" aria-hidden="true" />
              </div>
            ) : null}

            {/* Entry detail */}
            {!isLoadingDetail && selectedEntry ? (
              <>
                {/* Read-only field list */}
                <div className="inspector-field-list">
                  <div className="inspector-field">
                    <span className="inspector-key">SERVICE</span>
                    <span className="inspector-value">
                      {selectedEntry.serviceName}
                    </span>
                  </div>

                  <div className="inspector-field">
                    <span className="inspector-key">LOGIN_ID</span>
                    <span className="inspector-value">{selectedEntry.loginId}</span>
                    <button
                      className={`copy-btn ${
                        glitchField === "loginId" ? "copy-btn--glitch" : ""
                      }`}
                      type="button"
                      onClick={() =>
                        void handleCopyWithGlitch(
                          selectedEntry.loginId,
                          "ログインID",
                          "loginId"
                        )
                      }
                    >
                      [コピー]
                    </button>
                  </div>

                  <div className="inspector-field">
                    <span className="inspector-key">PASSWORD</span>
                    <span className="inspector-value inspector-value--password">
                      {"•".repeat(Math.min(selectedEntry.password.length, 16))}
                    </span>
                    <button
                      className={`copy-btn ${
                        glitchField === "password" ? "copy-btn--glitch" : ""
                      }`}
                      type="button"
                      onClick={() =>
                        void handleCopyWithGlitch(
                          selectedEntry.password,
                          "パスワード",
                          "password"
                        )
                      }
                    >
                      [コピー]
                    </button>
                  </div>

                  {selectedEntry.url ? (
                    <div className="inspector-field">
                      <span className="inspector-key">URL</span>
                      <span className="inspector-value">{selectedEntry.url}</span>
                      <button
                        className={`copy-btn ${
                          glitchField === "url" ? "copy-btn--glitch" : ""
                        }`}
                        type="button"
                        onClick={() =>
                          void handleCopyWithGlitch(selectedEntry.url, "URL", "url")
                        }
                      >
                        [COPY]
                      </button>
                    </div>
                  ) : null}

                  {selectedEntry.group ? (
                    <div className="inspector-field">
                      <span className="inspector-key">GROUP</span>
                      <span className="inspector-value">{selectedEntry.group}</span>
                    </div>
                  ) : null}

                  {selectedEntry.tags.length > 0 ? (
                    <div className="inspector-field">
                      <span className="inspector-key">TAGS</span>
                      <div className="entry-tags" style={{ flex: 1 }}>
                        {selectedEntry.tags.map((tag) => (
                          <span key={tag} className="tag-chip">
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : null}

                  {selectedEntry.notes ? (
                    <div className="inspector-field" style={{ alignItems: "flex-start" }}>
                      <span className="inspector-key">NOTES</span>
                      <span
                        className="inspector-value"
                        style={{ whiteSpace: "pre-wrap" }}
                      >
                        {selectedEntry.notes}
                      </span>
                    </div>
                  ) : null}

                  <div className="inspector-field">
                    <span className="inspector-key">CREATED</span>
                    <span className="inspector-value inspector-value--muted">
                      {new Date(selectedEntry.createdAt).toLocaleDateString("ja-JP")}
                    </span>
                  </div>

                  <div className="inspector-field">
                    <span className="inspector-key">UPDATED</span>
                    <span className="inspector-value inspector-value--muted">
                      {new Date(selectedEntry.updatedAt).toLocaleDateString("ja-JP")}
                    </span>
                  </div>
                </div>

                {/* Edit form */}
                <form
                  className="inspector-edit-form"
                  onSubmit={handleSubmitUpdate}
                >
                  <p className="form-section-title">&gt;_ 編集</p>

                  <div className="inspector-form-grid">
                    <div className="form-field">
                      <span className="form-label">サービス</span>
                      <input
                        className="form-input"
                        value={editServiceName}
                        onChange={(e) => setEditServiceName(e.target.value)}
                        required
                      />
                    </div>

                    <div className="form-field">
                      <span className="form-label">ログインID</span>
                      <input
                        className="form-input"
                        value={editLoginId}
                        onChange={(e) => setEditLoginId(e.target.value)}
                        required
                      />
                    </div>

                    <div className="form-field">
                      <span className="form-label">パスワード</span>
                      <div className="form-inline">
                        <input
                          className="form-input"
                          type="password"
                          value={editPassword}
                          onChange={(e) => setEditPassword(e.target.value)}
                          required
                        />
                        <button
                          className="cipher-btn"
                          type="button"
                          onClick={() => void handleGenerateForEdit()}
                        >
                          {isGeneratingPassword ? "[...]" : "[生成]"}
                        </button>
                      </div>
                    </div>

                    <div className="form-field">
                      <span className="form-label">URL</span>
                      <input
                        className="form-input"
                        value={editUrl}
                        onChange={(e) => setEditUrl(e.target.value)}
                      />
                    </div>
                  </div>

                  <div className="form-field">
                    <span className="form-label">グループ</span>
                    <input
                      className="form-input"
                      value={editGroupInput}
                      onChange={(e) => setEditGroupInput(e.target.value)}
                      placeholder="仕事_"
                    />
                  </div>

                  <div className="form-field">
                    <span className="form-label">タグ</span>
                    <input
                      className="form-input"
                      value={editTagInput}
                      onChange={(e) => setEditTagInput(e.target.value)}
                      placeholder="仕事, 金融, メール_"
                    />
                  </div>

                  <div className="form-field">
                    <span className="form-label">メモ</span>
                    <textarea
                      className="form-textarea"
                      value={editNotes}
                      onChange={(e) => setEditNotes(e.target.value)}
                      rows={5}
                    />
                  </div>

                  <div className="action-row">
                    <button
                      className="cipher-btn cipher-btn--primary"
                      type="submit"
                      disabled={isUpdating}
                    >
                      {isUpdating ? "[ 保存中... ]" : "[ 変更を保存 ]"}
                    </button>
                    <button
                      className="cipher-btn cipher-btn--danger"
                      type="button"
                      disabled={isDeleting}
                      onClick={() => void handleDeleteEntry()}
                    >
                      {isDeleting ? "[ 削除中... ]" : "[ 削除 ]"}
                    </button>
                  </div>
                </form>
              </>
            ) : null}
          </div>
        </section>
      </div>
    </div>
  );
}
