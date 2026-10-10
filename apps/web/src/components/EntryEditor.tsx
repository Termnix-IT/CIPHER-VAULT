import { useEffect, useId, useRef, useState } from "react";
import type { FormEvent } from "react";
import type { PasswordEntry, PasswordEntryUpsertPayload } from "@password-manager/shared/types";

type Draft = { serviceName: string; loginId: string; password: string; url: string; group: string; tags: string; notes: string };
type EntryEditorProps = {
  entry: PasswordEntry | null;
  busy: boolean;
  isSaving: boolean;
  isGenerating: boolean;
  onDirtyChange: (dirty: boolean) => void;
  onGenerate: () => Promise<string>;
  onCopy: (text: string, label: string) => Promise<void>;
  onSave: (payload: PasswordEntryUpsertPayload) => Promise<void>;
  onDelete: () => Promise<void>;
  onCancel: () => void;
};

export function EntryEditor({ entry, busy, isSaving, isGenerating, onDirtyChange, onGenerate, onCopy, onSave, onDelete, onCancel }: EntryEditorProps) {
  const [initial, setInitial] = useState<Draft>(() => ({ serviceName: entry?.serviceName ?? "", loginId: entry?.loginId ?? "",
    password: entry?.password ?? "", url: entry?.url ?? "", group: entry?.group ?? "", tags: entry?.tags.join(", ") ?? "", notes: entry?.notes ?? "" }));
  const [draft, setDraft] = useState(initial);
  const [extraOpen, setExtraOpen] = useState(false);
  const [saved, setSaved] = useState(false);
  const [localError, setLocalError] = useState("");
  const [passwordVisibility, setPasswordVisibility] = useState<"hidden" | "armed" | "visible">("hidden");
  const alive = useRef(true);
  const extraRef = useRef<HTMLDivElement>(null);
  const panelId = useId();
  const toggleId = useId();
  const passwordId = useId();
  const passwordHintId = useId();
  const notesId = useId();
  const dirty = (Object.keys(initial) as (keyof Draft)[]).some((key) => draft[key] !== initial[key]);
  const extraCount = [draft.group, draft.tags, draft.notes].filter((value) => value.trim()).length;

  useEffect(() => {
    const next = { serviceName: entry?.serviceName ?? "", loginId: entry?.loginId ?? "", password: entry?.password ?? "",
      url: entry?.url ?? "", group: entry?.group ?? "", tags: entry?.tags.join(", ") ?? "", notes: entry?.notes ?? "" };
    setInitial(next); setDraft(next); setPasswordVisibility("hidden");
  }, [entry]);
  useEffect(() => { onDirtyChange(dirty); }, [dirty, onDirtyChange]);
  useEffect(() => { alive.current = true; return () => { alive.current = false; onDirtyChange(false); }; }, [onDirtyChange]);
  useEffect(() => { extraRef.current?.toggleAttribute("inert", !extraOpen); }, [extraOpen]);
  useEffect(() => { if (!saved) return; const timer = window.setTimeout(() => setSaved(false), 1600); return () => window.clearTimeout(timer); }, [saved]);
  useEffect(() => { if (busy || isGenerating) setPasswordVisibility("hidden"); }, [busy, isGenerating]);
  useEffect(() => {
    if (passwordVisibility !== "armed") return;
    const timer = window.setTimeout(() => setPasswordVisibility("hidden"), 3000);
    return () => window.clearTimeout(timer);
  }, [passwordVisibility]);

  function change(key: keyof Draft, value: string) {
    setDraft((current) => ({ ...current, [key]: value })); setSaved(false);
  }
  async function generate() {
    setPasswordVisibility("hidden");
    try { const value = await onGenerate(); if (alive.current) change("password", value); }
    catch { /* The app displays the operation error. */ }
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (busy || isGenerating) return;
    setPasswordVisibility("hidden");
    setSaved(false);
    setLocalError("");
    try {
      await onSave({ ...draft, tags: draft.tags.split(",").map((tag) => tag.trim()).filter(Boolean), group: draft.group.trim() || undefined });
      if (alive.current) setSaved(true);
    } catch (cause) {
      if (alive.current) {
        setLocalError(cause instanceof Error ? cause.message : "保存できませんでした");
        if (cause instanceof Error && /メモ|グループ|タグ|notes|group|tags/i.test(cause.message)) setExtraOpen(true);
      }
    }
  }
  function field(key: keyof Draft, label: string, required = false) {
    return <label className="form-field"><span className="form-label">{label}</span>
      <input className="form-input" value={draft[key]} required={required} disabled={busy}
        autoComplete="off" onChange={(event) => change(key, event.target.value)} />
    </label>;
  }
  return <form className={`entry-editor ${saved ? "entry-editor--saved" : ""}`} onSubmit={submit}>
    <div className="editor-scroll">
      {entry && <>
        <div className="entry-summary">
          {([{ label: "ログインID", value: entry.loginId, password: false }, { label: "パスワード", value: entry.password, password: true },
            { label: "URL", value: entry.url, password: false }]).map((item) => <div className="summary-field" key={item.label}>
            <span className="summary-label">{item.label}</span>
            <div className="summary-value-row"><span className={`summary-value ${item.password ? "summary-value--password" : ""}`}>
              {item.password ? "•".repeat(Math.min(item.value.length, 16)) : item.value || "未登録"}
            </span><button className="copy-btn" type="button" disabled={!item.value || busy} aria-label={`${item.label}をコピー`} title={`${item.label}をコピー`}
              onClick={() => { void onCopy(item.value, item.label).catch(() => {}); }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true"><rect x="8" y="8" width="12" height="12" rx="1" /><path d="M16 8V4H4v12h4" /></svg>
            </button></div>
          </div>)}
        </div>
        <p className="entry-metadata">作成 {new Date(entry.createdAt).toLocaleDateString("ja-JP")}<span>更新 {new Date(entry.updatedAt).toLocaleDateString("ja-JP")}</span></p>
      </>}
      <div className="editor-primary">
        <p className="form-section-title">{entry ? "編集" : "ログイン情報"}</p>
        <div className="inspector-form-grid">
          {field("serviceName", "サービス", true)}
          {field("loginId", "ログインID", true)}
          <div className="form-field"><label className="form-label" htmlFor={passwordId}>パスワード</label><div className="form-inline">
            <div className="password-input-wrap" onKeyDown={(event) => {
              if (event.key === "Escape" && passwordVisibility !== "hidden") {
                event.stopPropagation(); setPasswordVisibility("hidden");
              }
            }}>
              <input id={passwordId} className="form-input" type={passwordVisibility === "visible" ? "text" : "password"}
                autoComplete="new-password" required disabled={busy || isGenerating}
                value={draft.password} onChange={(event) => change("password", event.target.value)} />
              <button className="password-visibility-btn" type="button" disabled={busy || isGenerating}
                aria-label={passwordVisibility === "visible" ? "パスワードを隠す" : "パスワードを表示（2回クリック）"}
                aria-pressed={passwordVisibility === "visible"} aria-describedby={passwordHintId}
                title={passwordVisibility === "visible" ? "クリックで隠す" : "2回クリックで表示"}
                onKeyDown={(event) => {
                  // Holding a key must never count as the two deliberate activations needed to reveal.
                  if (event.repeat && (event.key === "Enter" || event.key === " ")) event.preventDefault();
                }}
                onBlur={() => setPasswordVisibility((current) => current === "armed" ? "hidden" : current)}
                onClick={() => setPasswordVisibility((current) => current === "hidden" ? "armed" : current === "armed" ? "visible" : "hidden")}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
                  <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z" /><circle cx="12" cy="12" r="3" />
                  {passwordVisibility === "visible" && <path d="m3 3 18 18" />}
                </svg>
              </button>
              <span id={passwordHintId} className="password-visibility-hint" role="status">{passwordVisibility === "armed" ? "もう一度クリックで表示" : ""}</span>
            </div>
            <button className="cipher-btn" type="button" disabled={busy || isGenerating} onClick={() => void generate()}>{isGenerating ? "生成中…" : "生成"}</button>
          </div></div>
          {field("url", "URL")}
        </div>
      </div>
      <div className={`editor-extra ${extraOpen ? "editor-extra--open" : ""}`}>
        <button className="editor-extra-toggle" type="button" id={toggleId} aria-expanded={extraOpen} aria-controls={panelId} onClick={() => setExtraOpen(!extraOpen)}>
          <span className="editor-extra-chevron" aria-hidden="true">›</span><span>追加情報</span>
          <span className="editor-extra-status">{extraCount ? `入力あり · ${extraCount}項目` : "未入力"}</span>
        </button>
        <div className="editor-extra-panel" ref={extraRef} id={panelId} role="region" aria-labelledby={toggleId} aria-hidden={!extraOpen}>
          <div className="editor-extra-clip"><div className="editor-extra-fields">
            {field("group", "グループ")}{field("tags", "タグ（カンマ区切り）")}
            <div className="form-field editor-notes"><label className="form-label" htmlFor={notesId}>メモ</label>
              <textarea id={notesId} className="form-textarea" rows={2} disabled={busy} value={draft.notes} onChange={(event) => change("notes", event.target.value)} />
            </div>
          </div></div>
        </div>
      </div>
      {localError && <p className="status-msg status-msg--error" role="alert">{localError}</p>}
    </div>
    <div className="editor-actions">
      <span className="editor-save-status" role="status">{isSaving ? "保存中…" : saved ? "保存しました" : dirty ? "未保存の変更あり" : ""}</span>
      <div className="action-row">
        <button className="cipher-btn cipher-btn--primary" type="submit" disabled={busy || isGenerating}>{isSaving ? "保存中…" : entry ? "変更を保存" : "保存"}</button>
        {entry ? <button className="cipher-btn cipher-btn--danger" type="button" disabled={busy || isGenerating} onClick={() => { void onDelete().catch(() => {}); }}>削除</button> :
          <button className="cipher-btn" type="button" disabled={busy || isGenerating} onClick={onCancel}>キャンセル</button>}
      </div>
    </div>
  </form>;
}
