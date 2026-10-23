import { useEffect, useId, useRef, useState } from "react";
import type { FormEvent } from "react";
import type { PasswordEntry, PasswordEntryUpsertPayload } from "@password-manager/shared/types";

type Draft = { serviceName: string; loginId: string; password: string; url: string; group: string; tags: string; notes: string };
type EntryEditorProps = {
  entry: PasswordEntry | null;
  isEditing: boolean;
  busy: boolean;
  isSaving: boolean;
  isGenerating: boolean;
  onDirtyChange: (dirty: boolean) => void;
  onGenerate: () => Promise<string>;
  onCopy: (text: string, label: string) => Promise<void>;
  onSave: (payload: PasswordEntryUpsertPayload) => Promise<void>;
  onCancel: () => void;
};

function toDraft(entry: PasswordEntry | null): Draft {
  return { serviceName: entry?.serviceName ?? "", loginId: entry?.loginId ?? "", password: entry?.password ?? "",
    url: entry?.url ?? "", group: entry?.group ?? "", tags: entry?.tags.join(", ") ?? "", notes: entry?.notes ?? "" };
}

export function EntryEditor({ entry, isEditing, busy, isSaving, isGenerating, onDirtyChange, onGenerate, onCopy, onSave, onCancel }: EntryEditorProps) {
  const [initial, setInitial] = useState(() => toDraft(entry));
  const [draft, setDraft] = useState(initial);
  const [saved, setSaved] = useState(false);
  const [copiedLabel, setCopiedLabel] = useState<string | null>(null);
  const copyRequest = useRef(0);
  const [passwordVisibility, setPasswordVisibility] = useState<"hidden" | "armed" | "visible">("hidden");
  const alive = useRef(true);
  const passwordId = useId();
  const passwordHintId = useId();
  const notesId = useId();
  const editing = isEditing || !entry;
  const dirty = editing && (Object.keys(initial) as (keyof Draft)[]).some((key) => draft[key] !== initial[key]);

  useEffect(() => {
    const next = toDraft(entry);
    setInitial(next); setDraft(next); setPasswordVisibility("hidden");
    setCopiedLabel(null); copyRequest.current++;
    if (editing) setSaved(false);
  }, [entry, editing]);
  useEffect(() => { onDirtyChange(dirty); }, [dirty, onDirtyChange]);
  useEffect(() => { alive.current = true; return () => { alive.current = false; onDirtyChange(false); }; }, [onDirtyChange]);
  useEffect(() => { if (!saved) return; const timer = window.setTimeout(() => setSaved(false), 1600); return () => window.clearTimeout(timer); }, [saved]);
  useEffect(() => {
    if (!copiedLabel) return;
    const timer = window.setTimeout(() => setCopiedLabel(null), 1600);
    return () => window.clearTimeout(timer);
  }, [copiedLabel]);
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
  async function copy(value: string, label: string) {
    const request = ++copyRequest.current;
    setCopiedLabel(null);
    try {
      await onCopy(value, label);
      if (alive.current && request === copyRequest.current) setCopiedLabel(label);
    } catch { /* The app displays the operation error; do not show success feedback. */ }
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!editing || busy || isGenerating) return;
    setPasswordVisibility("hidden"); setSaved(false);
    try {
      await onSave({ ...draft, tags: draft.tags.split(",").map((tag) => tag.trim()).filter(Boolean), group: draft.group.trim() || undefined });
      if (alive.current) setSaved(true);
    } catch { /* Keep the draft open; the app displays the save error. */ }
  }
  function field(key: keyof Draft, label: string, required = false) {
    return <label className="editor-field"><span className="form-label">{label}</span>
      <input className="form-input" value={draft[key]} required={required} disabled={busy}
        autoFocus={key === "serviceName"} autoComplete="off" onChange={(event) => change(key, event.target.value)} />
    </label>;
  }
  function copyButton(value: string, label: string) {
    return <button className={`copy-btn ${copiedLabel === label ? "copy-btn--copied" : ""}`} type="button" disabled={!value || busy}
      aria-label={`${label}をコピー`} title={copiedLabel === label ? "コピーしました" : `${label}をコピー`}
      onClick={() => { void copy(value, label); }}>
      <svg key={copiedLabel === label ? "copied" : "copy"} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
        {copiedLabel === label ? <path d="m5 12 4 4L19 6" /> : <><rect x="8" y="8" width="12" height="12" rx="1" /><path d="M16 8V4H4v12h4" /></>}
      </svg>
    </button>;
  }
  const passwordToggle = <>
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
  </>;

  return <form className={`entry-editor ${editing ? "entry-editor--editing" : ""}`} onSubmit={submit}
    onKeyDown={(event) => {
      if (event.key === "Escape" && passwordVisibility !== "hidden") {
        event.stopPropagation(); setPasswordVisibility("hidden");
      }
    }}>
    <div className="editor-scroll">
      {editing ? <div className="editor-fields">
        {field("serviceName", "サービス", true)}
        {field("loginId", "ログインID", true)}
        <div className="editor-field"><label className="form-label" htmlFor={passwordId}>パスワード</label><div className="form-inline">
          <div className="password-input-wrap">
            <input id={passwordId} className="form-input" type={passwordVisibility === "visible" ? "text" : "password"}
              autoComplete="new-password" required disabled={busy || isGenerating}
              value={draft.password} onChange={(event) => change("password", event.target.value)} />
            {passwordToggle}
          </div>
          <button className="cipher-btn" type="button" disabled={busy || isGenerating} onClick={() => void generate()}>{isGenerating ? "生成中…" : "生成"}</button>
        </div></div>
        {field("url", "URL")}
        {field("group", "グループ")}
        {field("tags", "タグ")}
        <div className="editor-field editor-notes"><label className="form-label" htmlFor={notesId}>メモ</label>
          <textarea id={notesId} className="form-textarea" rows={3} disabled={busy} value={draft.notes} onChange={(event) => change("notes", event.target.value)} />
        </div>
      </div> : entry && <dl className="entry-view-fields">
        <div className="entry-view-field"><dt>ログインID</dt><dd>{entry.loginId}</dd>{copyButton(entry.loginId, "ログインID")}</div>
        <div className="entry-view-field"><dt>パスワード</dt><dd className="entry-password-value">
          <span className={passwordVisibility === "visible" ? "" : "summary-value--password"}>{passwordVisibility === "visible" ? entry.password : "••••••••••••"}</span>
          {passwordToggle}
        </dd>{copyButton(entry.password, "パスワード")}</div>
        <div className="entry-view-field"><dt>URL</dt><dd>{entry.url || "—"}</dd>{copyButton(entry.url, "URL")}</div>
        {entry.group && <div className="entry-view-field"><dt>グループ</dt><dd>{entry.group}</dd></div>}
        {entry.tags.length > 0 && <div className="entry-view-field"><dt>タグ</dt><dd className="entry-view-tags">{entry.tags.map((tag, index) => <span key={`${tag}-${index}`} className="tag-chip">{tag}</span>)}</dd></div>}
        {entry.notes && <div className="entry-view-field entry-view-notes"><dt>メモ</dt><dd>{entry.notes}</dd></div>}
      </dl>}
    </div>
    <div className="editor-actions">
      {editing ? <>
        <span className="editor-save-status" role="status">{isSaving ? "保存中…" : dirty ? "未保存" : ""}</span>
        <button className="cipher-btn" type="button" disabled={busy || isGenerating} onClick={onCancel}>キャンセル</button>
        <button className="cipher-btn cipher-btn--primary editor-save-btn" type="submit" disabled={busy || isGenerating}>{isSaving ? "保存中…" : "保存する"}</button>
      </> : <>
        <span className="entry-metadata">{entry && `更新 ${new Date(entry.updatedAt).toLocaleDateString("ja-JP")}`}</span>
        <span className="editor-save-status" role="status">{saved ? "保存しました" : ""}</span>
      </>}
    </div>
  </form>;
}
