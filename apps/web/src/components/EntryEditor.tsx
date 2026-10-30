import { useEffect, useId, useRef, useState } from "react";
import type { FormEvent } from "react";
import type { VaultEntry, VaultEntryType, VaultEntryUpsertPayload, VaultMaintenanceState } from "@password-manager/shared/types";

type Draft = {
  type: VaultEntryType; serviceName: string; loginId: string; password: string; url: string; group: string; tags: string; notes: string;
  apiKey: string; keyId: string; expiresOn: string; cardNumber: string; cardholder: string; expiryMonth: string; securityCode: string;
};
type SecretField = "password" | "apiKey" | "cardNumber" | "securityCode";
type Visibility = "hidden" | "armed" | "visible";
type EntryEditorProps = {
  entry: VaultEntry | null;
  vaultFormat: VaultMaintenanceState["format"];
  onOpenMaintenance: () => void;
  isEditing: boolean;
  busy: boolean;
  isSaving: boolean;
  isGenerating: boolean;
  onDirtyChange: (dirty: boolean) => void;
  onGenerate: () => Promise<string>;
  onCopy: (text: string, label: string) => Promise<void>;
  onSave: (payload: VaultEntryUpsertPayload) => Promise<void>;
  onCancel: () => void;
};

export function entryTypeLabel(type?: VaultEntryType) {
  return type === "apiKey" ? "APIキー" : type === "creditCard" ? "クレジットカード" : "ログイン";
}
function hiddenSecrets(): Record<SecretField, Visibility> {
  return { password: "hidden", apiKey: "hidden", cardNumber: "hidden", securityCode: "hidden" };
}
function toDraft(entry: VaultEntry | null, type: VaultEntryType = "login"): Draft {
  return { type: entry?.type ?? type, serviceName: entry?.serviceName ?? "", loginId: entry?.loginId ?? "", password: entry?.password ?? "",
    url: entry?.url ?? "", group: entry?.group ?? "", tags: entry?.tags.join(", ") ?? "", notes: entry?.notes ?? "",
    apiKey: entry?.type === "apiKey" ? entry.apiKey.key : "", keyId: entry?.type === "apiKey" ? entry.apiKey.keyId : "",
    expiresOn: entry?.type === "apiKey" ? entry.apiKey.expiresOn ?? "" : "",
    cardNumber: entry?.type === "creditCard" ? entry.card.number : "", cardholder: entry?.type === "creditCard" ? entry.card.cardholder : "",
    expiryMonth: entry?.type === "creditCard" ? entry.card.expiryMonth ?? "" : "", securityCode: entry?.type === "creditCard" ? entry.card.securityCode : "" };
}

export function EntryEditor({ entry, vaultFormat, onOpenMaintenance, isEditing, busy, isSaving, isGenerating, onDirtyChange, onGenerate, onCopy, onSave, onCancel }: EntryEditorProps) {
  const [initial, setInitial] = useState(() => toDraft(entry));
  const [draft, setDraft] = useState(initial);
  const [saved, setSaved] = useState(false);
  const [copiedLabel, setCopiedLabel] = useState<string | null>(null);
  const copyRequest = useRef(0), draftEpoch = useRef(0);
  const [visibility, setVisibility] = useState(hiddenSecrets);
  const alive = useRef(true);
  const fieldId = useId();
  const editing = isEditing || !entry;
  const migrationRequired = draft.type !== "login" && vaultFormat !== "v2";
  const dirty = editing && (Object.keys(initial) as (keyof Draft)[]).some((key) => draft[key] !== initial[key]);

  useEffect(() => {
    const next = toDraft(entry);
    setInitial(next); setDraft(next); setVisibility(hiddenSecrets());
    setCopiedLabel(null); copyRequest.current++; draftEpoch.current++;
    if (editing) setSaved(false);
  }, [entry, editing]);
  useEffect(() => { onDirtyChange(dirty); }, [dirty, onDirtyChange]);
  useEffect(() => { alive.current = true; return () => { alive.current = false; draftEpoch.current++; copyRequest.current++; onDirtyChange(false); }; }, [onDirtyChange]);
  useEffect(() => { if (!saved) return; const timer = window.setTimeout(() => setSaved(false), 1600); return () => window.clearTimeout(timer); }, [saved]);
  useEffect(() => {
    if (!copiedLabel) return;
    const timer = window.setTimeout(() => setCopiedLabel(null), 1600);
    return () => window.clearTimeout(timer);
  }, [copiedLabel]);
  useEffect(() => { if (busy || isGenerating) setVisibility(hiddenSecrets()); }, [busy, isGenerating]);
  const armedField = (Object.keys(visibility) as SecretField[]).find((key) => visibility[key] === "armed");
  useEffect(() => {
    if (!armedField) return;
    const timer = window.setTimeout(() => setVisibility((current) => ({ ...current, [armedField]: current[armedField] === "armed" ? "hidden" : current[armedField] })), 3000);
    return () => window.clearTimeout(timer);
  }, [armedField]);

  function change(key: Exclude<keyof Draft, "type">, value: string) {
    draftEpoch.current++; copyRequest.current++;
    setDraft((current) => ({ ...current, [key]: value })); setVisibility(hiddenSecrets()); setCopiedLabel(null); setSaved(false);
  }
  function changeType(type: VaultEntryType) {
    if (entry || busy || isGenerating || type === draft.type) return;
    const hasSpecificValues = [draft.loginId, draft.password, draft.apiKey, draft.keyId, draft.expiresOn, draft.cardNumber, draft.cardholder, draft.expiryMonth, draft.securityCode].some(Boolean);
    if (hasSpecificValues && !window.confirm("種類を変更すると、種類固有の入力内容を破棄します。名前・URL・グループ・タグ・メモは保持します。変更しますか？")) return;
    draftEpoch.current++; copyRequest.current++;
    setDraft((current) => ({ ...toDraft(null, type), serviceName: current.serviceName, url: current.url, group: current.group, tags: current.tags, notes: current.notes }));
    setVisibility(hiddenSecrets()); setCopiedLabel(null); setSaved(false);
  }
  async function generate() {
    const epoch = draftEpoch.current;
    setVisibility(hiddenSecrets());
    try { const value = await onGenerate(); if (alive.current && epoch === draftEpoch.current) change("password", value); }
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
    event.preventDefault(); if (!editing || busy || isGenerating || migrationRequired) return;
    setVisibility(hiddenSecrets()); setSaved(false);
    const common = { serviceName: draft.serviceName, url: draft.url, notes: draft.notes,
      tags: draft.tags.split(",").map((tag) => tag.trim()).filter(Boolean), group: draft.group.trim() || undefined };
    const payload: VaultEntryUpsertPayload = draft.type === "apiKey"
      ? { ...common, type: "apiKey", apiKey: { key: draft.apiKey, keyId: draft.keyId, expiresOn: draft.expiresOn || undefined } }
      : draft.type === "creditCard"
        ? { ...common, type: "creditCard", card: { number: draft.cardNumber, cardholder: draft.cardholder, expiryMonth: draft.expiryMonth || undefined, securityCode: draft.securityCode } }
        : { ...common, loginId: draft.loginId, password: draft.password };
    try {
      await onSave(payload);
      if (alive.current) setSaved(true);
    } catch { /* Keep the draft open; the app displays the save error. */ }
  }
  function field(key: Exclude<keyof Draft, "type">, label: string, required = false, inputType = "text") {
    return <label className={`editor-field ${["serviceName", "cardholder", "url"].includes(key) ? "editor-field--wide" : ""}`}><span className="form-label">{label}</span>
      <input className="form-input" type={inputType} value={draft[key]} required={required} disabled={busy || isGenerating}
        placeholder={inputType === "month" ? "YYYY-MM" : inputType === "date" ? "YYYY-MM-DD" : undefined}
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
  function secretToggle(key: SecretField, label: string) {
    const state = visibility[key];
    const hintId = `${fieldId}-${key}-hint`;
    return <>
      <button className="password-visibility-btn" type="button" disabled={busy || isGenerating}
        aria-label={state === "visible" ? `${label}を隠す` : `${label}を表示（2回クリック）`}
        aria-pressed={state === "visible"} aria-describedby={hintId}
        title={state === "visible" ? "クリックで隠す" : "2回クリックで表示"}
        onKeyDown={(event) => {
          // Holding a key must never count as the two deliberate activations needed to reveal.
          if (event.repeat && (event.key === "Enter" || event.key === " ")) event.preventDefault();
        }}
        onBlur={() => setVisibility((current) => ({ ...current, [key]: current[key] === "armed" ? "hidden" : current[key] }))}
        onClick={() => setVisibility((current) => {
          const next = { ...current };
          for (const field of Object.keys(next) as SecretField[]) if (next[field] === "armed") next[field] = "hidden";
          next[key] = current[key] === "hidden" ? "armed" : current[key] === "armed" ? "visible" : "hidden";
          return next;
        })}>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
          <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z" /><circle cx="12" cy="12" r="3" />
          {state === "visible" && <path d="m3 3 18 18" />}
        </svg>
      </button>
      <span id={hintId} className="password-visibility-hint" role="status">{state === "armed" ? "もう一度クリックで表示" : ""}</span>
    </>;
  }
  function secretInput(key: SecretField, label: string, required = false, optional = false) {
    const id = `${fieldId}-${key}`;
    return <div className={`editor-field ${key === "apiKey" || key === "cardNumber" ? "editor-field--wide" : ""}`}><label className="form-label" htmlFor={id}>{label}{optional ? "（任意）" : ""}</label><div className="form-inline">
      <div className="password-input-wrap">
        <input id={id} className="form-input" type={visibility[key] === "visible" ? "text" : "password"}
          autoComplete="new-password" spellCheck={false} required={required} disabled={busy || isGenerating}
          value={draft[key]} onChange={(event) => change(key, event.target.value)} />
        {secretToggle(key, label)}
      </div>
      {key === "password" ? <button className="cipher-btn" type="button" disabled={busy || isGenerating} onClick={() => void generate()}>{isGenerating ? "生成中…" : "生成"}</button>
        : copyButton(draft[key], label)}
    </div></div>;
  }
  function viewField(label: string, value: string, copyable = false) {
    return <div className="entry-view-field"><dt>{label}</dt><dd>{value || "—"}</dd>{copyable && copyButton(value, label)}</div>;
  }
  function secretView(key: SecretField, label: string, value: string, masked = "••••••••••••") {
    return <div className="entry-view-field"><dt>{label}</dt><dd className="entry-password-value">
      <span className={visibility[key] === "visible" ? "" : "summary-value--password"}>{value ? visibility[key] === "visible" ? value : masked : "—"}</span>
      {value && secretToggle(key, label)}
    </dd>{copyButton(value, label)}</div>;
  }

  return <form className={`entry-editor entry-editor--${draft.type} ${editing ? "entry-editor--editing" : ""}`} onSubmit={submit}
    onKeyDown={(event) => {
      if (event.key === "Escape" && Object.values(visibility).some((value) => value !== "hidden")) {
        event.stopPropagation(); setVisibility(hiddenSecrets());
      }
    }}>
    <div className="editor-scroll">
      {editing && !entry && <label className="editor-type-picker"><span className="form-label">種類</span>
        <select className="form-input" aria-label="保存する種類" value={draft.type} disabled={busy || isGenerating} onChange={(event) => changeType(event.target.value as VaultEntryType)}>
          <option value="login">ログイン</option><option value="apiKey">APIキー</option><option value="creditCard">クレジットカード</option>
        </select>
      </label>}
      {editing && migrationRequired ? <div className="entry-migration-notice" role="status">
        <h2>新しい保管庫形式への移行が必要です</h2>
        <p>APIキーとクレジットカードは、項目全体を暗号化する新しい形式の保管庫で保存できます。「保管庫の管理」から移行してください。</p>
        <button className="cipher-btn cipher-btn--primary" type="button" disabled={busy} onClick={onOpenMaintenance}>保管庫の管理を開く</button>
      </div> : editing ? <div className="editor-fields">
        {field("serviceName", draft.type === "login" ? "サービス" : "名前", true)}
        {draft.type === "login" ? <>
          {field("loginId", "ログインID", true)}
          {secretInput("password", "パスワード", true)}
          {field("url", "URL")}
        </> : draft.type === "apiKey" ? <>
          {secretInput("apiKey", "キー／トークン", true)}
          {field("keyId", "キーID（任意）")}
          {field("expiresOn", "有効期限（任意）", false, "date")}
          {field("url", "接続先URL（任意）")}
        </> : <>
          {secretInput("cardNumber", "カード番号", true)}
          {field("cardholder", "名義（任意）")}
          {field("expiryMonth", "有効期限（任意）", false, "month")}
          {secretInput("securityCode", "セキュリティコード", false, true)}
          {field("url", "URL（任意）")}
        </>}
        {field("group", "グループ")}
        {field("tags", "タグ")}
        <div className="editor-field editor-notes"><label className="form-label" htmlFor={`${fieldId}-notes`}>メモ</label>
          <textarea id={`${fieldId}-notes`} className="form-textarea" rows={3} disabled={busy} value={draft.notes} onChange={(event) => change("notes", event.target.value)} />
        </div>
      </div> : entry && <dl className="entry-view-fields">
        {entry.type === "apiKey" ? <>
          {secretView("apiKey", "キー／トークン", entry.apiKey.key)}
          {viewField("キーID", entry.apiKey.keyId, true)}
          {viewField("有効期限", entry.apiKey.expiresOn ?? "")}
          {viewField("接続先URL", entry.url, true)}
        </> : entry.type === "creditCard" ? <>
          {secretView("cardNumber", "カード番号", entry.card.number, `•••• •••• •••• ${entry.card.number.replace(/\D/g, "").slice(-4)}`)}
          {viewField("名義", entry.card.cardholder)}
          {viewField("有効期限", entry.card.expiryMonth ?? "")}
          {secretView("securityCode", "セキュリティコード", entry.card.securityCode)}
          {entry.url && viewField("URL", entry.url, true)}
        </> : <>
          {viewField("ログインID", entry.loginId, true)}
          {secretView("password", "パスワード", entry.password)}
          {viewField("URL", entry.url, true)}
        </>}
        {entry.group && viewField("グループ", entry.group)}
        {entry.tags.length > 0 && <div className="entry-view-field"><dt>タグ</dt><dd className="entry-view-tags">{entry.tags.map((tag, index) => <span key={`${tag}-${index}`} className="tag-chip">{tag}</span>)}</dd></div>}
        {entry.notes && <div className="entry-view-field entry-view-notes"><dt>メモ</dt><dd>{entry.notes}</dd></div>}
      </dl>}
    </div>
    <div className="editor-actions">
      {editing ? <>
        <span className="editor-save-status" role="status">{isSaving ? "保存中…" : dirty ? "未保存" : ""}</span>
        <button className="cipher-btn" type="button" disabled={busy || isGenerating} onClick={onCancel}>キャンセル</button>
        <button className="cipher-btn cipher-btn--primary editor-save-btn" type="submit" disabled={busy || isGenerating || migrationRequired}>{isSaving ? "保存中…" : "保存する"}</button>
      </> : <>
        <span className="entry-metadata">{entry && `更新 ${new Date(entry.updatedAt).toLocaleDateString("ja-JP")}`}</span>
        <span className="editor-save-status" role="status">{saved ? "保存しました" : ""}</span>
      </>}
    </div>
  </form>;
}
