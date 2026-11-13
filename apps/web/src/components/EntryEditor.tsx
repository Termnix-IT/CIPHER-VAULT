import { Fragment, useEffect, useId, useRef, useState } from "react";
import type { FormEvent } from "react";
import type { FinancialExtraSecret, VaultEntry, VaultEntryType, VaultEntryUpsertPayload, VaultMaintenanceState } from "@password-manager/shared/types";
import { CheckIcon, CloseIcon, CopyIcon, EyeIcon, GripIcon } from "./Icons";

type Draft = {
  type: VaultEntryType; serviceName: string; loginId: string; password: string; url: string; group: string; tags: string; notes: string;
  apiKey: string; keyId: string; expiresOn: string; cardNumber: string; cardholder: string; expiryMonth: string; securityCode: string;
  tradingPassword: string; extraSecrets: FinancialExtraSecret[];
};
type DraftText = Exclude<keyof Draft, "type" | "extraSecrets">;
type DraftSecret = "password" | "apiKey" | "cardNumber" | "securityCode" | "tradingPassword";
type SecretField = DraftSecret | `extra-${number}`;
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
  onDelete?: () => void;
  onCancel: () => void;
};

const TYPES: { type: VaultEntryType; label: string }[] = [{ type: "login", label: "ログイン" }, { type: "apiKey", label: "APIキー" }, { type: "creditCard", label: "カード" }, { type: "financial", label: "銀行/証券" }];
const MAX_EXTRA_SECRETS = 8;

export function entryTypeLabel(type?: VaultEntryType) {
  return type === "apiKey" ? "APIキー" : type === "creditCard" ? "クレジットカード" : type === "financial" ? "銀行/証券" : "ログイン";
}
function hiddenSecrets(): Record<SecretField, Visibility> {
  return { password: "hidden", apiKey: "hidden", cardNumber: "hidden", securityCode: "hidden", tradingPassword: "hidden" };
}
function toDraft(entry: VaultEntry | null, type: VaultEntryType = "login"): Draft {
  const financial = entry?.type === "financial" ? entry.financial : null;
  return { type: entry?.type ?? type, serviceName: entry?.serviceName ?? "", loginId: financial?.loginId ?? entry?.loginId ?? "", password: financial?.loginPassword ?? entry?.password ?? "",
    tradingPassword: financial?.tradingPassword ?? "", extraSecrets: financial?.extraSecrets ?? [],
    url: entry?.url ?? "", group: entry?.group ?? "", tags: entry?.tags.join(", ") ?? "", notes: entry?.notes ?? "",
    apiKey: entry?.type === "apiKey" ? entry.apiKey.key : "", keyId: entry?.type === "apiKey" ? entry.apiKey.keyId : "",
    expiresOn: entry?.type === "apiKey" ? entry.apiKey.expiresOn ?? "" : "",
    cardNumber: entry?.type === "creditCard" ? entry.card.number : "", cardholder: entry?.type === "creditCard" ? entry.card.cardholder : "",
    expiryMonth: entry?.type === "creditCard" ? entry.card.expiryMonth ?? "" : "", securityCode: entry?.type === "creditCard" ? entry.card.securityCode : "" };
}

export function EntryEditor({ entry, vaultFormat, onOpenMaintenance, isEditing, busy, isSaving, isGenerating, onDirtyChange, onGenerate, onCopy, onSave, onDelete, onCancel }: EntryEditorProps) {
  const [initial, setInitial] = useState(() => toDraft(entry));
  const [draft, setDraft] = useState(initial);
  const [copiedLabel, setCopiedLabel] = useState<string | null>(null);
  const [showExtras, setShowExtras] = useState(() => Boolean(entry && (entry.group || entry.tags.length || entry.notes)));
  const copyRequest = useRef(0), draftEpoch = useRef(0);
  const [visibility, setVisibility] = useState(hiddenSecrets);
  const alive = useRef(true);
  const fieldId = useId();
  const editing = isEditing || !entry;
  const migrationRequired = draft.type !== "login" && vaultFormat !== "v2";
  const dirty = editing && (Object.keys(initial) as (keyof Draft)[]).some((key) => key === "extraSecrets"
    ? JSON.stringify(draft.extraSecrets) !== JSON.stringify(initial.extraSecrets) : draft[key] !== initial[key]);

  useEffect(() => {
    const next = toDraft(entry);
    setInitial(next); setDraft(next); setVisibility(hiddenSecrets());
    setShowExtras(Boolean(next.group || next.tags || next.notes));
    setCopiedLabel(null); copyRequest.current++; draftEpoch.current++;
  }, [entry, editing]);
  useEffect(() => { onDirtyChange(dirty); }, [dirty, onDirtyChange]);
  useEffect(() => { alive.current = true; return () => { alive.current = false; draftEpoch.current++; copyRequest.current++; onDirtyChange(false); }; }, [onDirtyChange]);
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

  function change(key: DraftText, value: string) {
    draftEpoch.current++; copyRequest.current++;
    setDraft((current) => ({ ...current, [key]: value })); setVisibility(hiddenSecrets()); setCopiedLabel(null);
  }
  function changeExtraSecrets(update: (secrets: FinancialExtraSecret[]) => FinancialExtraSecret[]) {
    draftEpoch.current++; copyRequest.current++;
    setDraft((current) => ({ ...current, extraSecrets: update(current.extraSecrets) })); setVisibility(hiddenSecrets()); setCopiedLabel(null);
  }
  function changeExtraSecret(index: number, patch: Partial<FinancialExtraSecret>) {
    changeExtraSecrets((secrets) => secrets.map((secret, position) => position === index ? { ...secret, ...patch } : secret));
  }
  function changeType(type: VaultEntryType) {
    if (entry || busy || isGenerating || type === draft.type) return;
    const hasSpecificValues = draft.extraSecrets.length > 0 || [draft.loginId, draft.password, draft.tradingPassword, draft.apiKey, draft.keyId, draft.expiresOn, draft.cardNumber, draft.cardholder, draft.expiryMonth, draft.securityCode].some(Boolean);
    if (hasSpecificValues && !window.confirm("種類を変えると、入力中のIDやパスワードなどは消えます。名前・URL・グループ・タグ・メモは残ります。変えますか？")) return;
    draftEpoch.current++; copyRequest.current++;
    setDraft((current) => ({ ...toDraft(null, type), serviceName: current.serviceName, url: current.url, group: current.group, tags: current.tags, notes: current.notes }));
    setVisibility(hiddenSecrets()); setCopiedLabel(null);
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
    setVisibility(hiddenSecrets());
    const common = { serviceName: draft.serviceName, url: draft.url, notes: draft.notes,
      tags: draft.tags.split(",").map((tag) => tag.trim()).filter(Boolean), group: draft.group.trim() || undefined };
    const payload: VaultEntryUpsertPayload = draft.type === "apiKey"
      ? { ...common, type: "apiKey", apiKey: { key: draft.apiKey, keyId: draft.keyId, expiresOn: draft.expiresOn || undefined } }
      : draft.type === "creditCard"
        ? { ...common, type: "creditCard", card: { number: draft.cardNumber, cardholder: draft.cardholder, expiryMonth: draft.expiryMonth || undefined, securityCode: draft.securityCode } }
        : draft.type === "financial"
          ? { ...common, type: "financial", financial: { loginId: draft.loginId, loginPassword: draft.password, tradingPassword: draft.tradingPassword, extraSecrets: draft.extraSecrets } }
          : { ...common, loginId: draft.loginId, password: draft.password };
    try { await onSave(payload); }
    catch { /* Keep the draft open; the app displays the save error. */ }
  }
  function field(key: DraftText, label: string, required = false, inputType = "text", placeholder?: string) {
    return <label className="editor-field"><span className="form-label">{label}</span>
      <input className="form-input" type={inputType} value={draft[key]} required={required} disabled={busy || isGenerating}
        placeholder={placeholder ?? (inputType === "month" ? "YYYY-MM" : inputType === "date" ? "YYYY-MM-DD" : undefined)}
        autoFocus={key === "serviceName"} autoComplete="off" onChange={(event) => change(key, event.target.value)} />
      <span />
    </label>;
  }
  function copyButton(value: string, label: string) {
    const copied = copiedLabel === label;
    return <button className={`icon-btn copy-btn ${copied ? "copy-btn--copied" : ""}`} type="button" disabled={!value || busy}
      aria-label={`${label}をコピー`} title={copied ? "コピーしました" : `${label}をコピー`}
      onClick={() => { void copy(value, label); }}>
      {copied ? <CheckIcon /> : <CopyIcon />}
    </button>;
  }
  function secretToggle(key: SecretField, label: string) {
    const state = visibility[key] ?? "hidden"; // Extra secrets have no entry until first toggled.
    const hintId = `${fieldId}-${key}-hint`;
    return <span className="password-visibility-wrap">
      <button className="icon-btn password-visibility-btn" type="button" disabled={busy || isGenerating}
        aria-label={state === "visible" ? `${label}を隠す` : `${label}を表示（2回クリック）`}
        aria-pressed={state === "visible"} aria-describedby={hintId}
        title={state === "visible" ? "隠す" : "2回クリックで表示"}
        onKeyDown={(event) => {
          // Holding a key must never count as the two deliberate activations needed to reveal.
          if (event.repeat && (event.key === "Enter" || event.key === " ")) event.preventDefault();
        }}
        onBlur={() => setVisibility((current) => ({ ...current, [key]: current[key] === "armed" ? "hidden" : current[key] }))}
        onClick={() => setVisibility((current) => {
          const next = { ...current };
          for (const field of Object.keys(next) as SecretField[]) if (next[field] === "armed") next[field] = "hidden";
          next[key] = current[key] === "armed" ? "visible" : current[key] === "visible" ? "hidden" : "armed";
          return next;
        })}>
        <EyeIcon crossed={state === "visible"} />
      </button>
      <span id={hintId} className="password-visibility-hint" role="status">{state === "armed" ? "もう一度で表示" : ""}</span>
    </span>;
  }
  function extraSecretInput(secret: FinancialExtraSecret, index: number) {
    const key = `extra-${index}` as const;
    const label = secret.label.trim() || `追加の秘密${index + 1}`;
    return <div className="editor-field editor-extra-secret" key={index}>
      <input className="form-input" aria-label={`追加の秘密${index + 1}の名前`} placeholder="名前" required disabled={busy || isGenerating}
        autoComplete="off" value={secret.label} onChange={(event) => changeExtraSecret(index, { label: event.target.value })} />
      <div className="password-input-wrap">
        <input className="form-input" aria-label={`${label}の値`} type={visibility[key] === "visible" ? "text" : "password"}
          autoComplete="new-password" spellCheck={false} required disabled={busy || isGenerating}
          value={secret.value} onChange={(event) => changeExtraSecret(index, { value: event.target.value })} />
        {secretToggle(key, label)}
      </div>
      <span className="field-actions">
        <button className="icon-btn" type="button" aria-label={`${label}を削除`} title="削除" disabled={busy || isGenerating}
          onClick={() => changeExtraSecrets((secrets) => secrets.filter((_secret, position) => position !== index))}><CloseIcon /></button>
      </span>
    </div>;
  }
  function secretInput(key: DraftSecret, label: string, required = false) {
    const id = `${fieldId}-${key}`;
    return <div className="editor-field"><label className="form-label" htmlFor={id}>{label}</label>
      <div className="password-input-wrap">
        <input id={id} className="form-input" type={visibility[key] === "visible" ? "text" : "password"}
          autoComplete="new-password" spellCheck={false} required={required} disabled={busy || isGenerating}
          value={draft[key]} onChange={(event) => change(key, event.target.value)} />
        {secretToggle(key, label)}
      </div>
      <span className="field-actions">
        {key === "password" ? <button className="btn btn--small" type="button" disabled={busy || isGenerating} onClick={() => void generate()}>{isGenerating ? "生成中…" : "生成"}</button>
          : copyButton(draft[key], label)}
      </span>
    </div>;
  }
  /**
   * Drags the value into another app's field, such as a browser's sign-in form. Only the login ID
   * of a login offers this: a dragged value is handed to every window the pointer crosses and can
   * land in a search box or chat, so passwords and account numbers stay with the expiring copy.
   */
  function dragHandle(value: string, label: string) {
    return <span className="drag-handle" draggable={!busy} role="img" aria-label={`${label}をドラッグして入力欄へ`} data-tooltip={`ドラッグして入力欄へ（${label}）`}
      onDragStart={(event) => {
        event.dataTransfer.effectAllowed = "copy";
        event.dataTransfer.setData("text/plain", value);
        // The drag image names the field rather than showing the value.
        const image = document.createElement("span");
        image.className = "drag-image";
        image.textContent = label;
        document.body.append(image);
        event.dataTransfer.setDragImage(image, 12, 12);
        window.setTimeout(() => image.remove(), 0);
      }}><GripIcon /></span>;
  }
  function viewField(label: string, value: string, copyable = false, plain = false, draggable = false) {
    if (!value) return null;
    return <div className="entry-view-field"><dt>{label}</dt><dd className={plain ? "entry-view-plain" : undefined}>{value}</dd>
      <span className="field-actions">{copyable && copyButton(value, label)}{draggable && dragHandle(value, label)}</span></div>;
  }
  function secretView(key: SecretField, label: string, value: string, masked = "••••••••••••") {
    if (!value) return null;
    return <div className="entry-view-field"><dt>{label}</dt>
      <dd className="secret-value"><span className={visibility[key] === "visible" ? "" : "summary-value--password"}>{visibility[key] === "visible" ? value : masked}</span></dd>
      <span className="field-actions">{secretToggle(key, label)}{copyButton(value, label)}</span></div>;
  }

  return <form className={`entry-editor entry-editor--${draft.type} ${editing ? "entry-editor--editing" : ""}`} onSubmit={submit}
    onKeyDown={(event) => {
      if (event.key === "Escape" && Object.values(visibility).some((value) => value !== "hidden")) {
        event.stopPropagation(); setVisibility(hiddenSecrets());
      }
    }}>
    <div className="editor-scroll">
      {editing && !entry && <div className="type-tabs-row">
        <div className="segmented type-tabs" role="tablist" aria-label="保存する種類">
          {TYPES.map(({ type, label }) => <button key={type} type="button" role="tab" data-type={type} aria-selected={draft.type === type}
            disabled={busy || isGenerating} onClick={() => changeType(type)}>{label}</button>)}
        </div>
      </div>}
      {editing && migrationRequired ? <div className="entry-migration-notice" role="status">
        <h2>APIキー・カード・銀行/証券を保存するには、保管庫の更新が必要です</h2>
        <button className="btn btn--primary" type="button" disabled={busy} onClick={onOpenMaintenance}>保管庫を更新</button>
      </div> : editing ? <div className="editor-fields">
        {field("serviceName", draft.type === "login" ? "サービス" : "名前", true)}
        {draft.type === "login" ? <>
          {field("loginId", "ログインID", true)}
          {secretInput("password", "パスワード", true)}
          {field("url", "URL", false, "text", "https://")}
        </> : draft.type === "apiKey" ? <>
          {secretInput("apiKey", "キー", true)}
          {field("keyId", "キーID")}
          {field("expiresOn", "有効期限", false, "date")}
          {field("url", "URL", false, "text", "https://")}
        </> : draft.type === "financial" ? <>
          {field("loginId", "ログインID", true, "text", "契約者番号・口座番号など")}
          {secretInput("password", "ログインパスワード", true)}
          {secretInput("tradingPassword", "取引パスワード")}
          {draft.extraSecrets.map(extraSecretInput)}
          {draft.extraSecrets.length < MAX_EXTRA_SECRETS && <div className="editor-more">
            <button className="text-btn" type="button" disabled={busy || isGenerating}
              onClick={() => changeExtraSecrets((secrets) => [...secrets, { label: "", value: "" }])}>＋ 第2暗証番号などを追加</button>
          </div>}
          {field("url", "URL", false, "text", "https://")}
        </> : <>
          {secretInput("cardNumber", "カード番号", true)}
          {field("cardholder", "名義")}
          {field("expiryMonth", "有効期限", false, "month")}
          {secretInput("securityCode", "セキュリティコード")}
          {field("url", "URL", false, "text", "https://")}
        </>}
        {showExtras ? <>
          {field("group", "グループ", false, "text", "仕事")}
          {field("tags", "タグ", false, "text", "SNS, 個人")}
          <div className="editor-field editor-notes"><label className="form-label" htmlFor={`${fieldId}-notes`}>メモ</label>
            <textarea id={`${fieldId}-notes`} className="form-textarea" rows={3} disabled={busy} value={draft.notes} onChange={(event) => change("notes", event.target.value)} />
          </div>
        </> : <div className="editor-more">
          <button className="text-btn" type="button" disabled={busy} onClick={() => setShowExtras(true)}>＋ グループ・タグ・メモを追加</button>
        </div>}
      </div> : entry && <dl className="entry-view-fields">
        {entry.type === "apiKey" ? <>
          {secretView("apiKey", "キー", entry.apiKey.key)}
          {viewField("キーID", entry.apiKey.keyId, true)}
          {viewField("有効期限", entry.apiKey.expiresOn ?? "")}
        </> : entry.type === "creditCard" ? <>
          {secretView("cardNumber", "カード番号", entry.card.number, `•••• •••• •••• ${entry.card.number.replace(/\D/g, "").slice(-4)}`)}
          {viewField("名義", entry.card.cardholder)}
          {viewField("有効期限", entry.card.expiryMonth ?? "")}
          {secretView("securityCode", "セキュリティコード", entry.card.securityCode, "•••")}
        </> : entry.type === "financial" ? <>
          {viewField("ログインID", entry.financial.loginId, true)}
          {secretView("password", "ログインパスワード", entry.financial.loginPassword)}
          {secretView("tradingPassword", "取引パスワード", entry.financial.tradingPassword)}
          {entry.financial.extraSecrets.map((secret, index) => <Fragment key={index}>{secretView(`extra-${index}`, secret.label, secret.value)}</Fragment>)}
        </> : <>
          {viewField("ログインID", entry.loginId, true, false, true)}
          {secretView("password", "パスワード", entry.password)}
        </>}
        {viewField("URL", entry.url, true)}
        {viewField("グループ", entry.group ?? "", false, true)}
        {entry.tags.length > 0 && <div className="entry-view-field"><dt>タグ</dt><dd className="entry-view-tags">{entry.tags.map((tag, index) => <span key={`${tag}-${index}`} className="tag-chip">{tag}</span>)}</dd><span /></div>}
        {entry.notes && <div className="entry-view-field entry-view-notes"><dt>メモ</dt><dd>{entry.notes}</dd><span /></div>}
      </dl>}
    </div>
    {editing && <div className="editor-actions">
      {entry && onDelete && <button className="text-btn text-btn--danger entry-delete" type="button" disabled={busy || isGenerating} onClick={onDelete}>削除</button>}
      <span className="editor-actions-spacer" />
      <button className="btn" type="button" disabled={busy || isGenerating} onClick={onCancel}>キャンセル</button>
      <button className="btn btn--primary editor-save-btn" type="submit" disabled={busy || isGenerating || migrationRequired}>{isSaving ? "保存中…" : "保存"}</button>
    </div>}
  </form>;
}
