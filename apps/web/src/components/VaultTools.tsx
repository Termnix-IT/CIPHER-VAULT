import { useEffect, useRef, useState, type ReactNode } from "react";
import type { AuditIssue, SecurityAudit } from "@password-manager/shared/types";
import { auditVault, exportBackup, restoreBackup } from "../lib/api";
import { CloseIcon, FileIcon } from "./Icons";

const labels: Record<AuditIssue, string> = {
  weak: "推測されやすい", duplicate: "使い回し", oldPassword: "1年以上変更なし",
  missingUrl: "URLなし", staleEntry: "1年以上更新なし"
};
const URGENT: AuditIssue[] = ["weak", "duplicate"];
const REVIEW: AuditIssue[] = ["oldPassword", "missingUrl", "staleEntry"];
const MAX_BACKUP_BYTES = 16 * 1024 * 1024;

export function VaultTools({ entryCount, disabled, onRefresh, onSelect, renderTrigger, onClose }: {
  entryCount: number; disabled: boolean; onRefresh: () => Promise<void>; onSelect: (id: string) => Promise<void>;
  renderTrigger?: (open: (panel: "audit" | "backup") => void) => ReactNode;
  onClose?: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const alive = useRef(false);
  const [panel, setPanel] = useState<"audit" | "backup">("audit");
  const [backupTab, setBackupTab] = useState<"export" | "restore">("export");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [audit, setAudit] = useState<SecurityAudit | null>(null);
  const [filter, setFilter] = useState<AuditIssue | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [restorePassphrase, setRestorePassphrase] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);

  function clearSecrets() {
    setPassphrase(""); setConfirmation(""); setRestorePassphrase(""); setFile(null);
    if (fileInput.current) fileInput.current.value = "";
  }

  async function run(action: () => Promise<void>) {
    if (busy) return;
    setBusy(true); setError(""); setMessage("");
    try { await action(); }
    catch (cause) { if (alive.current) setError(cause instanceof Error ? cause.message : "うまくいきませんでした"); }
    finally { if (alive.current) { setBusy(false); setPassphrase(""); setConfirmation(""); setRestorePassphrase(""); } }
  }

  async function scan() {
    setAudit(null);
    await run(async () => {
      const result = await auditVault();
      if (alive.current) setAudit(result);
    });
  }

  function open(next: "audit" | "backup") {
    if (disabled || busy) return;
    setPanel(next); setBackupTab("export"); setError(""); setMessage(""); setFilter(null); setAudit(null); clearSecrets();
    dialog.current?.showModal();
    if (next === "audit") void scan();
  }

  function switchBackupTab(next: "export" | "restore") {
    if (busy) return;
    setBackupTab(next); setError(""); setMessage(""); clearSecrets();
  }

  async function saveBackup() {
    if (passphrase !== confirmation) { setError("もう一度入力した内容が一致しません"); return; }
    await run(async () => {
      const result = await exportBackup({ passphrase });
      if (!alive.current) return;
      const url = URL.createObjectURL(new Blob([result.content], { type: "application/octet-stream" }));
      const anchor = document.createElement("a");
      anchor.href = url; anchor.download = result.fileName;
      document.body.append(anchor); anchor.click(); anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 30000);
      setMessage("ファイルの保存を始めました。保存先に .cvault ファイルがあるか確かめてください。");
    });
  }

  async function restore() {
    await run(async () => {
      if (!file) throw new Error(".cvault ファイルを選んでください");
      if (file.size > MAX_BACKUP_BYTES) throw new Error("16 MiBまでのファイルを選んでください");
      const content = await file.text();
      if (!alive.current) return;
      const result = await restoreBackup({ passphrase: restorePassphrase, content });
      if (!alive.current) return;
      clearSecrets();
      await onRefresh();
      if (alive.current) setMessage(`${result.restoredCount}件を読み込みました。`);
    });
  }

  const visibleItems = audit?.items.filter((item) => !filter || item.issues.includes(filter)) ?? [];
  const urgentCount = audit?.items.filter((item) => item.issues.some((issue) => URGENT.includes(issue))).length ?? 0;
  const filterButton = (issue: AuditIssue, content: ReactNode) => <button key={issue} type="button" aria-pressed={filter === issue}
    onClick={() => setFilter(filter === issue ? null : issue)}>{content}</button>;

  return <>
    {renderTrigger ? renderTrigger(open) : <>
      <button className="btn" disabled={disabled} onClick={() => open("audit")}>パスワードの点検</button>
      <button className="btn" disabled={disabled} onClick={() => open("backup")}>バックアップ</button>
    </>}
    <dialog ref={dialog} className={`vault-tool-dialog ${panel === "audit" ? "audit-dialog" : "backup-dialog"}`} aria-labelledby="vault-tool-title"
      onCancel={(event) => { if (busy) event.preventDefault(); }}
      onClose={() => { clearSecrets(); setAudit(null); onClose?.(); }}>
      <header className="vault-tool-heading">
        <h2 id="vault-tool-title">{panel === "audit" ? "パスワードの点検" : "バックアップ"}</h2>
        <button className="icon-btn" type="button" aria-label="閉じる" disabled={busy} onClick={() => dialog.current?.close()}><CloseIcon /></button>
      </header>
      {panel === "audit" ? <>
        <div className="dialog-body">
          <div className="audit-score">
            <strong>{audit?.score ?? "—"}<small> / 100</small></strong>
            <p>{!audit ? (busy ? "点検しています…" : "")
              : audit.total === 0 ? "項目を保存すると点検できます"
              : urgentCount ? `${audit.total}件中 ${urgentCount}件に直したい点があります` : `${audit.total}件すべて、直したい点はありません`}</p>
          </div>
          {audit && audit.total > 0 && <>
            <p className="dialog-section-label">直したほうがいい</p>
            <div className="audit-urgent" aria-label="直したほうがいい項目で絞り込み">
              {URGENT.map((issue) => filterButton(issue, <>
                <span>{labels[issue]}</span><strong className={audit.counts[issue] ? "" : "audit-zero"}>{audit.counts[issue]}</strong>
              </>))}
            </div>
            <p className="dialog-section-label">余裕があれば見直す</p>
            <div className="audit-review" aria-label="見直し項目で絞り込み">
              {REVIEW.map((issue) => filterButton(issue, <>{labels[issue]}<span>{audit.counts[issue]}</span></>))}
            </div>
            <div className="audit-results">
              {visibleItems.map((item) => <div className="audit-row" key={item.id}>
                <div><div>{item.serviceName}</div><p className="audit-reasons">{item.issues.map((issue) => labels[issue]).join(" · ")}</p></div>
                <button className="btn btn--small" type="button" onClick={() => { dialog.current?.close(); void onSelect(item.id); }}>開く</button>
              </div>)}
              {visibleItems.length === 0 && <p className="audit-empty">{filter ? "当てはまる項目はありません" : "見直す項目はありません"}</p>}
            </div>
            <details className="vault-tool-details"><summary>スコアの決め方</summary>
              <p>推測されやすいパスワードや使い回しが多いほど、点数が下がります。</p>
              <p>1年以上変更していないパスワード、URLなし、1年以上更新していない項目は、点数に影響しません。</p>
              {audit.unknownPasswordAgeCount > 0 && <p>パスワードを変えた日がわからない項目が{audit.unknownPasswordAgeCount}件あります。次に変えた日から記録します。</p>}
              <p>流出したパスワードかどうかは確認していません。100点でも安全とは限りません。</p>
            </details>
          </>}
          {error && <p role="alert" className="form-error">{error}</p>}
        </div>
        <footer className="dialog-footer dialog-footer--split">
          <span className="dialog-footer-meta">{audit ? `${new Date(audit.checkedAt).toLocaleString("ja-JP", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" })} に点検` : ""}</span>
          <button className="btn" type="button" disabled={busy} onClick={() => void scan()}>もう一度点検</button>
        </footer>
      </> : <>
        <div className="dialog-body">
          <div className="segmented dialog-tabs" role="tablist" aria-label="バックアップの操作">
            <button type="button" role="tab" aria-selected={backupTab === "export"} disabled={busy} onClick={() => switchBackupTab("export")}>書き出す</button>
            <button type="button" role="tab" aria-selected={backupTab === "restore"} disabled={busy} onClick={() => switchBackupTab("restore")}>読み込む</button>
          </div>
          {backupTab === "export" ? <form id="backup-export" onSubmit={(event) => { event.preventDefault(); void saveBackup(); }}>
            <p className="vault-tool-lead">すべての項目を、1つのファイルに暗号化して保存します。</p>
            <label className="vault-tool-field">バックアップ用パスワード
              <input type="password" autoComplete="new-password" minLength={12} maxLength={1024} required disabled={busy} placeholder="12文字以上"
                value={passphrase} onChange={(event) => setPassphrase(event.target.value)} /></label>
            <label className="vault-tool-field">もう一度入力
              <input type="password" autoComplete="new-password" maxLength={1024} required disabled={busy}
                value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></label>
            <p className="vault-tool-note">読み込むときに必要です。ファイルとは別の場所に控えてください。</p>
          </form> : entryCount > 0 ? <p className="vault-tool-lead">読み込めるのは、項目が1件もない保管庫だけです。</p>
            : <form id="backup-restore" onSubmit={(event) => { event.preventDefault(); void restore(); }}>
              <label className="file-drop">
                <FileIcon />{file ? file.name : ".cvault ファイルを選ぶ"}
                <input ref={fileInput} type="file" accept=".cvault" disabled={busy} onChange={(event) => setFile(event.target.files?.[0] ?? null)} />
              </label>
              <label className="vault-tool-field">バックアップ用パスワード
                <input type="password" autoComplete="off" maxLength={1024} required disabled={busy}
                  value={restorePassphrase} onChange={(event) => setRestorePassphrase(event.target.value)} /></label>
            </form>}
          {busy && <p className="vault-tool-status" role="status">処理しています…</p>}
          {message && <p role="status" className="vault-tool-message">{message}</p>}
          {error && <p role="alert" className="form-error">{error}</p>}
        </div>
        {(backupTab === "export" || entryCount === 0) && <footer className="dialog-footer">
          {backupTab === "export"
            ? <button className="btn btn--primary" type="submit" form="backup-export" disabled={busy}>{entryCount}件を書き出す</button>
            : <button className="btn btn--primary" type="submit" form="backup-restore" disabled={busy || !file || restorePassphrase.length < 12}>読み込む</button>}
        </footer>}
      </>}
    </dialog>
  </>;
}
