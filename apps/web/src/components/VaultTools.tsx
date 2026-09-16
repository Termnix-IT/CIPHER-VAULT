import { useEffect, useRef, useState } from "react";
import type { AuditIssue, SecurityAudit } from "@password-manager/shared/types";
import { auditVault, exportBackup, restoreBackup } from "../lib/api";

const labels: Record<AuditIssue, string> = {
  weak: "弱いパスワード", duplicate: "重複パスワード", oldPassword: "古いパスワード",
  missingUrl: "URLなし", staleEntry: "長期間更新なし"
};

export function VaultTools({ entryCount, disabled, onRefresh, onSelect, onLock }: {
  entryCount: number; disabled: boolean; onRefresh: () => Promise<void>; onSelect: (id: string) => Promise<void>;
  onLock: () => Promise<void>;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const alive = useRef(false);
  const [panel, setPanel] = useState<"audit" | "backup">("audit");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [audit, setAudit] = useState<SecurityAudit | null>(null);
  const [filter, setFilter] = useState<AuditIssue | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);

  function clearSecrets() {
    setPassphrase(""); setConfirmation(""); setFile(null);
    if (fileInput.current) fileInput.current.value = "";
  }

  async function run(action: () => Promise<void>) {
    if (busy) return;
    setBusy(true); setError(""); setMessage("");
    try { await action(); }
    catch (cause) { if (alive.current) setError(cause instanceof Error ? cause.message : "処理に失敗しました"); }
    finally { if (alive.current) { setBusy(false); setPassphrase(""); setConfirmation(""); } }
  }

  async function scan() {
    setAudit(null);
    await run(async () => {
      const result = await auditVault();
      if (alive.current) setAudit(result);
    });
  }

  function open(next: "audit" | "backup") {
    setPanel(next); setError(""); setMessage(""); setFilter(null); setAudit(null); clearSecrets();
    dialog.current?.showModal();
    if (next === "audit") void scan();
  }

  async function saveBackup() {
    if (passphrase !== confirmation) { setError("確認用パスフレーズが一致しません"); return; }
    await run(async () => {
      const result = await exportBackup({ passphrase });
      if (!alive.current) return;
      const url = URL.createObjectURL(new Blob([result.content], { type: "application/octet-stream" }));
      const anchor = document.createElement("a");
      anchor.href = url; anchor.download = result.fileName;
      document.body.append(anchor); anchor.click(); anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 30000);
      setMessage("暗号化ファイルの保存を開始しました。保存先に .cvault ファイルがあることを確認してください。");
    });
  }

  async function restore() {
    await run(async () => {
      if (!file) throw new Error(".cvault ファイルを選択してください");
      if (file.size > 16 * 1024 * 1024) throw new Error("ファイルは16 MiB以内で指定してください");
      const content = await file.text();
      if (!alive.current) return;
      const result = await restoreBackup({ passphrase, content });
      if (!alive.current) return;
      clearSecrets();
      await onRefresh();
      if (alive.current) setMessage(`${result.restoredCount}件を復元しました。現在のマスターパスワードで引き続き利用できます。`);
    });
  }

  return <>
    <button className="cipher-btn" disabled={disabled} title={disabled ? "編集中の内容を保存してください" : undefined} onClick={() => open("audit")}>セキュリティ監査</button>
    <button className="cipher-btn" disabled={disabled} title={disabled ? "編集中の内容を保存してください" : undefined} onClick={() => open("backup")}>バックアップ</button>
    <dialog ref={dialog} className="vault-tool-dialog" aria-labelledby="vault-tool-title"
      onCancel={(event) => { if (busy) event.preventDefault(); }}
      onClose={() => { clearSecrets(); setAudit(null); }}>
      <header className="vault-tool-heading">
        <div><p className="vault-tool-eyebrow">LOCAL VAULT / {panel === "audit" ? "SECURITY" : "BACKUP"}</p>
          <h2 id="vault-tool-title">{panel === "audit" ? "セキュリティ監査" : "暗号化バックアップ / 復元"}</h2></div>
        <div className="vault-header-actions">
          <button className="cipher-btn" onClick={() => void onLock()}>ロック</button>
          <button className="cipher-btn" disabled={busy} onClick={() => dialog.current?.close()}>閉じる</button>
        </div>
      </header>
      {panel === "audit" ? <>
        <p className="vault-tool-note">端末内で解析します。スコアはパスワードの強さと使い回しの目安です。</p>
        <div className="audit-score"><span>SECURITY SCORE</span><strong>{audit?.score ?? "—"}<small> / 100</small></strong>
          <p>{audit ? `${audit.total}件を確認 · ${new Date(audit.checkedAt).toLocaleString("ja-JP")}` : busy ? "解析中…" : "未解析"}</p></div>
        {audit && <>
          {audit.total === 0 ? <p>エントリを保存すると監査できます。</p> : <>
            <div className="audit-counts" aria-label="監査項目で絞り込み">
              {(Object.keys(labels) as AuditIssue[]).map((issue) => <button key={issue} aria-pressed={filter === issue}
                onClick={() => setFilter(filter === issue ? null : issue)}>
                <span>{labels[issue]}</span><strong>{audit.counts[issue]}<small> 件</small></strong>
                <span className="vault-tool-note">{issue === "weak" || issue === "duplicate" ? "スコア対象" : "見直し項目"}</span>
              </button>)}
            </div>
            <div className="audit-results">
              <h3>{filter ? labels[filter] : "確認が必要なエントリ"}</h3>
              {audit.items.filter((item) => !filter || item.issues.includes(filter)).map((item) => <div className="audit-row" key={item.id}>
                <div><strong>{item.serviceName}</strong><p>{item.loginId}</p><p className="audit-reasons">{item.issues.map((issue) => labels[issue]).join(" / ")}</p></div>
                <button className="cipher-btn" onClick={() => { dialog.current?.close(); void onSelect(item.id); }}>エントリを開く</button>
              </div>)}
              {!audit.items.some((item) => !filter || item.issues.includes(filter)) && <p>該当するエントリはありません。</p>}
            </div>
          </>}
          <details className="vault-tool-details"><summary>判定基準とスコアの計算</summary>
            <p>弱さは zxcvbn の評価が0〜2、重複はパスワードの完全一致です。同じパスワードを使う全エントリを対象にします。</p>
            <p>100 −（弱い件数 × 60 ＋ 重複件数 × 40）÷ 全件数 を四捨五入。0件の場合はスコアを表示しません。</p>
            <p>古いパスワードは変更から365日以上、長期間更新なしはエントリの更新から365日以上です。URL未登録と合わせて減点対象にはしません。古さだけで変更を要求するものではありません。</p>
            <p>パスワード変更日が不明：{audit.unknownPasswordAgeCount}件。旧版のデータは次にパスワードを変更した時点から記録します。</p>
            <p>漏えい情報の照会は行いません。辞書による強度推定には限界があり、100点でも安全性を保証しません。</p>
          </details>
        </>}
        <button className="cipher-btn" disabled={busy} onClick={() => void scan()}>再解析</button>
      </> : <>
        <p className="vault-tool-note">サービス名・ID・パスワード・メモ・URL・タグ・グループ・日時を、専用パスフレーズで1つの .cvault ファイルに暗号化します。</p>
        <p>復元先では先にマスターパスワードを設定し、空の保管庫でこの画面を開いてください。</p>
        <form onSubmit={(event) => { event.preventDefault(); void saveBackup(); }}>
          <label className="vault-tool-field">バックアップ用パスフレーズ
            <input type="password" autoComplete="new-password" minLength={12} maxLength={1024} required disabled={busy}
              value={passphrase} onChange={(event) => setPassphrase(event.target.value)} /></label>
          <p className="vault-tool-note">12文字以上。復元にはこのパスフレーズが必要です。ファイルとは別の安全な場所に保管してください。</p>
          <label className="vault-tool-field">確認用パスフレーズ（書き出し時）
            <input type="password" autoComplete="new-password" maxLength={1024} disabled={busy}
              value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></label>
          <button className="cipher-btn cipher-btn--primary" type="submit" disabled={busy}>暗号化して書き出す（{entryCount}件）</button>
        </form>
        <section className="vault-restore"><h3>空の保管庫に復元</h3>
          {entryCount > 0 ? <p>この保管庫には{entryCount}件のデータがあるため、復元できません。</p> : <>
            <label className="vault-tool-field">バックアップファイル（最大16 MiB）
              <input ref={fileInput} type="file" accept=".cvault" disabled={busy} onChange={(event) => setFile(event.target.files?.[0] ?? null)} /></label>
            <p className="vault-tool-note">上のパスフレーズ欄に、書き出し時のパスフレーズを入力してください。</p>
            <button className="cipher-btn" disabled={busy || !file || passphrase.length < 12} onClick={() => void restore()}>選択したファイルを復元</button>
          </>}
        </section>
      </>}
      {busy && <p role="status">{panel === "audit" ? "解析しています…" : "暗号化データを処理しています…"}</p>}
      {message && <p role="status" className="vault-tool-message">{message}</p>}
      {error && <p role="alert" className="form-error">{error}</p>}
    </dialog>
  </>;
}
