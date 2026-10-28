import { useEffect, useRef, useState, type FormEvent } from "react";
import type { VaultMaintenanceOperation, VaultStatus } from "@password-manager/shared/types";
import { cancelVaultMaintenance, fetchVaultStatus, runVaultMaintenance } from "../lib/api";

const empty = () => ({ master: "", next: "", nextConfirm: "", backup: "", backupConfirm: "" });
const titles: Record<VaultMaintenanceOperation, string> = {
  migrate: "新しい形式へ移行", rekey: "マスターパスワード・鍵の更新", reset: "空の保管庫へ切り替え", recover: "中断後の復旧"
};

export function VaultMaintenance({ status, opened, onClose }: { status: VaultStatus; opened: boolean; onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null), form = useRef<HTMLFormElement>(null), firstInput = useRef<HTMLInputElement>(null);
  const busyRef = useRef(false), alive = useRef(true), source = useRef(""), wasOpened = useRef(false);
  const cancelRequested = useRef(false);
  const [operation, setOperation] = useState<VaultMaintenanceOperation>(status.maintenance?.state === "recovery-required" ? "recover" : status.maintenance?.format === "legacy" ? "migrate" : "rekey");
  const [fields, setFields] = useState(empty), [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false), [cancelBusy, setCancelBusy] = useState(false), [error, setError] = useState(""), [message, setMessage] = useState("");
  const required = status.maintenance?.state !== undefined && status.maintenance.state !== "ready";
  const processing = busy || status.maintenance?.state === "running";
  const reset = operation === "reset" || (operation === "recover" && status.maintenance?.recoveryOperation === "reset");
  const unavailable = operation === "recover" && status.maintenance?.state === "recovery-required" && !status.maintenance.recoveryOperation;
  const lockedResult = !required && !status.isUnlocked && !processing;

  function clearSecrets() {
    form.current?.querySelectorAll<HTMLInputElement>('input[type="password"]').forEach(input => { input.value = ""; });
    setFields(empty()); setAcknowledged(false);
  }
  useEffect(() => { alive.current = true; return () => { alive.current = false; if (busyRef.current) void cancelVaultMaintenance(source.current).catch(() => undefined); }; }, []);
  useEffect(() => {
    if (opened) {
      if (!wasOpened.current) {
        cancelRequested.current = false;
        clearSecrets(); setError(""); setMessage("");
        setOperation(status.maintenance?.state === "recovery-required" ? "recover" : status.maintenance?.operation ?? (status.maintenance?.format === "legacy" ? "migrate" : "rekey"));
      }
      if (!dialog.current?.open) dialog.current?.showModal();
      if (!processing) firstInput.current?.focus();
    } else { dialog.current?.close(); clearSecrets(); }
    wasOpened.current = opened;
  }, [opened]);
  useEffect(() => {
    if (busyRef.current) return;
    clearSecrets();
    if (status.maintenance?.state === "recovery-required") setOperation("recover");
    else if (status.maintenance?.state === "running" && status.maintenance.operation) { setMessage(""); setError(""); setOperation(status.maintenance.operation); }
  }, [status.sessionId, status.isUnlocked, status.maintenance?.state, busy]);

  function changeOperation(next: VaultMaintenanceOperation) { if (processing) return; clearSecrets(); setOperation(next); setError(""); setMessage(""); }
  async function submit(event: FormEvent) {
    event.preventDefault(); if (processing || unavailable) return;
    if (fields.next !== fields.nextConfirm || (operation !== "recover" && fields.backup !== fields.backupConfirm)) { setError("確認用の入力が一致しません"); return; }
    if (fields.master === fields.next) { setError("現在とは異なるマスターパスワードを設定してください"); return; }
    if (reset && !acknowledged) { setError("空の保管庫への切り替えを確認してください"); return; }
    const payload = { operation, masterPassword: fields.master, newMasterPassword: fields.next, confirmNewMasterPassword: fields.nextConfirm,
      backupPassphrase: fields.backup, ...(operation !== "recover" ? { confirmBackupPassphrase: fields.backupConfirm } : {}), ...(reset ? { confirmation: "RESET_ALL_DATA" as const } : {}) };
    source.current = status.sessionId; cancelRequested.current = false; busyRef.current = true; setBusy(true); setError(""); setMessage(""); clearSecrets();
    try {
      const result = await runVaultMaintenance(payload);
      if (alive.current) setMessage(result.maintenance?.state === "ready" ? "切り替えを完了しました。閉じて、新しいマスターパスワードで保管庫を解除してください。" : "状態を確認し、必要な復旧を完了してください。");
    } catch (cause) { if (alive.current) {
      if (cancelRequested.current) setMessage("取消を要求しました。保管庫の状態を確認してから解除または復旧を行ってください。");
      else setError(cause instanceof Error ? cause.message : "処理を完了できませんでした");
    } }
    finally { busyRef.current = false; if (alive.current) { setBusy(false); clearSecrets(); } }
  }
  async function cancel() {
    if (cancelBusy) return; cancelRequested.current = true; setCancelBusy(true); setError("");
    try {
      const result = await cancelVaultMaintenance(busyRef.current ? source.current : status.maintenance?.sourceSessionId || status.sessionId);
      if (alive.current) setMessage(result.requested ? "取消を要求しました。処理が停止するまでお待ちください。" : "対象の処理は既に終了したか、状態が変わっています。状態を確認してください。");
    } catch (cause) { cancelRequested.current = false; if (alive.current) setError(cause instanceof Error ? cause.message : "取消の状態を確認できませんでした"); }
    finally { if (alive.current) setCancelBusy(false); }
  }
  function close() { if (required || processing) return; clearSecrets(); dialog.current?.close(); onClose(); }

  return <dialog ref={dialog} className="vault-tool-dialog vault-maintenance-dialog" aria-labelledby="maintenance-title"
    onCancel={event => { event.preventDefault(); if (!required && !processing) close(); }}
    onClose={() => { if (dialog.current?.open) return; clearSecrets(); document.querySelector<HTMLInputElement>(".cipher-form input")?.focus(); }}>
    <header className="vault-tool-heading"><div><p className="vault-tool-eyebrow">LOCAL VAULT / MAINTENANCE</p><h2 id="maintenance-title">保管庫の管理</h2></div>
      {!required && !processing && <button className="cipher-btn" onClick={close}>閉じる</button>}</header>
    {!required && status.isUnlocked && <nav className="maintenance-options" aria-label="保管庫の操作">
      {(status.maintenance?.format === "legacy" ? ["migrate"] as const : ["rekey", "reset"] as const).map(mode =>
        <button key={mode} className="cipher-btn" aria-pressed={operation === mode} disabled={processing} onClick={() => changeOperation(mode)}>{titles[mode]}</button>)}
    </nav>}
    <section className="maintenance-content"><h3>{operation === "recover" ? "切り替えの完了確認が必要です" : titles[operation]}</h3>
      {unavailable ? <p role="alert">復旧対象を確認できません。アプリを終了し、元の保管庫と復旧用ファイルを保持してください。</p> : <>
        <div className="maintenance-summary"><strong>{reset ? "元のデータを保持し、新しい空の保管庫へ切り替えます" : "元の保管庫と復旧用バックアップを保持します"}</strong>
          <p>{operation === "recover" ? "通常の解除と編集を停止しています。操作を始めたときの認証情報で、元の保管庫と切り替え先を照合します。" : reset ? "切り替え後の一覧は空になります。元のDBやバックアップを安全に消去する操作ではありません。" : "全件の照合が終わってから切り替えます。完了後は新しいマスターパスワードで解除してください。"}</p></div>
        <p className="vault-tool-note">以前のパスワードで復号できるデータも、この端末内に保持します。</p>
        {operation === "migrate" && <p className="vault-tool-note">移行後は新形式に対応したアプリで利用してください。旧版で元の保管庫を編集しても、移行先には反映されません。</p>}
        {processing ? <div role="status" className="maintenance-progress"><p>暗号化データと復旧用ファイルを照合しています…</p><p className="vault-tool-note">処理には時間がかかる場合があります。取消を要求した場合も、安全に停止するまでお待ちください。</p></div>
          : lockedResult ? <p>この操作を続けるには、閉じて保管庫の状態を確認し、解除してください。</p>
          : <form ref={form} onSubmit={event => void submit(event)}>
            <div className="maintenance-fields">
              <label className="vault-tool-field maintenance-wide">{operation === "recover" ? "操作前のマスターパスワード" : "現在のマスターパスワード"}
                <input ref={firstInput} type="password" autoComplete="current-password" maxLength={1048576} value={fields.master} onChange={e => setFields({ ...fields, master: e.target.value })} /></label>
              <label className="vault-tool-field">{operation === "recover" ? "操作時に設定したマスターパスワード" : "新しいマスターパスワード"}
                <input type="password" autoComplete="new-password" minLength={12} maxLength={1048576} required value={fields.next} onChange={e => setFields({ ...fields, next: e.target.value })} /></label>
              <label className="vault-tool-field">新しいマスターパスワード（確認）
                <input type="password" autoComplete="new-password" minLength={12} maxLength={1048576} required value={fields.nextConfirm} onChange={e => setFields({ ...fields, nextConfirm: e.target.value })} /></label>
              <label className={`vault-tool-field ${operation === "recover" ? "maintenance-wide" : ""}`}>復旧用バックアップのパスフレーズ
                <input type="password" autoComplete={operation === "recover" ? "off" : "new-password"} minLength={12} maxLength={1024} required value={fields.backup} onChange={e => setFields({ ...fields, backup: e.target.value })} /></label>
              {operation !== "recover" && <label className="vault-tool-field">パスフレーズ（確認）
                <input type="password" autoComplete="new-password" minLength={12} maxLength={1024} required value={fields.backupConfirm} onChange={e => setFields({ ...fields, backupConfirm: e.target.value })} /></label>}
            </div>
            {reset && <label className="maintenance-acknowledgement"><input type="checkbox" required checked={acknowledged} onChange={e => setAcknowledged(e.target.checked)} />空の保管庫へ切り替えることを確認しました</label>}
            <p className="vault-tool-note">新しいマスターパスワードと復旧用パスフレーズは安全な場所に保管し、解除後に端末外へバックアップを書き出してください。</p>
            <footer className="maintenance-actions">{!required && <button className="cipher-btn" type="button" onClick={close}>キャンセル</button>}
              <button className="cipher-btn cipher-btn--primary" type="submit">{operation === "recover" ? "照合して復旧する" : operation === "migrate" ? "確認して移行する" : reset ? "確認して空の保管庫へ切り替える" : "確認して更新する"}</button></footer>
          </form>}
      </>}
      {processing && <div className="maintenance-actions"><button className="cipher-btn" disabled={cancelBusy} onClick={() => void cancel()}>処理を取り消す</button></div>}
      {message && <p role="status" className="vault-tool-message">{message}</p>}{error && <p role="alert" className="form-error">{error}</p>}
      {required && !processing && <button className="cipher-btn" onClick={() => void fetchVaultStatus().catch(() => setError("保管庫の状態を確認できませんでした"))}>状態を更新</button>}
    </section>
  </dialog>;
}
