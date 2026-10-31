import { useEffect, useRef, useState, type FormEvent } from "react";
import type { VaultMaintenanceOperation, VaultStatus } from "@password-manager/shared/types";
import { cancelVaultMaintenance, fetchVaultStatus, runVaultMaintenance } from "../lib/api";
import { CloseIcon } from "./Icons";

const empty = () => ({ master: "", next: "", nextConfirm: "", backup: "", backupConfirm: "" });
const titles: Record<VaultMaintenanceOperation, string> = {
  migrate: "保管庫を更新", rekey: "マスターパスワードを変更", reset: "保管庫を空にする", recover: "前回の変更を完了させてください"
};
const leads: Record<VaultMaintenanceOperation, string> = {
  migrate: "APIキーとカードを保存できる形式にします。あわせてマスターパスワードも新しくします。更新前の保管庫はこのパソコンに残ります。",
  rekey: "変更前の保管庫は、前のパスワードで開ける状態のまま、このパソコンに残ります。",
  reset: "一覧が空になります。今のデータはこのパソコンに残ります。",
  recover: "途中で止まった変更を、そのとき入力したパスワードで完了させます。"
};
const submitLabels: Record<VaultMaintenanceOperation, string> = { migrate: "更新する", rekey: "変更する", reset: "空にする", recover: "完了させる" };

export function VaultMaintenance({ status, requested, opened, onClose }: { status: VaultStatus; requested?: VaultMaintenanceOperation | null; opened: boolean; onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null), form = useRef<HTMLFormElement>(null), firstInput = useRef<HTMLInputElement>(null);
  const busyRef = useRef(false), alive = useRef(true), source = useRef(""), wasOpened = useRef(false);
  const cancelRequested = useRef(false);
  // Same rule as the Tools menu and the editor notice: only a known v2 vault offers rekey.
  const fallback = (): VaultMaintenanceOperation => status.maintenance?.format === "v2" ? "rekey" : "migrate";
  const [operation, setOperation] = useState<VaultMaintenanceOperation>(status.maintenance?.state === "recovery-required" ? "recover" : fallback());
  const [fields, setFields] = useState(empty), [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false), [cancelBusy, setCancelBusy] = useState(false), [error, setError] = useState(""), [message, setMessage] = useState("");
  const required = status.maintenance?.state !== undefined && status.maintenance.state !== "ready";
  const processing = busy || status.maintenance?.state === "running";
  const reset = operation === "reset" || (operation === "recover" && status.maintenance?.recoveryOperation === "reset");
  const unavailable = operation === "recover" && status.maintenance?.state === "recovery-required" && !status.maintenance.recoveryOperation;
  const lockedResult = !required && !status.isUnlocked && !processing;
  const showForm = !unavailable && !processing && !lockedResult;

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
        setOperation(status.maintenance?.state === "recovery-required" ? "recover" : status.maintenance?.operation ?? requested ?? fallback());
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

  async function submit(event: FormEvent) {
    event.preventDefault(); if (processing || unavailable) return;
    if (fields.next !== fields.nextConfirm || (operation !== "recover" && fields.backup !== fields.backupConfirm)) { setError("もう一度入力した内容が一致しません"); return; }
    if (fields.master === fields.next) { setError("今とは違うマスターパスワードにしてください"); return; }
    if (reset && !acknowledged) { setError("保管庫を空にすることを確認してください"); return; }
    const payload = { operation, masterPassword: fields.master, newMasterPassword: fields.next, confirmNewMasterPassword: fields.nextConfirm,
      backupPassphrase: fields.backup, ...(operation !== "recover" ? { confirmBackupPassphrase: fields.backupConfirm } : {}), ...(reset ? { confirmation: "RESET_ALL_DATA" as const } : {}) };
    source.current = status.sessionId; cancelRequested.current = false; busyRef.current = true; setBusy(true); setError(""); setMessage(""); clearSecrets();
    try {
      const result = await runVaultMaintenance(payload);
      if (alive.current) setMessage(result.maintenance?.state === "ready" ? "変更しました。新しいマスターパスワードで開いてください。" : "状態を確かめて、必要なら続きを完了させてください。");
    } catch (cause) { if (alive.current) {
      if (cancelRequested.current) setMessage("中止しました。保管庫の状態を確かめてから開いてください。");
      else setError(cause instanceof Error ? cause.message : "完了できませんでした");
    } }
    finally { busyRef.current = false; if (alive.current) { setBusy(false); clearSecrets(); } }
  }
  async function cancel() {
    if (cancelBusy) return; cancelRequested.current = true; setCancelBusy(true); setError("");
    try {
      const result = await cancelVaultMaintenance(busyRef.current ? source.current : status.maintenance?.sourceSessionId || status.sessionId);
      if (alive.current) setMessage(result.requested ? "中止を受け付けました。止まるまでお待ちください。" : "すでに終わっているか、状態が変わっています。状態を確かめてください。");
    } catch (cause) { cancelRequested.current = false; if (alive.current) setError(cause instanceof Error ? cause.message : "中止できたか確認できませんでした"); }
    finally { if (alive.current) setCancelBusy(false); }
  }
  function close() { if (required || processing) return; clearSecrets(); dialog.current?.close(); onClose(); }

  const recover = operation === "recover";
  return <dialog ref={dialog} className="vault-tool-dialog vault-maintenance-dialog" aria-labelledby="maintenance-title"
    onCancel={event => { event.preventDefault(); if (!required && !processing) close(); }}
    onClose={() => { if (dialog.current?.open) return; clearSecrets(); document.querySelector<HTMLInputElement>(".cipher-form input")?.focus(); }}>
    <header className="vault-tool-heading"><h2 id="maintenance-title">{titles[operation]}</h2>
      {!required && !processing && <button className="icon-btn" type="button" aria-label="閉じる" onClick={close}><CloseIcon /></button>}</header>
    <div className="dialog-body">
      {unavailable ? <p role="alert">復旧に必要な情報が見つかりません。アプリを終了し、保管庫のファイルはそのまま残してください。</p>
        : processing ? <div role="status" className="maintenance-progress"><span className="spinner" aria-hidden="true" />変更しています。終わるまで閉じずにお待ちください。</div>
        : lockedResult ? (message ? null : <p className="maintenance-lead">続けるには、閉じて保管庫を開き直してください。</p>)
        : <form id="maintenance-form" ref={form} onSubmit={event => void submit(event)}>
          <p className="maintenance-lead">{leads[operation]}</p>
          <div className="maintenance-fields">
            <label className="vault-tool-field maintenance-wide">{recover ? "変更前のマスターパスワード" : "今のマスターパスワード"}
              <input ref={firstInput} type="password" autoComplete="current-password" maxLength={1048576} value={fields.master} onChange={e => setFields({ ...fields, master: e.target.value })} /></label>
            <label className="vault-tool-field">{recover ? "変更時に決めたマスターパスワード" : "新しいマスターパスワード"}
              <input type="password" autoComplete="new-password" minLength={12} maxLength={1048576} required placeholder="12文字以上" value={fields.next} onChange={e => setFields({ ...fields, next: e.target.value })} /></label>
            <label className="vault-tool-field">もう一度入力
              <input type="password" autoComplete="new-password" minLength={12} maxLength={1048576} required value={fields.nextConfirm} onChange={e => setFields({ ...fields, nextConfirm: e.target.value })} /></label>
            <label className={`vault-tool-field ${recover ? "maintenance-wide" : ""}`}>復旧用パスワード
              <input type="password" autoComplete={recover ? "off" : "new-password"} minLength={12} maxLength={1024} required placeholder={recover ? undefined : "12文字以上"} value={fields.backup} onChange={e => setFields({ ...fields, backup: e.target.value })} /></label>
            {!recover && <label className="vault-tool-field">もう一度入力
              <input type="password" autoComplete="new-password" minLength={12} maxLength={1024} required value={fields.backupConfirm} onChange={e => setFields({ ...fields, backupConfirm: e.target.value })} /></label>}
          </div>
          {!recover && <p className="vault-tool-note">復旧用パスワードは、変更が途中で止まったときに元に戻すために使います。</p>}
          {reset && <label className="maintenance-acknowledgement"><input type="checkbox" required checked={acknowledged} onChange={e => setAcknowledged(e.target.checked)} />保管庫を空にすることを確認しました</label>}
        </form>}
      {message && <p role="status" className="vault-tool-message">{message}</p>}{error && <p role="alert" className="form-error">{error}</p>}
    </div>
    {processing ? <footer className="dialog-footer maintenance-actions"><button className="btn" type="button" disabled={cancelBusy} onClick={() => void cancel()}>中止</button></footer>
      : showForm ? <footer className="dialog-footer maintenance-actions">
        {required && <button className="btn" type="button" onClick={() => void fetchVaultStatus().catch(() => setError("保管庫の状態を確かめられませんでした"))}>状態を確かめる</button>}
        {!required && <button className="btn" type="button" onClick={close}>キャンセル</button>}
        <button className={`btn ${reset ? "btn--danger" : "btn--primary"}`} type="submit" form="maintenance-form">{submitLabels[operation]}</button>
      </footer>
      : required ? <footer className="dialog-footer maintenance-actions">
        <button className="btn" type="button" onClick={() => void fetchVaultStatus().catch(() => setError("保管庫の状態を確かめられませんでした"))}>状態を確かめる</button>
      </footer>
      : lockedResult ? <footer className="dialog-footer maintenance-actions"><button className="btn btn--primary" type="button" onClick={close}>閉じる</button></footer> : null}
  </dialog>;
}
