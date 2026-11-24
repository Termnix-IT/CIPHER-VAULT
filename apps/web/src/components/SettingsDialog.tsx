import { useEffect, useRef, useState } from "react";
import { AUTO_LOCK_MINUTES, type AutoLockMinutes } from "@password-manager/shared/types";
import { fetchVaultStatus, setAutoLock } from "../lib/api";
import { showModalDialog } from "../lib/modal";
import { CloseIcon } from "./Icons";

const OFF = "off";

/** "5分" or "1時間", as the menus and the lock notice say it. */
export function autoLockText(minutes: number) {
  return minutes >= 60 && minutes % 60 === 0 ? `${minutes / 60}時間` : `${minutes}分`;
}

type SettingsDialogProps = {
  open: boolean;
  autoLockMinutes: AutoLockMinutes | undefined;
  onClose: () => void;
  onSaved: (message: string) => void;
};

/** The app's settings. Only the auto-lock time for now; it is saved beside the vault, so it applies before unlocking too. */
export function SettingsDialog({ open, autoLockMinutes, onClose, onSaved }: SettingsDialogProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const current = autoLockMinutes === undefined ? "" : autoLockMinutes === null ? OFF : String(autoLockMinutes);
  const [choice, setChoice] = useState(current);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      setChoice(current); setError("");
      showModalDialog(dialog);
    } else if (!open && dialog.open) dialog.close();
  }, [open]);

  async function save() {
    if (!choice) return;
    const minutes = choice === OFF ? null : Number(choice) as Exclude<AutoLockMinutes, null>;
    setSaving(true); setError("");
    try {
      await setAutoLock({ autoLockMinutes: minutes });
      await fetchVaultStatus().catch(() => undefined);
      dialogRef.current?.close();
      onSaved(minutes === null ? "時間による自動ロックを無効にしました" : `${autoLockText(minutes)}操作がないとロックします`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "設定を保存できませんでした");
    } finally { setSaving(false); }
  }

  return <dialog className="vault-tool-dialog settings-dialog" ref={dialogRef} aria-labelledby="settings-title" onClose={onClose}
    onCancel={(event) => { if (saving) event.preventDefault(); }}>
    <header className="vault-tool-heading">
      <h2 id="settings-title">設定</h2>
      <button className="icon-btn" type="button" aria-label="閉じる" disabled={saving} onClick={() => dialogRef.current?.close()}><CloseIcon /></button>
    </header>
    <form className="settings-form" onSubmit={(event) => { event.preventDefault(); void save(); }}>
      <div className="dialog-body settings-body">
      <label className="settings-field">
        <span className="settings-label">自動ロック</span>
        <select value={choice} disabled={saving} onChange={(event) => setChoice(event.target.value)} aria-describedby="settings-auto-lock-note">
          {choice === "" && <option value="" disabled>読み込み中…</option>}
          {AUTO_LOCK_MINUTES.map((minutes) => <option key={minutes} value={minutes}>{autoLockText(minutes)}操作がないとき{minutes === 15 ? "（おすすめ）" : ""}</option>)}
          <option value={OFF}>無効</option>
        </select>
      </label>
      <p className="vault-tool-note" id="settings-auto-lock-note">
        パソコンの画面ロック・スリープ・アプリの終了では、この設定にかかわらずロックします。
      </p>
      {choice === OFF && <p className="settings-warning" role="alert">
        無効にすると、操作しないまま席を離れても保管庫は開いたままになります。離れるときはロック（Ctrl+L）か、パソコンの画面ロックを使ってください。
      </p>}
      {error && <p className="form-error" role="alert">{error}</p>}
      </div>
      <footer className="dialog-footer">
        <button className="btn" type="button" disabled={saving} onClick={() => dialogRef.current?.close()}>キャンセル</button>
        <button className="btn btn--primary" type="submit" disabled={saving || !choice || choice === current}>{saving ? "保存しています…" : "保存"}</button>
      </footer>
    </form>
  </dialog>;
}
