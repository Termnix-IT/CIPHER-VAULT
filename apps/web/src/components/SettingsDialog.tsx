import { useEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { AUTO_LOCK_MINUTES, type AutoLockMinutes, type GlobalShortcutState } from "@password-manager/shared/types";
import { fetchVaultStatus, getGlobalShortcut, setAutoLock, setGlobalShortcut } from "../lib/api";
import { showModalDialog } from "../lib/modal";
import { globalShortcutOf } from "../lib/shortcuts";
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

/**
 * The app's settings: the auto-lock time, saved beside the vault so it applies before unlocking too,
 * and the call-up shortcut, which works while other apps are in use (apps/desktop/src/global_hotkey.rs).
 */
export function SettingsDialog({ open, autoLockMinutes, onClose, onSaved }: SettingsDialogProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const current = autoLockMinutes === undefined ? "" : autoLockMinutes === null ? OFF : String(autoLockMinutes);
  const [choice, setChoice] = useState(current);
  const [hotkey, setHotkey] = useState<GlobalShortcutState | null>(null);
  const [shortcut, setShortcut] = useState<string | null>(null);
  const [summonCompact, setSummonCompact] = useState(true);
  const [recording, setRecording] = useState(false);
  const [keyProblem, setKeyProblem] = useState("");
  const [loadFailed, setLoadFailed] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  // Each opening reads the key again; an answer for an earlier opening is dropped.
  const opening = useRef(0);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      setChoice(current); setError(""); setKeyProblem(""); setRecording(false); setHotkey(null); setLoadFailed(false);
      const reading = ++opening.current;
      void getGlobalShortcut().then((state) => {
        if (reading !== opening.current) return;
        setHotkey(state); setShortcut(state.shortcut); setSummonCompact(state.summonCompact);
      }, () => { if (reading === opening.current) setLoadFailed(true); });
      showModalDialog(dialog);
    } else if (!open && dialog.open) { opening.current++; dialog.close(); }
  }, [open]);

  const autoLockChanged = Boolean(choice) && choice !== current;
  const hotkeyChanged = hotkey !== null && (shortcut !== hotkey.shortcut || summonCompact !== hotkey.summonCompact);

  async function save() {
    if (!autoLockChanged && !hotkeyChanged) return;
    setSaving(true); setError("");
    const messages: string[] = [];
    try {
      if (autoLockChanged) {
        const minutes = choice === OFF ? null : Number(choice) as Exclude<AutoLockMinutes, null>;
        await setAutoLock({ autoLockMinutes: minutes });
        await fetchVaultStatus().catch(() => undefined);
        messages.push(minutes === null ? "時間による自動ロックを無効にしました" : `${autoLockText(minutes)}操作がないとロックします`);
      }
      if (hotkeyChanged) {
        const saved = await setGlobalShortcut({ shortcut, summonCompact });
        setHotkey(saved);
        messages.push(saved.shortcut ? `${saved.shortcut}で呼び出せます` : "呼び出しキーをなしにしました");
      }
      dialogRef.current?.close();
      onSaved(messages.join("。"));
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "設定を保存できませんでした";
      // The auto-lock time may already be saved when the key is not; say which part took effect.
      setError(messages.length ? `自動ロックの時間は保存しました（${messages[0]}）。呼び出しキーは保存できませんでした: ${message}` : message);
    } finally { setSaving(false); }
  }

  function record(event: ReactKeyboardEvent) {
    if (!recording) return;
    // Tab leaves the button as usual, and a key typed into the input method is not a shortcut.
    if (event.key === "Tab" && !event.ctrlKey && !event.altKey) { setRecording(false); setKeyProblem(""); return; }
    if (event.nativeEvent.isComposing || event.keyCode === 229) return;
    // The other keys are read here only: the dialog's own Escape and the app's shortcuts never see them.
    event.preventDefault(); event.stopPropagation();
    if (event.key === "Escape" && !event.ctrlKey && !event.altKey && !event.shiftKey) { setRecording(false); setKeyProblem(""); return; }
    if (event.repeat) return;
    const named = globalShortcutOf(event.nativeEvent);
    if (!named) return;
    if ("problem" in named) { setKeyProblem(named.problem); return; }
    setShortcut(named.text); setKeyProblem(""); setRecording(false);
  }

  return <dialog className="vault-tool-dialog settings-dialog" ref={dialogRef} aria-labelledby="settings-title" onClose={onClose}
    onCancel={(event) => { if (saving || recording) event.preventDefault(); }}>
    <header className="vault-tool-heading">
      <h2 id="settings-title">設定</h2>
      <button className="icon-btn" type="button" aria-label="閉じる" data-tooltip="閉じる" disabled={saving} onClick={() => dialogRef.current?.close()}><CloseIcon /></button>
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
      <div className="settings-field settings-field--section">
        <span className="settings-label" id="settings-hotkey-label">呼び出しキー</span>
        <div className="settings-shortcut">
          <button className={`shortcut-recorder ${recording ? "shortcut-recorder--recording" : ""}`} type="button"
            aria-labelledby="settings-hotkey-label settings-hotkey-value" aria-describedby="settings-hotkey-note" aria-pressed={recording}
            disabled={saving || hotkey === null} onClick={() => { setRecording(!recording); setKeyProblem(""); }}
            onKeyDown={record} onBlur={() => setRecording(false)}>
            <span id="settings-hotkey-value">{hotkey === null ? (loadFailed ? "読み込めませんでした" : "読み込み中…") : recording ? "キーを押してください（Escで中止）" : shortcut ?? "なし"}</span>
          </button>
          <button className="btn btn--small" type="button" disabled={saving || hotkey === null || shortcut === null} onClick={() => { setShortcut(null); setKeyProblem(""); }}>なしにする</button>
        </div>
      </div>
      <label className="settings-check">
        <input type="checkbox" checked={summonCompact} disabled={saving || hotkey === null} onChange={(event) => setSummonCompact(event.target.checked)} />
        呼び出したときはコンパクト表示で開く
      </label>
      <p className="vault-tool-note" id="settings-hotkey-note">
        ほかのアプリを使っているときも、このキーでCIPHER VAULTを手前に出して検索欄へ移ります。もう一度押すと元のアプリへ戻ります。ロック中はロック画面を出すだけで、コピーや表示はしません。
      </p>
      {keyProblem && <p className="form-error" role="alert">{keyProblem}</p>}
      {hotkey && hotkey.shortcut && !hotkey.registered && shortcut === hotkey.shortcut && <p className="settings-warning" role="alert">
        {hotkey.error ?? "呼び出しキーを登録できませんでした"}。別のキーを選んでください。
      </p>}
      {error && <p className="form-error" role="alert">{error}</p>}
      </div>
      <footer className="dialog-footer">
        <button className="btn" type="button" disabled={saving} onClick={() => dialogRef.current?.close()}>キャンセル</button>
        <button className="btn btn--primary" type="submit" disabled={saving || recording || (!autoLockChanged && !hotkeyChanged)}>{saving ? "保存しています…" : "保存"}</button>
      </footer>
    </form>
  </dialog>;
}
