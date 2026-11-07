import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { AppUpdateState } from "@password-manager/shared/types";
import { releaseNotesToText } from "../lib/release-notes";
import { CloseIcon } from "./Icons";
import { showModalDialog } from "../lib/modal";

export function AppInfo({ hasUnsavedChanges, isSaving, renderTrigger, onClose }: {
  hasUnsavedChanges: boolean;
  isSaving: boolean;
  renderTrigger?: (open: () => void) => ReactNode;
  onClose?: () => void;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const api = window.passwordManager;
  const [state, setState] = useState<AppUpdateState | null>(null);
  const [error, setError] = useState("");
  const releaseNotes = useMemo(() => releaseNotesToText(state?.releaseNotes ?? ""), [state?.releaseNotes]);
  useEffect(() => {
    if (!api) return;
    let active = true;
    let receivedEvent = false;
    const unsubscribe = api.onUpdateState((next) => { receivedEvent = true; setState(next); });
    void api.getUpdateState().then((next) => { if (active && !receivedEvent) setState(next); })
      .catch(() => { if (active) setError("バージョン情報を取得できませんでした。"); });
    return () => { active = false; unsubscribe(); };
  }, [api]);

  async function run(action: () => Promise<void>) {
    setError("");
    try { await action(); }
    catch { setError("うまくいきませんでした。もう一度お試しください。"); }
  }
  const status = state?.status;
  const close = () => dialogRef.current?.close();
  const open = () => { if (!dialogRef.current?.open) { if (dialogRef.current) showModalDialog(dialogRef.current); } };
  const latest = state?.latestVersion && ["available", "downloading", "downloaded", "installing"].includes(status ?? "") ? `バージョン ${state.latestVersion} があります` : "";
  const stateText = status === "checking" ? "確認しています…"
    : status === "current" ? "最新のバージョンです"
    : status === "downloaded" ? "再起動すると更新されます"
    : status === "installing" ? "更新しています。終わると自動で再起動します"
    : status === "unsupported" || !api ? "このバージョンはアプリ内で更新できません"
    : latest;
  return <>
    {renderTrigger ? renderTrigger(open) : <button className="btn" onClick={open}>バージョンと更新</button>}
    <dialog className="app-info-dialog" ref={dialogRef} aria-labelledby="app-info-title" onClose={onClose}>
      <header className="vault-tool-heading">
        <h2 id="app-info-title">バージョンと更新</h2>
        <button className="icon-btn" type="button" aria-label="閉じる" onClick={close}><CloseIcon /></button>
      </header>
      <div className="dialog-body app-info-update" aria-live="polite">
        <dl>
          <div className="tool-row"><dt>アプリ</dt><dd>CIPHER VAULT</dd></div>
          {state && <div className="tool-row"><dt>バージョン</dt><dd className="mono">{state.currentVersion}</dd></div>}
          {stateText && <div className="tool-row"><dt>更新</dt><dd>{stateText}</dd></div>}
          {status === "downloading" && <div className="tool-row"><dt>ダウンロード</dt><dd className="app-info-progress">
            <progress aria-label="ダウンロードの進み具合" max="100" value={state?.progress ?? 0} /><span className="mono">{Math.floor(state?.progress ?? 0)}%</span>
          </dd></div>}
        </dl>
        {releaseNotes && <details><summary>変更内容</summary><pre>{releaseNotes}</pre></details>}
        {(error || state?.message) && <p className="form-error" role="alert">{error || state?.message}</p>}
        {isSaving && status === "downloaded" && <p className="vault-tool-note">保存が終わると更新できます</p>}
        <p className="vault-tool-note">更新の確認ではGitHubに接続します。保管庫の中身は送りません。</p>
      </div>
      <footer className="dialog-footer">
        <div className="app-info-actions">
          {api && status && ["idle", "current", "error"].includes(status) && <button className="btn" onClick={() => void run(api.checkForUpdates)}>更新を確認</button>}
          {api && status === "available" && <button className="btn btn--primary" onClick={() => void run(api.downloadUpdate)}>ダウンロード</button>}
          {api && status === "downloaded" && <>
            <button className="btn btn--primary" disabled={isSaving} onClick={() => void run(async () => {
              if (await api.installUpdate(hasUnsavedChanges) === false) close();
            })}>再起動して更新</button>
            <button className="btn" onClick={close}>あとで</button>
          </>}
          {api && status === "unsupported" && <button className="btn" onClick={() => void run(api.openReleasePage)}>ダウンロードページを開く</button>}
        </div>
      </footer>
    </dialog>
  </>;
}
