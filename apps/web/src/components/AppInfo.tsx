import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { AppUpdateState } from "@password-manager/shared/types";
import { releaseNotesToText } from "../lib/release-notes";
import { CloseIcon } from "./Icons";

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
  const open = () => { if (!dialogRef.current?.open) dialogRef.current?.showModal(); };
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
      <div className="app-info-heading">
        <img src="./icon.png" alt="" width="64" height="64" />
        <div><h2 id="app-info-title">CIPHER VAULT</h2>{state && <p>バージョン {state.currentVersion}</p>}</div>
        <button className="icon-btn" type="button" aria-label="閉じる" onClick={close}><CloseIcon /></button>
      </div>
      <div className="app-info-update" aria-live="polite">
        {stateText && <p className="app-info-state">{stateText}</p>}
        {status === "downloading" && <><progress aria-label="ダウンロードの進み具合" max="100" value={state?.progress ?? 0} /><p className="form-notice">ダウンロード中 {Math.floor(state?.progress ?? 0)}%</p></>}
        {releaseNotes && <details><summary>変更内容</summary><pre>{releaseNotes}</pre></details>}
        {(error || state?.message) && <p className="form-error" role="alert">{error || state?.message}</p>}
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
        {isSaving && status === "downloaded" && <p className="form-notice">保存が終わると更新できます</p>}
        <p className="app-info-note">更新の確認ではGitHubに接続します。保管庫の中身は送りません。</p>
      </div>
    </dialog>
  </>;
}
