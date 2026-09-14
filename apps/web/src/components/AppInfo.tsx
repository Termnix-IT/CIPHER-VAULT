import { useEffect, useRef, useState } from "react";
import type { AppUpdateState } from "@password-manager/shared/types";

export function AppInfo({ hasUnsavedChanges, isSaving }: { hasUnsavedChanges: boolean; isSaving: boolean }) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const api = window.passwordManager;
  const [state, setState] = useState<AppUpdateState | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    if (!api) return;
    let active = true;
    let receivedEvent = false;
    const unsubscribe = api.onUpdateState((next) => { receivedEvent = true; setState(next); });
    void api.getUpdateState().then((next) => { if (active && !receivedEvent) setState(next); })
      .catch(() => { if (active) setError("アプリ情報を取得できませんでした。"); });
    return () => { active = false; unsubscribe(); };
  }, [api]);

  async function run(action: () => Promise<void>) {
    setError("");
    try { await action(); }
    catch { setError("操作に失敗しました。もう一度お試しください。"); }
  }
  const status = state?.status;
  const close = () => dialogRef.current?.close();
  return <>
    <button className="app-info-trigger" onClick={() => dialogRef.current?.showModal()}>アプリ情報</button>
    <dialog className="app-info-dialog" ref={dialogRef} aria-labelledby="app-info-title">
      <div className="app-info-heading">
        <img src="./icon.png" alt="" width="88" height="88" />
        <div><h2 id="app-info-title">CIPHER VAULT</h2><p>{state ? `バージョン ${state.currentVersion}` : "ローカルのパスワード保管庫"}</p></div>
        <button className="cipher-btn" aria-label="アプリ情報を閉じる" onClick={close}>閉じる</button>
      </div>
      <div className="app-info-update" aria-live="polite">
        <h3>ソフトウェアの更新</h3>
        <p>確認・ダウンロード・インストールは、操作したときだけ実行します。</p>
        {status === "checking" && <p>最新版を確認しています…</p>}
        {status === "current" && <p>お使いのバージョンは最新です。</p>}
        {state?.latestVersion && <p>更新バージョン：{state.latestVersion}</p>}
        {state?.releaseNotes && <details><summary>変更内容</summary><pre>{state.releaseNotes}</pre></details>}
        {status === "downloading" && <div><progress aria-label="ダウンロード進捗" max="100" value={state?.progress ?? 0} /><p>ダウンロード中… {Math.floor(state?.progress ?? 0)}%</p></div>}
        {status === "downloaded" && <p>更新の準備ができました。「あとで」を選ぶと、通常終了時にも適用されません。</p>}
        {status === "installing" && <p>保管庫をロックしました。インストーラーを起動しています…</p>}
        {(status === "unsupported" || !api) && <p>アプリ内更新は、Windows の setup 版で利用できます。</p>}
        {(error || state?.message) && <p className="form-error" role="alert">{error || state?.message}</p>}
        <div className="app-info-actions">
          {api && status && ["idle", "current", "error"].includes(status) && <button className="cipher-btn" onClick={() => void run(api.checkForUpdates)}>更新を確認</button>}
          {api && status === "available" && <button className="cipher-btn" onClick={() => void run(api.downloadUpdate)}>ダウンロード</button>}
          {api && status === "downloaded" && <>
            <button className="cipher-btn" disabled={isSaving} onClick={() => void run(async () => {
              if (await api.installUpdate(hasUnsavedChanges) === false) close();
            })}>再起動して更新</button>
            <button className="cipher-btn" onClick={close}>あとで</button>
          </>}
          {api && status === "unsupported" && <button className="cipher-btn" onClick={() => void run(api.openReleasePage)}>配布ページを開く</button>}
        </div>
        {isSaving && status === "downloaded" && <p>保存処理の完了後に更新できます。</p>}
        <p className="app-info-note">更新の確認時は GitHub に接続します。保管庫の内容は送信しません。</p>
      </div>
    </dialog>
  </>;
}
