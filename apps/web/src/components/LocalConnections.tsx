import { useEffect, useRef, useState, type FormEvent } from "react";
import type { LocalConnectionsState } from "@password-manager/shared/types";
import { approveLocalPairing, cancelLocalPairing, getLocalConnections, revokeLocalClient, saveLocalConnectionInfo, selectLocalPairingRequest, setLocalConnectionsEnabled } from "../lib/api";
import { CloseIcon } from "./Icons";

const date = (value: number) => new Date(value).toLocaleDateString("ja-JP");
const kindLabel = (kind: "agent" | "browser") => kind === "browser" ? "ブラウザ" : "エージェント";
const labels: Record<LocalConnectionsState["status"], string> = { disabled: "オフ", paused: "停止中", locked: "保管庫を開くと再開します", starting: "準備しています…", ready: "オン · ロックすると止まります", unavailable: "利用できません（登録は残っています）" };

export function LocalConnections({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null), alive = useRef(true), active = useRef(false), busyRef = useRef(false), reading = useRef(false), epoch = useRef(0);
  const latest = useRef<LocalConnectionsState | null>(null);
  const [state, setState] = useState<LocalConnectionsState | null>(null), [busy, setBusy] = useState(false), [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState(""), [message, setMessage] = useState("");
  const ready = state?.status === "ready", processing = busy || state?.status === "starting";
  function receive(value: LocalConnectionsState) { latest.current = value; setState(value); }
  useEffect(() => { alive.current = true; return () => { alive.current = false; active.current = false; epoch.current++; dialog.current?.close(); }; }, []);
  useEffect(() => {
    active.current = opened; epoch.current++; setConfirmed(false); setError(""); setMessage("");
    latest.current = null; setState(null);
    if (!opened) { dialog.current?.close(); return; }
    if (!dialog.current?.open) dialog.current?.showModal();
    const poll = async () => {
      if (reading.current || busyRef.current || !active.current) return;
      reading.current = true; const current = epoch.current;
      try { const value = await getLocalConnections(); if (alive.current && active.current && current === epoch.current) receive(value); }
      catch (cause) { if (alive.current && active.current && current === epoch.current) setError(cause instanceof Error ? cause.message : "接続の状態を確かめられません"); }
      finally { reading.current = false; }
    };
    void poll(); const timer = window.setInterval(() => { void poll(); }, 1000);
    return () => { active.current = false; window.clearInterval(timer); };
  }, [opened]);
  useEffect(() => { setConfirmed(false); }, [state?.review?.pendingId]);
  async function perform(action: () => Promise<LocalConnectionsState>, text = "") {
    if (busyRef.current) return; busyRef.current = true; setBusy(true); setError(""); setMessage(""); setConfirmed(false); const current = ++epoch.current;
    try { const result = await action(); if (alive.current && active.current && current === epoch.current) { receive(result); setMessage(text); } }
    catch (cause) { if (alive.current && active.current && current === epoch.current) setError(cause instanceof Error ? cause.message : "完了できませんでした"); }
    finally { busyRef.current = false; if (alive.current && current === epoch.current) setBusy(false); }
  }
  async function close() {
    if (processing) return;
    const pending = latest.current?.review?.pendingId;
    if (pending) { try { await cancelLocalPairing(pending); } catch { /* Lock/expiry also invalidates review. */ } }
    if (alive.current) onClose();
  }
  function submit(event: FormEvent) {
    event.preventDefault(); const review = state?.review;
    if (!review || !confirmed || !ready || processing) return;
    void perform(() => approveLocalPairing({ pendingId: review.pendingId, expectedRevision: review.revision, fingerprint256: review.fingerprint256, confirmation: "MATCHED_FINGERPRINT" }), "登録しました。「接続情報を保存」で書き出したファイルを、接続元で読み込んでください。");
  }
  async function save(clientId: string) {
    if (busyRef.current) return;
    let saved = false;
    await perform(async () => { saved = await saveLocalConnectionInfo(clientId); return getLocalConnections(); });
    if (saved && alive.current && active.current) setMessage("接続情報を保存しました。接続元で読み込んでください。");
  }
  const clients = state?.clients.filter(client => client.state === "active") ?? [], history = state?.clients.filter(client => client.state !== "active") ?? [];
  return <dialog ref={dialog} className="vault-tool-dialog local-connections-dialog" aria-labelledby="connections-title" onCancel={event => { event.preventDefault(); void close(); }}>
    <div className="vault-tool-heading"><h2 id="connections-title">外部アプリの接続</h2><button type="button" className="icon-btn" aria-label="閉じる" disabled={processing} onClick={() => { void close(); }}><CloseIcon /></button></div>
    <div className="dialog-body">
      {state ? <>
        <div className={`connections-status ${ready ? "connections-ready" : ""}`}>
          <div><span id="connections-switch-label">接続を受け付ける</span><strong>{labels[state.status]}</strong></div>
          <button type="button" className="switch" role="switch" aria-checked={state.enabled} aria-labelledby="connections-switch-label" disabled={processing}
            onClick={() => { void perform(() => setLocalConnectionsEnabled(!state.enabled, state.revision)); }} />
        </div>
        {state.review && <form className="connections-review" onSubmit={submit}>
          <h3>新しい接続：{state.review.displayName}</h3>
          <p className="connections-facts">{kindLabel(state.review.kind)} · {date(state.review.registrationExpiresAt)} まで有効 · {new Date(state.review.expiresAt).toLocaleTimeString("ja-JP", { hour: "2-digit", minute: "2-digit" })} までに確認</p>
          <p className="dialog-section-label">確認コード</p>
          <code className="connections-fingerprint">{state.review.fingerprint256.slice(0, 47)}<br />{state.review.fingerprint256.slice(48)}</code>
          <label className="maintenance-acknowledgement"><input type="checkbox" checked={confirmed} disabled={processing || !ready} onChange={event => setConfirmed(event.target.checked)} />接続元に表示されたコードと同じです</label>
          <p className="vault-tool-note">登録しても、パスワードは渡しません。</p>
          <div className="reset-actions"><button type="button" className="btn" disabled={processing} onClick={() => { void perform(() => cancelLocalPairing(state.review!.pendingId)); }}>キャンセル</button><button type="submit" className="btn btn--primary connections-approve" disabled={processing || !ready || !confirmed}>登録</button></div>
        </form>}
        <p className="dialog-section-label">登録済み</p>
        {clients.length === 0 && <p className="vault-tool-note">まだ登録されていません</p>}
        {clients.map(client => <div className="connections-row" key={client.clientId}>
          <div><div>{client.displayName}</div><p>{kindLabel(client.kind)} · {date(client.expiresAt)} まで</p></div>
          <div className="connections-row-actions">
            <button type="button" className="text-btn connections-export" disabled={processing} onClick={() => { void save(client.clientId); }}>接続情報を保存</button>
            <button type="button" className="text-btn text-btn--danger connections-revoke" disabled={processing} onClick={() => { void perform(() => revokeLocalClient(client.clientId, state.revision), "解除しました。"); }}>解除</button>
          </div>
        </div>)}
      </> : <p className="vault-tool-note" role="status">確かめています…</p>}
      {error && <p role="alert" className="form-error">{error}</p>}{message && <p role="status" className="vault-tool-message">{message}</p>}
    </div>
    {state && <div className="dialog-footer dialog-footer--split">
      {history.length > 0 ? <details className="connections-history"><summary>期限切れ・解除済み {history.length}件</summary>{history.map(client => <p key={client.clientId}>{client.displayName} · {client.state === "revoked" ? "解除済み" : "期限切れ"}</p>)}</details> : <span />}
      <button type="button" className="btn connections-select" disabled={!ready || processing} onClick={() => { void perform(selectLocalPairingRequest); }}>接続を追加…</button>
    </div>}
  </dialog>;
}
