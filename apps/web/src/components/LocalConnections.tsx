import { useEffect, useRef, useState, type FormEvent } from "react";
import type { LocalConnectionsState } from "@password-manager/shared/types";
import { approveLocalPairing, cancelLocalPairing, getLocalConnections, revokeLocalClient, saveLocalConnectionInfo, selectLocalPairingRequest, setLocalConnectionsEnabled } from "../lib/api";

const date = (value: number) => new Date(value).toLocaleDateString("ja-JP");
const labels: Record<LocalConnectionsState["status"], string> = { disabled: "ローカル接続は無効です", paused: "ローカル接続は停止中です", locked: "接続の再開待ちです", starting: "接続を準備しています", ready: "ローカル接続は有効です", unavailable: "接続情報を利用できません" };

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
      catch (cause) { if (alive.current && active.current && current === epoch.current) setError(cause instanceof Error ? cause.message : "接続情報を確認できません"); }
      finally { reading.current = false; }
    };
    void poll(); const timer = window.setInterval(() => { void poll(); }, 1000);
    return () => { active.current = false; window.clearInterval(timer); };
  }, [opened]);
  useEffect(() => { setConfirmed(false); }, [state?.review?.pendingId]);
  async function perform(action: () => Promise<LocalConnectionsState>, text = "") {
    if (busyRef.current) return; busyRef.current = true; setBusy(true); setError(""); setMessage(""); setConfirmed(false); const current = ++epoch.current;
    try { const result = await action(); if (alive.current && active.current && current === epoch.current) { receive(result); setMessage(text); } }
    catch (cause) { if (alive.current && active.current && current === epoch.current) setError(cause instanceof Error ? cause.message : "処理を完了できません"); }
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
    void perform(() => approveLocalPairing({ pendingId: review.pendingId, expectedRevision: review.revision, fingerprint256: review.fingerprint256, confirmation: "MATCHED_FINGERPRINT" }), "接続元を登録しました。接続情報を保存し、接続元で読み込んでください。");
  }
  async function save(clientId: string) {
    if (busyRef.current) return;
    let saved = false;
    await perform(async () => { saved = await saveLocalConnectionInfo(clientId); return getLocalConnections(); });
    if (saved && alive.current && active.current) setMessage("接続情報を保存しました。接続元で読み込んでください。");
  }
  const clients = state?.clients.filter(client => client.state === "active") ?? [], history = state?.clients.filter(client => client.state !== "active") ?? [];
  return <dialog ref={dialog} className="vault-tool-dialog local-connections-dialog" aria-labelledby="connections-title" onCancel={event => { event.preventDefault(); void close(); }}>
    <div className="vault-tool-heading"><div><p className="vault-tool-eyebrow">LOCAL CONNECTIONS</p><h2 id="connections-title">接続の管理</h2></div><button type="button" className="cipher-btn" disabled={processing} onClick={() => { void close(); }}>閉じる</button></div>
    {state ? <>
      <div className={`connections-status ${ready ? "connections-ready" : ""}`}><div><strong>{labels[state.status]}</strong><p>{ready ? "保管庫をロックすると、接続も停止します。" : state.status === "unavailable" ? "接続資格と登録情報を保持したまま停止しています。" : "接続資格は、この端末のOS保護機能を使って保存します。"}</p></div>
        <button type="button" className={state.enabled ? "cipher-btn" : "cipher-btn cipher-btn--primary"} disabled={processing} onClick={() => { void perform(() => setLocalConnectionsEnabled(!state.enabled, state.revision)); }}>{processing ? "準備中…" : state.enabled ? "接続を停止" : state.status === "disabled" ? "ローカル接続を有効にする" : "接続を再開"}</button>
      </div>
      <section className="connections-section"><div className="vault-tool-heading"><h3>登録済みの接続元</h3><button type="button" className="cipher-btn connections-select" disabled={!ready || processing} onClick={() => { void perform(selectLocalPairingRequest); }}>接続リクエストを選択</button></div>
        {clients.length === 0 && <p className="vault-tool-note">接続元はまだ登録されていません。</p>}
        {clients.map(client => <div className="connections-row" key={client.clientId}><div><strong>{client.displayName}</strong><p>{client.kind === "browser" ? "ブラウザ" : "エージェント"} · 有効期限 {date(client.expiresAt)}</p><p>接続元の登録のみ。保管庫の操作は許可していません。</p><button type="button" className="connections-export" disabled={processing} onClick={() => { void save(client.clientId); }}>接続情報を保存</button></div>
          <button type="button" className="cipher-btn connections-revoke" disabled={processing} onClick={() => { void perform(() => revokeLocalClient(client.clientId, state.revision), "登録を取り消しました。"); }}>登録を取り消す</button></div>)}
        {history.length > 0 && <details className="connections-history"><summary>期限切れ・取り消し済み（{history.length}件）</summary>{history.map(client => <p key={client.clientId}>{client.displayName} · {client.state === "revoked" ? "取り消し済み" : "期限切れ"}</p>)}</details>}
      </section>
      {state.review && <section className="connections-section"><h3>新しい接続元を確認</h3><p className="vault-tool-note">接続元にも表示されている照合値と比較してください。</p><form className="connections-review" onSubmit={submit}><div className="connections-facts"><span>表示名 <strong>{state.review.displayName}</strong></span><span>種別 {state.review.kind === "browser" ? "ブラウザ" : "エージェント"}</span><span>有効期限 {date(state.review.registrationExpiresAt)}</span></div>
        <p className="vault-tool-note">照合値（SHA-256）</p><code className="connections-fingerprint">{state.review.fingerprint256.slice(0, 47)}<br />{state.review.fingerprint256.slice(48)}</code><label className="maintenance-acknowledgement"><input type="checkbox" checked={confirmed} disabled={processing || !ready} onChange={event => setConfirmed(event.target.checked)} />接続元に表示された照合値と一致しています</label>
        <p className="vault-tool-note">登録だけでは、パスワードの取得やサービスへの操作は許可されません。</p><p className="vault-tool-note">確認期限 {new Date(state.review.expiresAt).toLocaleTimeString("ja-JP")}</p>
        <div className="maintenance-actions"><button type="button" className="cipher-btn" disabled={processing} onClick={() => { void perform(() => cancelLocalPairing(state.review!.pendingId)); }}>キャンセル</button><button type="submit" className="cipher-btn cipher-btn--primary connections-approve" disabled={processing || !ready || !confirmed}>この接続元を登録</button></div></form></section>}
    </> : <p className="vault-tool-note" role="status">接続情報を確認しています…</p>}
    {error && <p role="alert" className="form-error">{error}</p>}{message && <p role="status" className="vault-tool-message">{message}</p>}
  </dialog>;
}
