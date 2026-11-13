import type { FormEvent } from "react";
import { useEffect, useState } from "react";
import { LockIcon } from "../components/Icons";

type LockScreenProps = {
  onDirtyChange: (dirty: boolean) => void;
  isConfigured: boolean;
  /** A vault of the legacy format is in the data folder, which this version cannot open. */
  legacyVaultFound?: boolean;
  isSubmitting: boolean;
  errorMessage: string;
  notice?: string;
  onSubmit: (masterPassword: string) => Promise<void>;
};

export function LockScreen({
  onDirtyChange,
  isConfigured,
  legacyVaultFound = false,
  isSubmitting,
  errorMessage,
  notice = "",
  onSubmit,
}: LockScreenProps) {
  const [masterPassword, setMasterPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [mismatch, setMismatch] = useState(false);
  useEffect(() => { onDirtyChange(Boolean(masterPassword || confirmPassword)); }, [masterPassword, confirmPassword, onDirtyChange]);
  useEffect(() => () => onDirtyChange(false), [onDirtyChange]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!isConfigured && masterPassword !== confirmPassword) {
      setMismatch(true);
      return;
    }
    await onSubmit(masterPassword);
  }

  const message = mismatch ? "もう一度入力した内容が一致しません" : errorMessage;

  return (
    <div className="lock-shell">
      <section className="lock-panel">
        <div className="lock-mark"><LockIcon /></div>
        <h1 className="lock-title">CIPHER VAULT</h1>

        {!isConfigured && legacyVaultFound ? <div className="lock-legacy" role="note">
          <p>以前の形式の保管庫が見つかりました。この版では開けません。</p>
          <p>v1.0.1までの版でバックアップを書き出し、ここで新しい保管庫を作成してから、「ツール」の「バックアップ」で復元してください。以前の保管庫のファイルはそのまま残ります。</p>
        </div> : null}

        <form className="cipher-form" onSubmit={handleSubmit}>
          <input
            className="field-input"
            name="master"
            type="password"
            aria-label="マスターパスワード"
            placeholder={isConfigured ? "マスターパスワード" : "マスターパスワード（12文字以上）"}
            value={masterPassword}
            onChange={(e) => { setMasterPassword(e.target.value); setMismatch(false); }}
            minLength={isConfigured ? undefined : 12}
            autoComplete={isConfigured ? "current-password" : "new-password"}
            autoFocus
          />
          {!isConfigured ? (
            <input
              className="field-input"
              name="confirm"
              type="password"
              aria-label="マスターパスワードをもう一度入力"
              placeholder="もう一度入力"
              value={confirmPassword}
              onChange={(e) => { setConfirmPassword(e.target.value); setMismatch(false); }}
              minLength={12}
              autoComplete="new-password"
            />
          ) : null}

          {message ? <p className="lock-message lock-message--error" role="alert">{message}</p>
            : notice ? <p className="lock-message lock-message--notice" role="status">{notice}</p> : null}

          <button className="btn btn--primary btn--large btn--block" type="submit" disabled={isSubmitting}>
            {isSubmitting ? (isConfigured ? "開いています…" : "作成しています…") : isConfigured ? "開く" : "保管庫を作成"}
          </button>
        </form>

        {!isConfigured ? <p className="lock-hint">忘れると、保存した内容は取り出せなくなります。</p> : null}
      </section>
    </div>
  );
}
