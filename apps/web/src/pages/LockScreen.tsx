import type { FormEvent } from "react";
import { useEffect, useRef, useState } from "react";
import { LockIcon } from "../components/Icons";

type LockScreenProps = {
  onDirtyChange: (dirty: boolean) => void;
  isConfigured: boolean;
  allowReset?: boolean;
  isSubmitting: boolean;
  errorMessage: string;
  notice?: string;
  onSubmit: (masterPassword: string) => Promise<void>;
  onReset: () => Promise<void>;
};

type ResetStep = "idle" | "warning" | "confirmation";

const RESET_CODE_CHARACTERS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const RESET_CODE_LENGTH = 6;

function createResetConfirmationCode() {
  const values = new Uint32Array(RESET_CODE_LENGTH);
  window.crypto.getRandomValues(values);

  return Array.from(values, (value) => RESET_CODE_CHARACTERS[value % RESET_CODE_CHARACTERS.length]).join("");
}

export function LockScreen({
  onDirtyChange,
  isConfigured,
  allowReset = true,
  isSubmitting,
  errorMessage,
  notice = "",
  onSubmit,
  onReset,
}: LockScreenProps) {
  const [masterPassword, setMasterPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [mismatch, setMismatch] = useState(false);
  const [resetStep, setResetStep] = useState<ResetStep>("idle");
  const [hasAcknowledgedDataLoss, setHasAcknowledgedDataLoss] = useState(false);
  const [resetCode, setResetCode] = useState("");
  const [resetCodeInput, setResetCodeInput] = useState("");
  const [pasteBlocked, setPasteBlocked] = useState(false);
  const [hasAttemptedReset, setHasAttemptedReset] = useState(false);
  const resetCodeInputRef = useRef<HTMLInputElement>(null);
  useEffect(() => { onDirtyChange(Boolean(masterPassword || confirmPassword || resetCodeInput)); }, [masterPassword, confirmPassword, resetCodeInput, onDirtyChange]);
  useEffect(() => () => onDirtyChange(false), [onDirtyChange]);

  useEffect(() => {
    if (resetStep === "confirmation") {
      resetCodeInputRef.current?.focus();
    }
  }, [resetStep]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!isConfigured && masterPassword !== confirmPassword) {
      setMismatch(true);
      return;
    }
    await onSubmit(masterPassword);
  }

  function openResetWarning() {
    setMasterPassword("");
    setConfirmPassword("");
    setHasAcknowledgedDataLoss(false);
    setResetCode("");
    setResetCodeInput("");
    setHasAttemptedReset(false);
    setResetStep("warning");
  }

  function openResetConfirmation() {
    if (!hasAcknowledgedDataLoss) {
      return;
    }

    setResetCode(createResetConfirmationCode());
    setResetCodeInput("");
    setPasteBlocked(false);
    setHasAttemptedReset(false);
    setResetStep("confirmation");
  }

  function cancelReset() {
    setHasAcknowledgedDataLoss(false);
    setResetCode("");
    setResetCodeInput("");
    setHasAttemptedReset(false);
    setResetStep("idle");
  }

  async function handleReset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (resetCodeInput !== resetCode) {
      return;
    }

    setHasAttemptedReset(true);

    try {
      await onReset();
      cancelReset();
    } catch {
      // The parent displays the reset error while this confirmation step stays open.
    }
  }

  const message = mismatch ? "もう一度入力した内容が一致しません" : errorMessage;

  return (
    <div className="lock-shell">
      <section className="lock-panel">
        <div className="lock-mark"><LockIcon /></div>
        <h1 className="lock-title">CIPHER VAULT</h1>

        {resetStep === "idle" ? (
          <>
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

            {!isConfigured ? <p className="lock-hint">忘れると、保存した内容は取り出せなくなります。</p>
              : allowReset ? <button className="reset-entry-link" type="button" onClick={openResetWarning}>パスワードを忘れた場合</button> : null}
          </>
        ) : null}

        {resetStep === "warning" ? (
          <section className="reset-flow" aria-labelledby="reset-warning-title">
            <h2 id="reset-warning-title">保管庫をリセットしますか？</h2>
            <p role="alert">保存したパスワードやメモはすべて消え、元に戻せません。</p>
            <label className="reset-acknowledgement">
              <input
                type="checkbox"
                checked={hasAcknowledgedDataLoss}
                onChange={(event) => setHasAcknowledgedDataLoss(event.target.checked)}
              />
              <span>すべて消えることを理解しました</span>
            </label>
            <div className="reset-actions">
              <button className="btn" type="button" onClick={cancelReset}>キャンセル</button>
              <button className="btn btn--danger" type="button" disabled={!hasAcknowledgedDataLoss} onClick={openResetConfirmation}>次へ</button>
            </div>
          </section>
        ) : null}

        {resetStep === "confirmation" ? (
          <form className="reset-flow" onSubmit={handleReset}>
            <h2>下のコードを入力してください</h2>
            <output className="reset-code" aria-label={`確認コード ${resetCode}`}>{resetCode}</output>
            <input
              ref={resetCodeInputRef}
              className="field-input reset-code-input"
              type="text"
              aria-label="確認コード"
              value={resetCodeInput}
              onChange={(event) => {
                const nextValue = event.target.value.toUpperCase().replace(/[^A-Z0-9]/g, "");
                setResetCodeInput(nextValue.slice(0, RESET_CODE_LENGTH));
              }}
              onPaste={(event) => { event.preventDefault(); setPasteBlocked(true); }}
              maxLength={RESET_CODE_LENGTH}
              autoComplete="off"
              spellCheck={false}
            />
            {pasteBlocked ? <p role="status">貼り付けはできません。手で入力してください。</p> : null}

            {hasAttemptedReset && errorMessage ? (
              <p className="lock-message lock-message--error" aria-live="polite">{errorMessage}</p>
            ) : null}

            <div className="reset-actions">
              <button className="btn" type="button" onClick={() => setResetStep("warning")} disabled={isSubmitting}>戻る</button>
              <button className="btn btn--danger" type="submit" disabled={isSubmitting || resetCodeInput !== resetCode}>
                {isSubmitting ? "リセットしています…" : "すべて消してリセット"}
              </button>
            </div>
          </form>
        ) : null}
      </section>
    </div>
  );
}
