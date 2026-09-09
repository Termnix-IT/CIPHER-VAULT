import type { FormEvent } from "react";
import { useEffect, useRef, useState } from "react";
import { BinaryRain } from "../components/BinaryRain";
import { useGlitchDecode } from "../lib/useGlitchDecode";

type LockScreenProps = {
  isConfigured: boolean;
  isSubmitting: boolean;
  errorMessage: string;
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
  isConfigured,
  isSubmitting,
  errorMessage,
  onSubmit,
  onReset,
}: LockScreenProps) {
  const [masterPassword, setMasterPassword] = useState("");
  const [resetStep, setResetStep] = useState<ResetStep>("idle");
  const [hasAcknowledgedDataLoss, setHasAcknowledgedDataLoss] = useState(false);
  const [resetCode, setResetCode] = useState("");
  const [resetCodeInput, setResetCodeInput] = useState("");
  const [hasAttemptedReset, setHasAttemptedReset] = useState(false);
  const resetCodeInputRef = useRef<HTMLInputElement>(null);
  const decodedTitle = useGlitchDecode("CIPHER VAULT", 900); // タイトルは英語維持

  useEffect(() => {
    if (resetStep === "confirmation") {
      resetCodeInputRef.current?.focus();
    }
  }, [resetStep]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await onSubmit(masterPassword);
  }

  function openResetWarning() {
    setMasterPassword("");
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

  const isResetFlow = resetStep !== "idle";

  return (
    <div className="cipher-auth-shell">
      <BinaryRain />

      {/* Corner system markers */}
      <div className="corner-marker corner-marker--tl" aria-hidden="true">
        <span>SYS: 0xA4E2F1</span>
        <span>ENC: AES-256-GCM</span>
      </div>
      <div className="corner-marker corner-marker--tr" aria-hidden="true">
        <span>KDF: SCRYPT</span>
        <span>HMAC: SHA-256</span>
      </div>
      <div className="corner-marker corner-marker--bl" aria-hidden="true">
        <span>PROTOCOL: LOCAL</span>
        <span>BUILD: 1.0.0</span>
      </div>
      <div className="corner-marker corner-marker--br" aria-hidden="true">
        <span>CLEARANCE: REQUIRED</span>
        <span>AUTH: MASTER KEY</span>
      </div>

      <section className="cipher-panel">
        <div className="panel-scan-line" aria-hidden="true" />

        <h1 className="glitch-title">{decodedTitle}</h1>

        <p className="system-status">
          {">"} システム状態:{" "}
          <span className={isResetFlow ? "status-value status-value--danger" : "status-value"}>
            {isResetFlow ? "リセット確認中" : isConfigured ? "ロック中" : "未設定"}
          </span>
        </p>

        <div className="system-specs" aria-hidden="true">
          <span>CIPHER: AES-256-GCM</span>
          <span className="spec-sep">·</span>
          <span>KDF: SCRYPT</span>
          <span className="spec-sep">·</span>
          <span>STORAGE: LOCAL</span>
        </div>

        {resetStep === "idle" ? (
          <>
            <form className="cipher-form" onSubmit={handleSubmit}>
              <label className="terminal-label">
                マスターキー
                <input
                  className="terminal-input"
                  type="password"
                  placeholder={
                    isConfigured
                      ? "パスフレーズを入力_"
                      : "パスフレーズを作成（12文字以上）_"
                  }
                  value={masterPassword}
                  onChange={(e) => setMasterPassword(e.target.value)}
                  minLength={12}
                  autoComplete={isConfigured ? "current-password" : "new-password"}
                  autoFocus
                />
              </label>

              {errorMessage ? (
                <p className="error-line">{"! ERR: "}{errorMessage}</p>
              ) : null}

              <button
                className="cipher-btn cipher-btn--primary cipher-btn--block"
                type="submit"
                disabled={isSubmitting}
              >
                {isSubmitting
                  ? "[ 認証中... ]"
                  : isConfigured
                  ? "[ 保管庫を解錠 ]"
                  : "[ 保管庫を初期化 ]"}
              </button>
            </form>

            {isConfigured ? (
              <button className="reset-entry-link" type="button" onClick={openResetWarning}>
                マスターキーを忘れた場合
              </button>
            ) : (
              <p className="lock-hint">
                新しい保管庫を作成します。マスターキーは復元できません。
              </p>
            )}
          </>
        ) : null}

        {resetStep === "warning" ? (
          <section className="reset-flow" aria-labelledby="reset-warning-title">
            <p className="reset-flow-step">RESET PROTOCOL // STEP 1 OF 2</p>
            <h2 id="reset-warning-title" className="reset-flow-title">保管庫を完全にリセットしますか？</h2>
            <div className="reset-warning" role="alert">
              <p>保存済みのパスワード、メモ、ログイン情報はすべて削除されます。</p>
              <p>削除したデータは復元できません。新しい保管庫として再設定が必要です。</p>
            </div>
            <label className="reset-acknowledgement">
              <input
                type="checkbox"
                checked={hasAcknowledgedDataLoss}
                onChange={(event) => setHasAcknowledgedDataLoss(event.target.checked)}
              />
              <span>すべての保存データが失われることを理解しました</span>
            </label>
            <div className="reset-actions">
              <button className="cipher-btn" type="button" onClick={cancelReset}>[ キャンセル ]</button>
              <button
                className="cipher-btn cipher-btn--danger"
                type="button"
                disabled={!hasAcknowledgedDataLoss}
                onClick={openResetConfirmation}
              >
                [ 最終確認へ ]
              </button>
            </div>
          </section>
        ) : null}

        {resetStep === "confirmation" ? (
          <form className="reset-flow" onSubmit={handleReset}>
            <p className="reset-flow-step">RESET PROTOCOL // STEP 2 OF 2</p>
            <h2 className="reset-flow-title">確認コードを入力してください</h2>
            <p className="reset-code-label">表示されたコードを手入力してください</p>
            <output className="reset-code" aria-label={`確認コード ${resetCode}`}>{resetCode}</output>
            <label className="terminal-label">
              確認コード
              <input
                ref={resetCodeInputRef}
                className="terminal-input reset-code-input"
                type="text"
                value={resetCodeInput}
                onChange={(event) => {
                  const nextValue = event.target.value.toUpperCase().replace(/[^A-Z0-9]/g, "");
                  setResetCodeInput(nextValue.slice(0, RESET_CODE_LENGTH));
                }}
                onPaste={(event) => event.preventDefault()}
                maxLength={RESET_CODE_LENGTH}
                autoComplete="off"
                spellCheck={false}
                aria-describedby="reset-code-help"
              />
            </label>
            <p id="reset-code-help" className="reset-code-help">コピー＆ペーストは使用できません。</p>

            {hasAttemptedReset && errorMessage ? (
              <p className="error-line" aria-live="polite">{"! ERR: "}{errorMessage}</p>
            ) : null}

            <div className="reset-actions">
              <button className="cipher-btn" type="button" onClick={() => setResetStep("warning")} disabled={isSubmitting}>
                [ 戻る ]
              </button>
              <button
                className="cipher-btn cipher-btn--danger"
                type="submit"
                disabled={isSubmitting || resetCodeInput !== resetCode}
              >
                {isSubmitting ? "[ リセット中... ]" : "[ すべて削除してリセット ]"}
              </button>
            </div>
          </form>
        ) : null}
      </section>
    </div>
  );
}
