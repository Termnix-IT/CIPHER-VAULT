import type { FormEvent } from "react";
import { useState } from "react";
import { BinaryRain } from "../components/BinaryRain";
import { useGlitchDecode } from "../lib/useGlitchDecode";

type LockScreenProps = {
  isConfigured: boolean;
  isSubmitting: boolean;
  errorMessage: string;
  onSubmit: (masterPassword: string) => Promise<void>;
};

export function LockScreen({
  isConfigured,
  isSubmitting,
  errorMessage,
  onSubmit,
}: LockScreenProps) {
  const [masterPassword, setMasterPassword] = useState("");
  const decodedTitle = useGlitchDecode("CIPHER VAULT", 900); // タイトルは英語維持

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await onSubmit(masterPassword);
  }

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
          <span className="status-value">
            {isConfigured ? "ロック中" : "未設定"}
          </span>
        </p>

        <div className="system-specs" aria-hidden="true">
          <span>CIPHER: AES-256-GCM</span>
          <span className="spec-sep">·</span>
          <span>KDF: SCRYPT</span>
          <span className="spec-sep">·</span>
          <span>STORAGE: LOCAL</span>
        </div>

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
              autoComplete="current-password"
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

        {!isConfigured && (
          <p className="lock-hint">
            新しい保管庫を作成します。マスターキーは復元できません。
          </p>
        )}
      </section>
    </div>
  );
}
