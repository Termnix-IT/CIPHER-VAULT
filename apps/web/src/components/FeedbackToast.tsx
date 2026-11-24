import type { CopyNotice } from "../pages/VaultDashboard";

/** The error or the copy notice at the bottom of the vault screen. A copy notice counts down until the copy is cleared. */
export function FeedbackToast({ errorMessage, copyNotice }: { errorMessage: string; copyNotice: CopyNotice | null }) {
  const feedback = errorMessage || copyNotice?.text;
  return <div className="toast-region">
    {feedback && <p key={errorMessage || copyNotice?.id} className={`toast ${errorMessage ? "toast--error" : "toast--copy"}`} role={errorMessage ? "alert" : "status"}>
      {!errorMessage && (copyNotice?.clearsInMs ?? 0) > 0 && <svg className="copy-ring" viewBox="0 0 16 16" aria-hidden="true" style={{ ["--clear-ms" as string]: `${copyNotice?.clearsInMs}ms` }}>
        <circle cx="8" cy="8" r="6" /><circle className="copy-ring-remaining" cx="8" cy="8" r="6" pathLength="100" />
      </svg>}
      {feedback}
    </p>}
  </div>;
}
