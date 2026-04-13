# CIPHER VAULT UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** パスワードマネージャーの全フロントエンドをターミナル/暗号解読テーマ「CIPHER VAULT」スタイルに全面リデザインする。

**Architecture:** 既存のReactコンポーネント構造・Props・API呼び出しは一切変更しない。変更はスタイル（CSS）とJSX構造・クラス名のみ。新規ファイルは `BinaryRain.tsx`（Canvasコンポーネント）と `useGlitchDecode.ts`（アニメーションhook）の2ファイルのみ。

**Tech Stack:** React 18, TypeScript, Vite, CSS (no CSS-in-JS), Google Fonts (Share Tech Mono + JetBrains Mono)

---

## File Map

| ファイル | 操作 | 内容 |
|---------|------|------|
| `apps/web/index.html` | 修正 | Google Fonts CDN追加 |
| `apps/web/src/styles.css` | 全面書き換え | 全CSS変数・コンポーネントスタイル |
| `apps/web/src/components/BinaryRain.tsx` | 新規作成 | Canvas バイナリ雨コンポーネント |
| `apps/web/src/lib/useGlitchDecode.ts` | 新規作成 | グリッチデコードアニメーションhook |
| `apps/web/src/pages/LockScreen.tsx` | 全面書き換え | 認証画面JSX再構築 |
| `apps/web/src/pages/VaultDashboard.tsx` | 全面書き換え | ダッシュボードJSX再構築 |
| `apps/web/src/App.tsx` | 一部修正 | ローディング状態のクラス名を新CSSに対応させる |

---

## Task 1: Google Fonts + 完全CSS書き換え

**Files:**
- Modify: `apps/web/index.html`
- Rewrite: `apps/web/src/styles.css`

- [ ] **Step 1: index.html にGoogle Fontsを追加する**

`apps/web/index.html` を以下の内容に置き換える:

```html
<!doctype html>
<html lang="ja">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>CIPHER VAULT</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=JetBrains+Mono:wght@400;500;700&display=swap"
      rel="stylesheet"
    />
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 2: styles.css を全面書き換えする**

`apps/web/src/styles.css` を以下の内容で完全に置き換える:

```css
/* =============================
   VARIABLES
   ============================= */
:root {
  --bg-void: #000000;
  --bg-surface: #080808;
  --bg-panel: #0d0d0d;
  --border: rgba(0, 255, 255, 0.15);
  --border-bright: rgba(0, 255, 255, 0.5);
  --text-primary: #e8f4f4;
  --text-dim: rgba(200, 230, 230, 0.5);
  --accent-cyan: #00ffff;
  --accent-hot: #00e5ff;
  --accent-danger: #ff0055;
  --font-mono: "Share Tech Mono", "Courier New", monospace;
  --font-body: "JetBrains Mono", "Courier New", monospace;
}

/* =============================
   GLOBAL RESET
   ============================= */
*,
*::before,
*::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

html,
body {
  min-height: 100%;
  background: var(--bg-void);
  color: var(--text-primary);
  font-family: var(--font-body);
  font-size: 14px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}

#root {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

/* Scanline overlay */
body::before {
  content: "";
  position: fixed;
  inset: 0;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0, 0, 0, 0.03) 2px,
    rgba(0, 0, 0, 0.03) 4px
  );
  pointer-events: none;
  z-index: 9999;
}

/* =============================
   APP SHELL
   ============================= */
.app-shell {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  overflow: hidden;
}

/* =============================
   SHARED BUTTON
   ============================= */
.cipher-btn {
  font-family: var(--font-mono);
  font-size: 0.82rem;
  letter-spacing: 0.08em;
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text-dim);
  padding: 10px 18px;
  cursor: pointer;
  transition:
    border-color 0.15s ease,
    color 0.15s ease,
    background 0.15s ease,
    box-shadow 0.15s ease;
  text-align: center;
  border-radius: 0;
  white-space: nowrap;
  flex-shrink: 0;
}

.cipher-btn:hover:not(:disabled) {
  border-color: var(--accent-cyan);
  color: var(--accent-cyan);
  background: rgba(0, 255, 255, 0.04);
  box-shadow: 0 0 10px rgba(0, 255, 255, 0.12);
}

.cipher-btn:focus-visible {
  outline: 1px solid var(--accent-cyan);
  outline-offset: 2px;
}

.cipher-btn:disabled {
  opacity: 0.35;
  cursor: wait;
}

.cipher-btn--primary {
  border-color: var(--border-bright);
  color: var(--accent-cyan);
}

.cipher-btn--primary:hover:not(:disabled) {
  background: rgba(0, 255, 255, 0.08);
  box-shadow: 0 0 18px rgba(0, 255, 255, 0.18);
}

.cipher-btn--danger {
  border-color: rgba(255, 0, 85, 0.35);
  color: rgba(255, 0, 85, 0.65);
}

.cipher-btn--danger:hover:not(:disabled) {
  border-color: var(--accent-danger);
  color: var(--accent-danger);
  background: rgba(255, 0, 85, 0.06);
  box-shadow: 0 0 12px rgba(255, 0, 85, 0.18);
}

/* =============================
   SHARED INPUT / TEXTAREA
   ============================= */
.terminal-input,
.form-input,
.form-textarea {
  background: transparent;
  border: none;
  border-bottom: 1px solid var(--border);
  color: var(--text-primary);
  font-family: var(--font-body);
  font-size: 0.88rem;
  padding: 8px 4px;
  outline: none;
  width: 100%;
  transition: border-color 0.15s ease;
  caret-color: var(--accent-cyan);
}

.terminal-input:focus,
.form-input:focus,
.form-textarea:focus {
  border-bottom-color: var(--accent-cyan);
}

.terminal-input::placeholder,
.form-input::placeholder,
.form-textarea::placeholder {
  color: rgba(0, 255, 255, 0.2);
}

.form-textarea {
  resize: vertical;
  min-height: 64px;
}

/* =============================
   LOCK SCREEN
   ============================= */
.cipher-auth-shell {
  position: relative;
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  min-height: 100vh;
}

.cipher-panel {
  position: relative;
  z-index: 1;
  width: 100%;
  max-width: 460px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  padding: 40px 36px;
  opacity: 0;
  animation: panel-appear 0.5s ease 0.3s forwards;
}

/* Corner decorations */
.cipher-panel::before,
.cipher-panel::after {
  content: "";
  position: absolute;
  width: 14px;
  height: 14px;
  border-color: var(--accent-cyan);
  border-style: solid;
  opacity: 0.8;
}

.cipher-panel::before {
  top: -2px;
  left: -2px;
  border-width: 2px 0 0 2px;
}

.cipher-panel::after {
  bottom: -2px;
  right: -2px;
  border-width: 0 2px 2px 0;
}

@keyframes panel-appear {
  0% {
    opacity: 0;
    clip-path: inset(0 100% 100% 0);
  }
  60% {
    opacity: 1;
    clip-path: inset(0 0% 40% 0);
  }
  100% {
    opacity: 1;
    clip-path: inset(0 0 0 0);
  }
}

.glitch-title {
  font-family: var(--font-mono);
  font-size: clamp(1.5rem, 4vw, 2rem);
  letter-spacing: 0.14em;
  color: var(--accent-cyan);
  text-shadow: 0 0 18px rgba(0, 255, 255, 0.45);
  margin-bottom: 20px;
  min-height: 1.2em;
}

.system-status {
  font-family: var(--font-body);
  font-size: 0.78rem;
  color: var(--text-dim);
  margin-bottom: 32px;
  letter-spacing: 0.04em;
}

.status-value {
  color: var(--accent-cyan);
}

.cipher-form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.terminal-label {
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-family: var(--font-mono);
  font-size: 0.72rem;
  letter-spacing: 0.12em;
  color: var(--text-dim);
  text-transform: uppercase;
}

.error-line {
  font-family: var(--font-body);
  font-size: 0.8rem;
  color: var(--accent-danger);
  letter-spacing: 0.02em;
}

/* =============================
   DASHBOARD — HEADER
   ============================= */
.cipher-header {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 12px 20px;
  border-bottom: 1px solid var(--border);
  background: rgba(0, 0, 0, 0.6);
  flex-shrink: 0;
  position: relative;
  z-index: 10;
}

.header-logo {
  font-family: var(--font-mono);
  font-size: 0.95rem;
  letter-spacing: 0.06em;
  flex-shrink: 0;
}

.header-logo-type {
  color: var(--accent-cyan);
  text-shadow: 0 0 12px rgba(0, 255, 255, 0.4);
}

.header-logo-sep {
  color: var(--text-dim);
}

.header-logo-name {
  color: var(--text-primary);
}

.header-status {
  display: flex;
  align-items: center;
  gap: 10px;
  font-family: var(--font-body);
  font-size: 0.75rem;
  color: var(--text-dim);
  letter-spacing: 0.04em;
  flex: 1;
  justify-content: center;
  flex-wrap: wrap;
}

.status-sep {
  color: var(--border-bright);
  opacity: 0.6;
}

.uptime-value {
  color: var(--accent-cyan);
  font-variant-numeric: tabular-nums;
}

.selected-label {
  color: var(--text-primary);
  max-width: 200px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* =============================
   DASHBOARD — BODY
   ============================= */
.cipher-dashboard {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.dashboard-body {
  flex: 1;
  display: grid;
  grid-template-columns: minmax(260px, 340px) 1fr;
  overflow: hidden;
}

/* =============================
   SIDEBAR
   ============================= */
.vault-sidebar {
  display: flex;
  flex-direction: column;
  border-right: 1px solid var(--border);
  overflow: hidden;
  background: var(--bg-surface);
}

.sidebar-head {
  padding: 14px 16px 12px;
  border-bottom: 1px solid rgba(0, 255, 255, 0.06);
  flex-shrink: 0;
}

.sidebar-eyebrow {
  font-family: var(--font-mono);
  font-size: 0.68rem;
  letter-spacing: 0.14em;
  color: var(--text-dim);
  text-transform: uppercase;
  margin-bottom: 10px;
}

.search-prompt {
  display: flex;
  align-items: center;
  gap: 6px;
  border-bottom: 1px solid var(--border);
  padding-bottom: 6px;
}

.search-prompt-char {
  color: var(--accent-cyan);
  font-family: var(--font-mono);
  font-size: 0.85rem;
  flex-shrink: 0;
}

.search-input {
  flex: 1;
  background: transparent;
  border: none;
  outline: none;
  color: var(--text-primary);
  font-family: var(--font-body);
  font-size: 0.85rem;
  caret-color: var(--accent-cyan);
}

.search-input::placeholder {
  color: rgba(0, 255, 255, 0.18);
}

.sidebar-actions {
  display: flex;
  gap: 8px;
  padding: 10px 16px;
  border-bottom: 1px solid rgba(0, 255, 255, 0.06);
  flex-shrink: 0;
}

.sidebar-actions .cipher-btn {
  flex: 1;
  font-size: 0.75rem;
  padding: 7px 10px;
}

/* Entry list */
.entry-list {
  flex: 1;
  overflow-y: auto;
  padding: 4px 0;
  scrollbar-width: thin;
  scrollbar-color: var(--border) transparent;
}

.entry-list::-webkit-scrollbar {
  width: 3px;
}

.entry-list::-webkit-scrollbar-thumb {
  background: var(--border);
}

.entry-row {
  display: flex;
  align-items: flex-start;
  gap: 6px;
  padding: 11px 16px;
  cursor: pointer;
  border-left: 2px solid transparent;
  transition:
    border-color 0.12s ease,
    background 0.12s ease;
  animation: entry-slide-in 0.25s ease both;
}

@keyframes entry-slide-in {
  from {
    opacity: 0;
    transform: translateX(-6px);
  }
  to {
    opacity: 1;
    transform: translateX(0);
  }
}

.entry-row:hover {
  background: rgba(0, 255, 255, 0.025);
}

.entry-row:focus-visible {
  outline: 1px solid var(--accent-cyan);
  outline-offset: -1px;
}

.entry-row--active {
  border-left-color: var(--accent-cyan);
  background: rgba(0, 255, 255, 0.04);
}

.entry-cursor {
  font-family: var(--font-mono);
  color: var(--accent-cyan);
  font-size: 0.82rem;
  line-height: 1.5;
  width: 10px;
  flex-shrink: 0;
  opacity: 0;
  transition: opacity 0.12s;
}

.entry-row--active .entry-cursor {
  opacity: 1;
}

.entry-info {
  flex: 1;
  min-width: 0;
}

.entry-name {
  font-family: var(--font-body);
  font-size: 0.86rem;
  font-weight: 500;
  color: var(--text-primary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.entry-login {
  font-size: 0.76rem;
  color: var(--text-dim);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  margin-top: 2px;
}

.entry-tags {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
  margin-top: 5px;
}

.tag-chip {
  font-family: var(--font-mono);
  font-size: 0.65rem;
  color: rgba(0, 255, 255, 0.55);
  border: 1px solid rgba(0, 255, 255, 0.18);
  padding: 1px 5px;
  letter-spacing: 0.04em;
}

.entry-date {
  font-size: 0.68rem;
  color: rgba(200, 230, 230, 0.28);
  flex-shrink: 0;
  white-space: nowrap;
  padding-top: 2px;
}

.empty-state-text {
  padding: 20px 16px;
  font-size: 0.8rem;
  color: var(--text-dim);
  font-family: var(--font-body);
}

/* =============================
   NEW ENTRY FORM (sidebar)
   ============================= */
.new-entry-form {
  border-top: 1px solid rgba(0, 255, 255, 0.08);
  background: rgba(0, 0, 0, 0.3);
  flex-shrink: 0;
  max-height: 55vh;
  overflow-y: auto;
  scrollbar-width: thin;
  scrollbar-color: var(--border) transparent;
}

.new-entry-form-inner {
  padding: 14px 16px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.form-section-title {
  font-family: var(--font-mono);
  font-size: 0.7rem;
  letter-spacing: 0.12em;
  color: var(--accent-cyan);
  text-transform: uppercase;
}

.form-field {
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.form-label {
  font-family: var(--font-mono);
  font-size: 0.68rem;
  letter-spacing: 0.1em;
  color: var(--text-dim);
  text-transform: uppercase;
}

.form-inline {
  display: flex;
  gap: 8px;
  align-items: flex-end;
}

.form-inline .form-input {
  flex: 1;
}

.form-inline .cipher-btn {
  font-size: 0.72rem;
  padding: 8px 10px;
  flex-shrink: 0;
}

.form-btn-row {
  display: flex;
  gap: 8px;
  padding-top: 4px;
}

.form-btn-row .cipher-btn {
  flex: 1;
  font-size: 0.75rem;
  padding: 9px 12px;
}

/* =============================
   VAULT DETAIL / INSPECTOR
   ============================= */
.vault-detail {
  display: flex;
  flex-direction: column;
  overflow: hidden;
  background: var(--bg-surface);
}

.inspector-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 14px 20px;
  border-bottom: 1px solid rgba(0, 255, 255, 0.06);
  flex-shrink: 0;
}

.inspector-eyebrow {
  font-family: var(--font-mono);
  font-size: 0.68rem;
  letter-spacing: 0.14em;
  color: var(--text-dim);
  text-transform: uppercase;
}

.inspector-quick-copy {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.inspector-body {
  flex: 1;
  overflow-y: auto;
  padding: 20px 20px;
  display: flex;
  flex-direction: column;
  gap: 20px;
  scrollbar-width: thin;
  scrollbar-color: var(--border) transparent;
}

/* Field list (read view) */
.inspector-field-list {
  display: flex;
  flex-direction: column;
}

.inspector-field {
  display: flex;
  align-items: baseline;
  gap: 14px;
  padding: 9px 0;
  border-bottom: 1px solid rgba(0, 255, 255, 0.04);
}

.inspector-key {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  letter-spacing: 0.08em;
  color: var(--text-dim);
  text-transform: uppercase;
  min-width: 96px;
  flex-shrink: 0;
}

.inspector-value {
  font-family: var(--font-body);
  font-size: 0.86rem;
  color: var(--text-primary);
  flex: 1;
  word-break: break-all;
}

.inspector-value--password {
  letter-spacing: 0.18em;
}

.inspector-value--muted {
  color: var(--text-dim);
  font-style: italic;
}

/* Copy button */
.copy-btn {
  font-family: var(--font-mono);
  font-size: 0.68rem;
  color: rgba(0, 255, 255, 0.45);
  border: 1px solid rgba(0, 255, 255, 0.18);
  background: transparent;
  padding: 2px 7px;
  cursor: pointer;
  letter-spacing: 0.06em;
  border-radius: 0;
  flex-shrink: 0;
  transition:
    color 0.12s ease,
    border-color 0.12s ease,
    box-shadow 0.12s ease;
}

.copy-btn:hover {
  color: var(--accent-cyan);
  border-color: rgba(0, 255, 255, 0.45);
  box-shadow: 0 0 8px rgba(0, 255, 255, 0.15);
}

.copy-btn--glitch {
  animation: glitch-flash 0.35s ease forwards;
}

@keyframes glitch-flash {
  0% {
    color: var(--accent-cyan);
    background: rgba(0, 255, 255, 0.18);
    transform: skewX(0deg);
    letter-spacing: 0.06em;
  }
  20% {
    transform: skewX(-5deg);
    letter-spacing: 0.14em;
  }
  40% {
    transform: skewX(5deg);
    letter-spacing: 0.02em;
  }
  70% {
    transform: skewX(-2deg);
  }
  100% {
    color: rgba(0, 255, 255, 0.45);
    background: transparent;
    transform: skewX(0deg);
    letter-spacing: 0.06em;
  }
}

/* Edit form */
.inspector-edit-form {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.inspector-form-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 14px;
}

.action-row {
  display: flex;
  gap: 8px;
  padding-top: 4px;
  flex-wrap: wrap;
}

.action-row .cipher-btn {
  flex: 1;
  min-width: 120px;
}

/* Empty state */
.inspector-empty {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 28px 0;
}

.inspector-empty-tag {
  font-family: var(--font-mono);
  font-size: 0.68rem;
  letter-spacing: 0.1em;
  color: rgba(0, 255, 255, 0.35);
  border: 1px solid rgba(0, 255, 255, 0.18);
  padding: 2px 8px;
  display: inline-block;
}

.inspector-empty h3 {
  font-family: var(--font-mono);
  font-size: 1rem;
  color: var(--text-dim);
  letter-spacing: 0.04em;
}

.inspector-empty p {
  font-size: 0.8rem;
  color: rgba(200, 230, 230, 0.32);
  max-width: 38ch;
  line-height: 1.7;
}

/* Status messages */
.status-msg {
  font-family: var(--font-body);
  font-size: 0.78rem;
  padding: 6px 0;
}

.status-msg--copy {
  color: var(--accent-cyan);
}

.status-msg--error {
  color: var(--accent-danger);
}

.loading-text {
  font-family: var(--font-body);
  font-size: 0.8rem;
  color: var(--text-dim);
}

/* =============================
   RESPONSIVE
   ============================= */
@media (max-width: 860px) {
  .dashboard-body {
    grid-template-columns: 1fr;
    grid-template-rows: auto 1fr;
  }

  .vault-sidebar {
    border-right: none;
    border-bottom: 1px solid var(--border);
    max-height: 45vh;
  }

  .header-status {
    display: none;
  }
}

/* =============================
   ACCESSIBILITY
   ============================= */
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    animation-delay: 0ms !important;
    transition-duration: 0.01ms !important;
  }

  canvas {
    display: none !important;
  }

  .cipher-panel {
    opacity: 1 !important;
    clip-path: none !important;
  }
}
```

- [ ] **Step 3: TypeScript ビルドが通ることを確認する（CSS変更のみなので通るはず）**

プロジェクトルートで実行:
```bash
npm run build:web
```

Expected: エラーなしで `apps/web/dist/` に出力される。

- [ ] **Step 4: App.tsx のローディング状態を新クラスに更新する**

`apps/web/src/App.tsx` の初期ローディング表示部分（`vaultStatus === null` の分岐）を以下に変更する:

変更前:
```tsx
return (
  <main className="app-shell">
    <section className="panel auth-panel">
      <p className="muted">保管庫の状態を読み込んでいます...</p>
    </section>
  </main>
);
```

変更後:
```tsx
return (
  <main className="app-shell">
    <div className="cipher-auth-shell">
      <p className="loading-text">&gt; initializing vault...</p>
    </div>
  </main>
);
```

- [ ] **Step 5: コミット**

```bash
git add apps/web/index.html apps/web/src/styles.css apps/web/src/App.tsx
git commit -m "style: rewrite CSS with CIPHER VAULT dark terminal theme"
```

---

## Task 2: BinaryRain Canvas コンポーネント作成

**Files:**
- Create: `apps/web/src/components/BinaryRain.tsx`

- [ ] **Step 1: ファイルを作成する**

`apps/web/src/components/BinaryRain.tsx` を新規作成:

```tsx
import { useEffect, useRef } from "react";

export function BinaryRain() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const fontSize = 13;
    let drops: number[] = [];

    function resize() {
      if (!canvas || !ctx) return;
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      const columns = Math.floor(canvas.width / fontSize);
      drops = Array.from({ length: columns }, () => Math.random() * -50);
    }

    resize();
    window.addEventListener("resize", resize);

    let animId: number;

    function draw() {
      if (!canvas || !ctx) return;

      ctx.fillStyle = "rgba(0, 0, 0, 0.06)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.fillStyle = "rgba(0, 255, 255, 0.045)";
      ctx.font = `${fontSize}px "JetBrains Mono", monospace`;

      for (let i = 0; i < drops.length; i++) {
        const char = Math.random() > 0.5 ? "1" : "0";
        ctx.fillText(char, i * fontSize, drops[i] * fontSize);

        if (drops[i] * fontSize > canvas.height && Math.random() > 0.97) {
          drops[i] = 0;
        }
        drops[i] += 0.5;
      }

      animId = requestAnimationFrame(draw);
    }

    draw();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("resize", resize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        width: "100%",
        height: "100%",
        pointerEvents: "none",
        zIndex: 0,
      }}
    />
  );
}
```

- [ ] **Step 2: ビルドが通ることを確認する**

```bash
npm run build:web
```

Expected: エラーなし。

- [ ] **Step 3: コミット**

```bash
git add apps/web/src/components/BinaryRain.tsx
git commit -m "feat: add BinaryRain canvas component for cipher aesthetic"
```

---

## Task 3: useGlitchDecode Hook 作成

**Files:**
- Create: `apps/web/src/lib/useGlitchDecode.ts`

- [ ] **Step 1: hookファイルを作成する**

`apps/web/src/lib/useGlitchDecode.ts` を新規作成:

```ts
import { useEffect, useState } from "react";

const GLITCH_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*!?/\\|[]{}";

function randomChar(): string {
  return GLITCH_CHARS[Math.floor(Math.random() * GLITCH_CHARS.length)];
}

function randomStr(length: number): string {
  return Array.from({ length }, () => randomChar()).join("");
}

/**
 * グリッチデコードアニメーション。
 * delayMs後にtarget文字列へ向かってランダム文字から徐々にデコードされる。
 */
export function useGlitchDecode(target: string, delayMs = 900): string {
  const [display, setDisplay] = useState(() => randomStr(target.length));

  useEffect(() => {
    setDisplay(randomStr(target.length));

    const startTimeout = setTimeout(() => {
      const totalFrames = 28;
      let frame = 0;

      const interval = setInterval(() => {
        frame++;
        const progress = frame / totalFrames;
        const revealedCount = Math.floor(progress * target.length);

        setDisplay(
          target
            .split("")
            .map((char, i) => {
              if (char === " ") return " ";
              if (i < revealedCount) return char;
              return randomChar();
            })
            .join("")
        );

        if (frame >= totalFrames) {
          clearInterval(interval);
          setDisplay(target);
        }
      }, 40);

      return () => clearInterval(interval);
    }, delayMs);

    return () => clearTimeout(startTimeout);
  }, [target, delayMs]);

  return display;
}
```

- [ ] **Step 2: ビルドが通ることを確認する**

```bash
npm run build:web
```

Expected: エラーなし。

- [ ] **Step 3: コミット**

```bash
git add apps/web/src/lib/useGlitchDecode.ts
git commit -m "feat: add useGlitchDecode hook for terminal title animation"
```

---

## Task 4: LockScreen 全面書き換え

**Files:**
- Rewrite: `apps/web/src/pages/LockScreen.tsx`

- [ ] **Step 1: LockScreen.tsx を以下の内容で書き換える**

```tsx
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
  const decodedTitle = useGlitchDecode("CIPHER VAULT", 900);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await onSubmit(masterPassword);
  }

  return (
    <div className="cipher-auth-shell">
      <BinaryRain />

      <section className="cipher-panel">
        <h1 className="glitch-title">{decodedTitle}</h1>

        <p className="system-status">
          {">"} SYSTEM STATUS:{" "}
          <span className="status-value">
            {isConfigured ? "LOCKED" : "UNINITIALIZED"}
          </span>
        </p>

        <form className="cipher-form" onSubmit={handleSubmit}>
          <label className="terminal-label">
            MASTER KEY
            <input
              className="terminal-input"
              type="password"
              placeholder={
                isConfigured
                  ? "enter passphrase_"
                  : "create passphrase (12+ chars)_"
              }
              value={masterPassword}
              onChange={(e) => setMasterPassword(e.target.value)}
              minLength={12}
              autoComplete="current-password"
            />
          </label>

          {errorMessage ? (
            <p className="error-line">{"! ERR: "}{errorMessage}</p>
          ) : null}

          <button
            className="cipher-btn cipher-btn--primary"
            type="submit"
            disabled={isSubmitting}
          >
            {isSubmitting
              ? "[ PROCESSING... ]"
              : isConfigured
              ? "[ DECRYPT VAULT ]"
              : "[ INITIALIZE VAULT ]"}
          </button>
        </form>
      </section>
    </div>
  );
}
```

- [ ] **Step 2: ビルドが通ることを確認する**

```bash
npm run build:web
```

Expected: TypeScript エラーなし。

- [ ] **Step 3: コミット**

```bash
git add apps/web/src/pages/LockScreen.tsx
git commit -m "feat: rewrite LockScreen with CIPHER VAULT terminal aesthetic"
```

---

## Task 5: VaultDashboard 全面書き換え

**Files:**
- Rewrite: `apps/web/src/pages/VaultDashboard.tsx`

- [ ] **Step 1: VaultDashboard.tsx を以下の内容で書き換える**

```tsx
import type { FormEvent } from "react";
import { useEffect, useRef, useState } from "react";
import type {
  PasswordEntry,
  PasswordEntrySummary,
  PasswordEntryUpsertPayload,
} from "../../../../packages/shared/src/types";

type VaultDashboardProps = {
  entries: PasswordEntrySummary[];
  isLoading: boolean;
  isCreating: boolean;
  isUpdating: boolean;
  isDeleting: boolean;
  isLoadingDetail: boolean;
  isGeneratingPassword: boolean;
  selectedEntry: PasswordEntry | null;
  errorMessage: string;
  copyMessage: string;
  onLock: () => Promise<void>;
  onRefresh: () => Promise<void>;
  onCreateEntry: (payload: PasswordEntryUpsertPayload) => Promise<void>;
  onSelectEntry: (id: string) => Promise<void>;
  onUpdateEntry: (id: string, payload: PasswordEntryUpsertPayload) => Promise<void>;
  onDeleteEntry: (id: string) => Promise<void>;
  onGeneratePassword: () => Promise<string>;
  onCopyToClipboard: (value: string, label: string) => Promise<void>;
};

function useUptime(): string {
  const startRef = useRef(Date.now());
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const id = setInterval(() => {
      setElapsed(Date.now() - startRef.current);
    }, 1000);
    return () => clearInterval(id);
  }, []);

  const totalSec = Math.floor(elapsed / 1000);
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

export function VaultDashboard({
  entries,
  isLoading,
  isCreating,
  isUpdating,
  isDeleting,
  isLoadingDetail,
  isGeneratingPassword,
  selectedEntry,
  errorMessage,
  copyMessage,
  onLock,
  onRefresh,
  onCreateEntry,
  onSelectEntry,
  onUpdateEntry,
  onDeleteEntry,
  onGeneratePassword,
  onCopyToClipboard,
}: VaultDashboardProps) {
  const uptime = useUptime();
  const [searchTerm, setSearchTerm] = useState("");
  const [isFormOpen, setIsFormOpen] = useState(false);

  // Create form state
  const [serviceName, setServiceName] = useState("");
  const [loginId, setLoginId] = useState("");
  const [password, setPassword] = useState("");
  const [url, setUrl] = useState("");
  const [notes, setNotes] = useState("");
  const [tagInput, setTagInput] = useState("");

  // Edit form state
  const [editServiceName, setEditServiceName] = useState("");
  const [editLoginId, setEditLoginId] = useState("");
  const [editPassword, setEditPassword] = useState("");
  const [editUrl, setEditUrl] = useState("");
  const [editNotes, setEditNotes] = useState("");
  const [editTagInput, setEditTagInput] = useState("");

  // Copy glitch state
  const [glitchField, setGlitchField] = useState<string | null>(null);

  useEffect(() => {
    if (!selectedEntry) {
      setEditServiceName("");
      setEditLoginId("");
      setEditPassword("");
      setEditUrl("");
      setEditNotes("");
      setEditTagInput("");
      return;
    }
    setEditServiceName(selectedEntry.serviceName);
    setEditLoginId(selectedEntry.loginId);
    setEditPassword(selectedEntry.password);
    setEditUrl(selectedEntry.url);
    setEditNotes(selectedEntry.notes);
    setEditTagInput(selectedEntry.tags.join(", "));
  }, [selectedEntry]);

  const normalized = searchTerm.trim().toLowerCase();
  const filteredEntries = !normalized
    ? entries
    : entries.filter(
        (entry) =>
          entry.serviceName.toLowerCase().includes(normalized) ||
          entry.loginId.toLowerCase().includes(normalized) ||
          entry.tags.some((tag) => tag.toLowerCase().includes(normalized))
      );

  async function handleCopyWithGlitch(value: string, label: string, field: string) {
    setGlitchField(field);
    await onCopyToClipboard(value, label);
    setTimeout(() => setGlitchField(null), 400);
  }

  async function handleSubmitCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await onCreateEntry({
      serviceName,
      loginId,
      password,
      url,
      notes,
      tags: tagInput.split(",").map((t) => t.trim()).filter(Boolean),
    });
    setServiceName("");
    setLoginId("");
    setPassword("");
    setUrl("");
    setNotes("");
    setTagInput("");
    setIsFormOpen(false);
  }

  async function handleSubmitUpdate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedEntry) return;
    await onUpdateEntry(selectedEntry.id, {
      serviceName: editServiceName,
      loginId: editLoginId,
      password: editPassword,
      url: editUrl,
      notes: editNotes,
      tags: editTagInput.split(",").map((t) => t.trim()).filter(Boolean),
    });
  }

  async function handleDeleteEntry() {
    if (!selectedEntry) return;
    await onDeleteEntry(selectedEntry.id);
    setEditServiceName("");
    setEditLoginId("");
    setEditPassword("");
    setEditUrl("");
    setEditNotes("");
    setEditTagInput("");
  }

  async function handleGenerateForCreate() {
    const next = await onGeneratePassword();
    setPassword(next);
  }

  async function handleGenerateForEdit() {
    const next = await onGeneratePassword();
    setEditPassword(next);
  }

  return (
    <div className="cipher-dashboard">
      {/* ── Header ── */}
      <header className="cipher-header">
        <span className="header-logo">
          <span className="header-logo-type">VAULT</span>
          <span className="header-logo-sep">://</span>
          <span className="header-logo-name">SECURE</span>
        </span>

        <div className="header-status">
          <span>ENTRIES: {entries.length}</span>
          <span className="status-sep">|</span>
          <span>
            UPTIME: <span className="uptime-value">{uptime}</span>
          </span>
          {selectedEntry ? (
            <>
              <span className="status-sep">|</span>
              <span>
                SEL:{" "}
                <span className="selected-label">{selectedEntry.serviceName}</span>
              </span>
            </>
          ) : null}
        </div>

        <div style={{ display: "flex", gap: "8px", flexShrink: 0 }}>
          <button
            className="cipher-btn"
            type="button"
            onClick={() => void onRefresh()}
          >
            [ REFRESH ]
          </button>
          <button
            className="cipher-btn cipher-btn--primary"
            type="button"
            onClick={() => void onLock()}
          >
            [ LOCK ]
          </button>
        </div>
      </header>

      {/* ── Body ── */}
      <div className="dashboard-body">
        {/* ── Sidebar ── */}
        <aside className="vault-sidebar">
          <div className="sidebar-head">
            <p className="sidebar-eyebrow">// ENTRIES</p>
            <div className="search-prompt">
              <span className="search-prompt-char">&gt;</span>
              <input
                className="search-input"
                type="search"
                placeholder="search services, IDs, tags_"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          </div>

          <div className="sidebar-actions">
            <button
              className="cipher-btn"
              type="button"
              onClick={() => setIsFormOpen((v) => !v)}
            >
              {isFormOpen ? "[ CANCEL ]" : "[+ NEW ENTRY ]"}
            </button>
          </div>

          {/* New entry form */}
          {isFormOpen ? (
            <div className="new-entry-form">
              <form className="new-entry-form-inner" onSubmit={handleSubmitCreate}>
                <p className="form-section-title">&gt;_ NEW ENTRY</p>

                <div className="form-field">
                  <span className="form-label">SERVICE</span>
                  <input
                    className="form-input"
                    value={serviceName}
                    onChange={(e) => setServiceName(e.target.value)}
                    required
                    placeholder="github.com_"
                  />
                </div>

                <div className="form-field">
                  <span className="form-label">LOGIN ID</span>
                  <input
                    className="form-input"
                    value={loginId}
                    onChange={(e) => setLoginId(e.target.value)}
                    required
                    placeholder="user@email.com_"
                  />
                </div>

                <div className="form-field">
                  <span className="form-label">PASSWORD</span>
                  <div className="form-inline">
                    <input
                      className="form-input"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      placeholder="••••••••••••_"
                    />
                    <button
                      className="cipher-btn"
                      type="button"
                      onClick={() => void handleGenerateForCreate()}
                    >
                      {isGeneratingPassword ? "[...]" : "[GEN]"}
                    </button>
                  </div>
                </div>

                <div className="form-field">
                  <span className="form-label">URL</span>
                  <input
                    className="form-input"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://_"
                  />
                </div>

                <div className="form-field">
                  <span className="form-label">TAGS</span>
                  <input
                    className="form-input"
                    value={tagInput}
                    onChange={(e) => setTagInput(e.target.value)}
                    placeholder="仕事, 金融, メール_"
                  />
                </div>

                <div className="form-field">
                  <span className="form-label">NOTES</span>
                  <textarea
                    className="form-textarea"
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    rows={3}
                    placeholder="_"
                  />
                </div>

                <div className="form-btn-row">
                  <button
                    className="cipher-btn cipher-btn--primary"
                    type="submit"
                    disabled={isCreating}
                  >
                    {isCreating ? "[ SAVING... ]" : "[ SAVE ENTRY ]"}
                  </button>
                </div>
              </form>
            </div>
          ) : null}

          {/* Entry list */}
          <div className="entry-list" role="list">
            {isLoading ? (
              <p className="loading-text" style={{ padding: "16px" }}>
                &gt; loading entries...
              </p>
            ) : null}

            {!isLoading && filteredEntries.length === 0 ? (
              <p className="empty-state-text">
                &gt; no entries found. add one above.
              </p>
            ) : null}

            {filteredEntries.map((entry, index) => (
              <article
                key={entry.id}
                className={`entry-row ${
                  selectedEntry?.id === entry.id ? "entry-row--active" : ""
                }`}
                style={{ animationDelay: `${index * 50}ms` }}
                role="button"
                tabIndex={0}
                onClick={() => void onSelectEntry(entry.id)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    void onSelectEntry(entry.id);
                  }
                }}
              >
                <span className="entry-cursor" aria-hidden="true">
                  &gt;
                </span>
                <div className="entry-info">
                  <p className="entry-name">{entry.serviceName}</p>
                  <p className="entry-login">{entry.loginId}</p>
                  {entry.tags.length > 0 ? (
                    <div className="entry-tags">
                      {entry.tags.map((tag) => (
                        <span key={tag} className="tag-chip">
                          {tag}
                        </span>
                      ))}
                    </div>
                  ) : null}
                </div>
                <span className="entry-date">
                  {new Date(entry.updatedAt).toLocaleDateString("ja-JP")}
                </span>
              </article>
            ))}
          </div>
        </aside>

        {/* ── Detail Panel ── */}
        <section className="vault-detail">
          <div className="inspector-header">
            <p className="inspector-eyebrow">// INSPECTOR</p>

            {selectedEntry ? (
              <div className="inspector-quick-copy">
                <button
                  className="cipher-btn"
                  type="button"
                  style={{ fontSize: "0.75rem", padding: "6px 12px" }}
                  onClick={() =>
                    void handleCopyWithGlitch(
                      selectedEntry.loginId,
                      "ログインID",
                      "loginId-quick"
                    )
                  }
                >
                  [ COPY LOGIN ]
                </button>
                <button
                  className="cipher-btn cipher-btn--primary"
                  type="button"
                  style={{ fontSize: "0.75rem", padding: "6px 12px" }}
                  onClick={() =>
                    void handleCopyWithGlitch(
                      selectedEntry.password,
                      "パスワード",
                      "password-quick"
                    )
                  }
                >
                  [ COPY PASS ]
                </button>
              </div>
            ) : null}
          </div>

          <div className="inspector-body">
            {/* Status messages */}
            {copyMessage ? (
              <p className="status-msg status-msg--copy">&gt; {copyMessage}</p>
            ) : null}
            {errorMessage ? (
              <p className="status-msg status-msg--error">
                ! ERR: {errorMessage}
              </p>
            ) : null}

            {isLoadingDetail ? (
              <p className="loading-text">&gt; loading entry...</p>
            ) : null}

            {/* Empty state */}
            {!isLoadingDetail && !selectedEntry ? (
              <div className="inspector-empty">
                <span className="inspector-empty-tag">AWAITING SELECTION</span>
                <h3>左一覧からエントリを選択</h3>
                <p>
                  サービス名・ログイン情報・メモ・タグ・コピー操作・編集フォームがここに表示されます。
                </p>
              </div>
            ) : null}

            {/* Entry detail */}
            {!isLoadingDetail && selectedEntry ? (
              <>
                {/* Read-only field list */}
                <div className="inspector-field-list">
                  <div className="inspector-field">
                    <span className="inspector-key">SERVICE</span>
                    <span className="inspector-value">
                      {selectedEntry.serviceName}
                    </span>
                  </div>

                  <div className="inspector-field">
                    <span className="inspector-key">LOGIN_ID</span>
                    <span className="inspector-value">{selectedEntry.loginId}</span>
                    <button
                      className={`copy-btn ${
                        glitchField === "loginId" ? "copy-btn--glitch" : ""
                      }`}
                      type="button"
                      onClick={() =>
                        void handleCopyWithGlitch(
                          selectedEntry.loginId,
                          "ログインID",
                          "loginId"
                        )
                      }
                    >
                      [COPY]
                    </button>
                  </div>

                  <div className="inspector-field">
                    <span className="inspector-key">PASSWORD</span>
                    <span className="inspector-value inspector-value--password">
                      {"•".repeat(Math.min(selectedEntry.password.length, 16))}
                    </span>
                    <button
                      className={`copy-btn ${
                        glitchField === "password" ? "copy-btn--glitch" : ""
                      }`}
                      type="button"
                      onClick={() =>
                        void handleCopyWithGlitch(
                          selectedEntry.password,
                          "パスワード",
                          "password"
                        )
                      }
                    >
                      [COPY]
                    </button>
                  </div>

                  {selectedEntry.url ? (
                    <div className="inspector-field">
                      <span className="inspector-key">URL</span>
                      <span className="inspector-value">{selectedEntry.url}</span>
                      <button
                        className={`copy-btn ${
                          glitchField === "url" ? "copy-btn--glitch" : ""
                        }`}
                        type="button"
                        onClick={() =>
                          void handleCopyWithGlitch(selectedEntry.url, "URL", "url")
                        }
                      >
                        [COPY]
                      </button>
                    </div>
                  ) : null}

                  {selectedEntry.tags.length > 0 ? (
                    <div className="inspector-field">
                      <span className="inspector-key">TAGS</span>
                      <div className="entry-tags" style={{ flex: 1 }}>
                        {selectedEntry.tags.map((tag) => (
                          <span key={tag} className="tag-chip">
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : null}

                  {selectedEntry.notes ? (
                    <div className="inspector-field" style={{ alignItems: "flex-start" }}>
                      <span className="inspector-key">NOTES</span>
                      <span
                        className="inspector-value"
                        style={{ whiteSpace: "pre-wrap" }}
                      >
                        {selectedEntry.notes}
                      </span>
                    </div>
                  ) : null}

                  <div className="inspector-field">
                    <span className="inspector-key">CREATED</span>
                    <span className="inspector-value inspector-value--muted">
                      {new Date(selectedEntry.createdAt).toLocaleDateString("ja-JP")}
                    </span>
                  </div>

                  <div className="inspector-field">
                    <span className="inspector-key">UPDATED</span>
                    <span className="inspector-value inspector-value--muted">
                      {new Date(selectedEntry.updatedAt).toLocaleDateString("ja-JP")}
                    </span>
                  </div>
                </div>

                {/* Edit form */}
                <form
                  className="inspector-edit-form"
                  onSubmit={handleSubmitUpdate}
                >
                  <p className="form-section-title">&gt;_ EDIT ENTRY</p>

                  <div className="inspector-form-grid">
                    <div className="form-field">
                      <span className="form-label">SERVICE</span>
                      <input
                        className="form-input"
                        value={editServiceName}
                        onChange={(e) => setEditServiceName(e.target.value)}
                        required
                      />
                    </div>

                    <div className="form-field">
                      <span className="form-label">LOGIN ID</span>
                      <input
                        className="form-input"
                        value={editLoginId}
                        onChange={(e) => setEditLoginId(e.target.value)}
                        required
                      />
                    </div>

                    <div className="form-field">
                      <span className="form-label">PASSWORD</span>
                      <div className="form-inline">
                        <input
                          className="form-input"
                          type="password"
                          value={editPassword}
                          onChange={(e) => setEditPassword(e.target.value)}
                          required
                        />
                        <button
                          className="cipher-btn"
                          type="button"
                          onClick={() => void handleGenerateForEdit()}
                        >
                          {isGeneratingPassword ? "[...]" : "[GEN]"}
                        </button>
                      </div>
                    </div>

                    <div className="form-field">
                      <span className="form-label">URL</span>
                      <input
                        className="form-input"
                        value={editUrl}
                        onChange={(e) => setEditUrl(e.target.value)}
                      />
                    </div>
                  </div>

                  <div className="form-field">
                    <span className="form-label">TAGS</span>
                    <input
                      className="form-input"
                      value={editTagInput}
                      onChange={(e) => setEditTagInput(e.target.value)}
                      placeholder="仕事, 金融, メール_"
                    />
                  </div>

                  <div className="form-field">
                    <span className="form-label">NOTES</span>
                    <textarea
                      className="form-textarea"
                      value={editNotes}
                      onChange={(e) => setEditNotes(e.target.value)}
                      rows={5}
                    />
                  </div>

                  <div className="action-row">
                    <button
                      className="cipher-btn cipher-btn--primary"
                      type="submit"
                      disabled={isUpdating}
                    >
                      {isUpdating ? "[ SAVING... ]" : "[ SAVE CHANGES ]"}
                    </button>
                    <button
                      className="cipher-btn cipher-btn--danger"
                      type="button"
                      disabled={isDeleting}
                      onClick={() => void handleDeleteEntry()}
                    >
                      {isDeleting ? "[ DELETING... ]" : "[ DELETE ]"}
                    </button>
                  </div>
                </form>
              </>
            ) : null}
          </div>
        </section>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: ビルドが通ることを確認する**

```bash
npm run build:web
```

Expected: TypeScript エラーなし、`apps/web/dist/` に出力される。

- [ ] **Step 3: コミット**

```bash
git add apps/web/src/pages/VaultDashboard.tsx
git commit -m "feat: rewrite VaultDashboard with CIPHER VAULT terminal aesthetic"
```

---

## Task 6: ビジュアル動作確認 + 最終調整

**Files:**
- 変更なし（確認のみ）

- [ ] **Step 1: 開発サーバーを起動する**

プロジェクトルートで実行:
```bash
npm run dev:web
```

ブラウザで `http://localhost:5173` を開く。

- [ ] **Step 2: LockScreen の確認リスト**

以下をすべて目視確認する:
- [ ] バイナリ雨（0/1）が背景で流れている
- [ ] `CIPHER VAULT` タイトルがランダム文字からデコードされるアニメーションが動作する
- [ ] パネルがleft-topから展開するように出現する
- [ ] SYSTEM STATUSが`LOCKED`または`UNINITIALIZED`で正しく表示される
- [ ] パスワード入力フィールドが下線スタイルで、フォーカスでシアンに光る
- [ ] `[ DECRYPT VAULT ]` / `[ INITIALIZE VAULT ]` ボタンがブラケットスタイルで表示される
- [ ] エラー時に `! ERR: ...` がマゼンタ/赤で表示される

- [ ] **Step 3: VaultDashboard の確認リスト**

ロック解除後に以下を確認:
- [ ] ヘッダーに `VAULT://SECURE` が表示される
- [ ] `UPTIME: 00:00:XX` がリアルタイムでカウントアップする
- [ ] エントリが一覧に流れ込むアニメーション（staggered）が動作する
- [ ] エントリ選択時に左端 `>` カーソルが出現し、シアン左ボーダーが光る
- [ ] インスペクターに `SERVICE:`, `LOGIN_ID:`, `PASSWORD:` がターミナル出力形式で表示される
- [ ] `[COPY]` ボタンでグリッチアニメーションが発生する
- [ ] `[+ NEW ENTRY ]` でフォームが展開・収納される
- [ ] `[ DELETE ]` ボタンがホバーで赤くグローする
- [ ] `[LOCK]`でロック画面に戻る
- [ ] スキャンライン（横縞）が全画面に薄く重なっている

- [ ] **Step 4: 最終ビルド確認**

```bash
npm run build:web
```

Expected: エラーなし、distディレクトリに成果物が生成される。

- [ ] **Step 5: 最終コミット**

```bash
git add -A
git commit -m "chore: CIPHER VAULT redesign complete - visual verification passed"
```
