// Tauri's IPC answers on its own custom protocol. Windows WebView2 reaches it as http://ipc.localhost.
export const TAURI_IPC_SOURCES = "ipc: http://ipc.localhost";

// The screen's CSP, written into index.html by the Vite build. Tauri applies its own CSP from
// apps/desktop/tauri.conf.json on top of the meta tag, so both must stay the same text;
// tests/renderer-policy.test.mjs compares them.
export function rendererContentSecurityPolicy() {
  return [
    "default-src 'none'", "base-uri 'none'", "object-src 'none'", "frame-src 'none'", "form-action 'none'",
    "script-src 'self'", "style-src 'self' 'unsafe-inline'", "style-src-elem 'self'",
    "style-src-attr 'unsafe-inline'", "img-src 'self' data: blob:", "font-src 'self'",
    "worker-src 'none'", `connect-src ${TAURI_IPC_SOURCES}`
  ].join("; ");
}
