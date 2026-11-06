import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { rendererContentSecurityPolicy } from "@password-manager/shared";

const apiProxy = { target: "http://127.0.0.1:3001", changeOrigin: true };

// `--mode tauri` builds the screen for the Rust app into its own directory, because its CSP must
// allow Tauri's IPC while the Web and Electron builds keep theirs.
export default defineConfig(({ mode }) => ({
  base: "./",
  // Preserve Vite 5 output targets independently of the build-tool upgrade.
  build: { target: ["chrome87", "edge88", "firefox78", "safari14"], outDir: mode === "tauri" ? "dist-tauri" : "dist" },
  plugins: [react(), {
    name: "cipher-vault-csp",
    transformIndexHtml: {
      order: "pre",
      handler(html, context) {
        const origin = context.server?.resolvedUrls?.local[0] ?? "http://localhost:5173";
        return html.replace("__CIPHER_VAULT_CSP__", rendererContentSecurityPolicy(context.server ? "development" : mode === "tauri" ? "tauri" : "web", origin));
      }
    }
  }],
  server: {
    port: 5173,
    proxy: {
      "/vault": apiProxy,
      "/entries": apiProxy,
      "/password": apiProxy
    }
  }
}));
