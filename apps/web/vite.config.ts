import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { rendererContentSecurityPolicy } from "@password-manager/shared";

const apiProxy = { target: "http://127.0.0.1:3001", changeOrigin: true };

export default defineConfig({
  base: "./",
  plugins: [react(), {
    name: "cipher-vault-csp",
    transformIndexHtml: {
      order: "pre",
      handler(html, context) {
        const origin = context.server?.resolvedUrls?.local[0] ?? "http://localhost:5173";
        return html.replace("__CIPHER_VAULT_CSP__", rendererContentSecurityPolicy(context.server ? "development" : "web", origin));
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
});
