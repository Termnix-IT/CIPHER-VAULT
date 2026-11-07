import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { rendererContentSecurityPolicy } from "@password-manager/shared";

// Builds the screen the Tauri app embeds (apps/desktop/tauri.conf.json frontendDist).
export default defineConfig({
  base: "./",
  // Preserve Vite 5 output targets independently of the build-tool upgrade.
  build: { target: ["chrome87", "edge88", "firefox78", "safari14"], outDir: "dist-tauri" },
  plugins: [react(), {
    name: "cipher-vault-csp",
    transformIndexHtml: {
      order: "pre",
      handler(html) {
        return html.replace("__CIPHER_VAULT_CSP__", rendererContentSecurityPolicy());
      }
    }
  }]
});
