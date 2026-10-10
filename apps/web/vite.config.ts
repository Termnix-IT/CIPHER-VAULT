import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const apiProxy = { target: "http://127.0.0.1:3001", changeOrigin: true };

export default defineConfig({
  base: "./",
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/vault": apiProxy,
      "/entries": apiProxy,
      "/password": apiProxy
    }
  }
});
