import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/vault": "http://localhost:3001",
      "/entries": "http://localhost:3001",
      "/password": "http://localhost:3001"
    }
  }
});
