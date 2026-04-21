import { copyFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const distDirectory = path.resolve(__dirname, "../dist/apps/electron/src");
const preloadJsPath = path.join(distDirectory, "preload.js");
const preloadMjsPath = path.join(distDirectory, "preload.mjs");

if (!existsSync(preloadJsPath)) {
  throw new Error(`preload.js was not found: ${preloadJsPath}`);
}

copyFileSync(preloadJsPath, preloadMjsPath);
