import { createReadStream, existsSync } from "node:fs";
import path from "node:path";
import type { ServerResponse } from "node:http";

function resolveWebDistPath() {
  const workspacePath = path.resolve(process.cwd(), "apps/web/dist");

  if (existsSync(workspacePath)) {
    return workspacePath;
  }

  return path.resolve(process.cwd(), "web");
}

function getContentType(filePath: string) {
  if (filePath.endsWith(".js")) {
    return "application/javascript; charset=utf-8";
  }

  if (filePath.endsWith(".css")) {
    return "text/css; charset=utf-8";
  }

  if (filePath.endsWith(".html")) {
    return "text/html; charset=utf-8";
  }

  if (filePath.endsWith(".json")) {
    return "application/json; charset=utf-8";
  }

  if (filePath.endsWith(".svg")) {
    return "image/svg+xml";
  }

  return "application/octet-stream";
}

export function tryServeStaticAsset(urlPath: string, response: ServerResponse) {
  const webDistPath = resolveWebDistPath();
  const normalizedPath = urlPath === "/" ? "/index.html" : urlPath;
  const targetPath = path.resolve(webDistPath, `.${normalizedPath}`);

  if (!targetPath.startsWith(webDistPath) || !existsSync(targetPath)) {
    return false;
  }

  response.writeHead(200, {
    "Content-Type": getContentType(targetPath)
  });
  createReadStream(targetPath).pipe(response);
  return true;
}

export function serveAppShell(response: ServerResponse) {
  const webDistPath = resolveWebDistPath();
  const indexPath = path.join(webDistPath, "index.html");

  if (!existsSync(indexPath)) {
    response.writeHead(503, { "Content-Type": "application/json; charset=utf-8" });
    response.end(JSON.stringify({ error: "Webアセットがビルドされていません" }));
    return;
  }

  response.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8"
  });
  createReadStream(indexPath).pipe(response);
}
