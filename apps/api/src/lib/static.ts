import { createReadStream, existsSync, realpathSync, statSync } from "node:fs";
import path from "node:path";
import type { ServerResponse } from "node:http";

function resolveWebDistPath() {
  const overridePath = process.env.PASSWORD_MANAGER_WEB_DIST;

  if (overridePath && existsSync(overridePath)) {
    return path.resolve(overridePath);
  }

  const workspacePath = path.resolve(process.cwd(), "apps/web/dist");

  if (existsSync(workspacePath)) {
    return workspacePath;
  }

  return path.resolve(process.cwd(), "web");
}

function getContentType(filePath: string) {
  if (filePath.endsWith(".png")) return "image/png";
  if (filePath.endsWith(".ico")) return "image/x-icon";
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

  let realTarget: string;
  try {
    realTarget = realpathSync(targetPath);
    const relative = path.relative(realpathSync(webDistPath), realTarget);
    if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative) || !statSync(realTarget).isFile()) {
      return false;
    }
  } catch {
    return false;
  }

  response.writeHead(200, {
    "Content-Type": getContentType(realTarget)
  });
  const stream = createReadStream(realTarget);
  stream.on("error", () => response.destroy());
  response.on("close", () => stream.destroy());
  stream.pipe(response);
  return true;
}

export function serveAppShell(response: ServerResponse) {
  if (!tryServeStaticAsset("/index.html", response)) {
    response.writeHead(503, { "Content-Type": "application/json; charset=utf-8" });
    response.end(JSON.stringify({ error: "Webアセットがビルドされていません" }));
    return;
  }
}
