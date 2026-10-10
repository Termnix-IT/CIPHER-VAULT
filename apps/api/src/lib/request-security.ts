import { randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";
import { HttpError } from "./errors.js";

// This token protects browser requests; it is not authentication for remote API access.
const csrfToken = randomBytes(32).toString("hex");
const safeMethods = new Set(["GET", "HEAD", "OPTIONS"]);

function webOrigins() {
  return (process.env.PASSWORD_MANAGER_WEB_ORIGIN ?? "").split(",").filter(Boolean).map((value) => new URL(value.trim()).origin);
}

export function assertTrustedRequest(request: IncomingMessage) {
  const host = request.headers.host;
  const port = request.socket.localPort;
  const configuredHost = process.env.PASSWORD_MANAGER_API_HOST ?? "127.0.0.1";
  const hosts = new Set(["localhost", "127.0.0.1", "[::1]", configuredHost].map((name) => {
    const hostname = name.includes(":") && !name.startsWith("[") ? `[${name}]` : name;
    return `${hostname}${port === 80 ? "" : `:${port}`}`;
  }));
  // Never derive the allowlist from Host: that would allow DNS rebinding.
  if (!host || !hosts.has(host.toLowerCase())) throw new HttpError(403, "接続先が許可されていません");
  const origins = new Set([`http://${host}`, ...webOrigins()]);
  const origin = request.headers.origin;
  if ((origin !== undefined && !origins.has(origin)) || request.headers["sec-fetch-site"] === "cross-site") {
    throw new HttpError(403, "外部ページからのリクエストは許可されていません");
  }
  if (safeMethods.has(request.method ?? "GET")) return;

  if (request.headers["content-type"]?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    throw new HttpError(415, "Content-Typeにはapplication/jsonを指定してください");
  }
  const supplied = request.headers["x-cipher-vault-csrf"];
  if (typeof supplied !== "string" || !/^[a-f0-9]{64}$/.test(supplied) ||
      !timingSafeEqual(Buffer.from(supplied), Buffer.from(csrfToken))) {
    throw new HttpError(403, "リクエストの確認トークンが正しくありません");
  }
}

export function getCsrfToken() {
  return csrfToken;
}
