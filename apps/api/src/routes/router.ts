import type { IncomingMessage, ServerResponse } from "node:http";
import { HttpError } from "../lib/errors.js";
import { assertTrustedRequest, getCsrfToken } from "../lib/request-security.js";
import { exportBackup, restoreBackup } from "../services/backup-service.js";
import { auditVault } from "../services/audit-service.js";
import { readJsonBody } from "../lib/json.js";
import { INPUT_LIMITS, parseEmptyPayload } from "../lib/input-validation.js";
import { serveAppShell, tryServeStaticAsset } from "../lib/static.js";
import { generatePassword } from "../services/password-service.js";
import { createEntry, deleteEntry, getEntryById, listEntries, updateEntry } from "../services/entry-service.js";
import { getVaultStatus, lockVaultForSession, recordVaultActivity, resetVault, setupVault, unlockVault } from "../services/vault-service.js";
import { requireSessionId, vaultSession, withVaultSession } from "../services/vault-session.js";

function sendJson(response: ServerResponse, statusCode: number, payload: unknown) {
  response.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Cross-Origin-Resource-Policy": "same-origin" });
  response.end(JSON.stringify(payload));
}

export async function router(request: IncomingMessage, response: ServerResponse) {
  const method = request.method ?? "GET";
  try {
    assertTrustedRequest(request);
    let url: string;
    try {
      url = new URL(request.url ?? "/", "http://localhost").pathname;
    } catch {
      throw new HttpError(400, "URLの形式が正しくありません");
    }
    const entryMatch = url.match(/^\/entries\/([^/]+)$/);
    const pathname = url;
    const sessionId = request.headers["x-cipher-vault-session"];
    if (method === "GET" && url === "/vault/csrf") {
      sendJson(response, 200, { token: getCsrfToken() });
      return;
    }
    if (method === "POST" && url === "/vault/backup/export") {
      sendJson(response, 200, await withVaultSession(sessionId, async (session) => {
        const payload = await readJsonBody(request);
        vaultSession.requireUnlocked(session);
        return exportBackup(payload);
      }));
      return;
    }
    if (method === "POST" && url === "/vault/backup/restore") {
      sendJson(response, 200, await withVaultSession(sessionId, async (session) => {
        const payload = await readJsonBody(request, INPUT_LIMITS.restoreRequestBytes);
        vaultSession.requireUnlocked(session);
        return restoreBackup(payload);
      }));
      return;
    }
    if (method === "POST" && url === "/vault/audit") {
      sendJson(response, 200, await withVaultSession(sessionId, async (session) => {
        parseEmptyPayload(await readJsonBody(request));
        vaultSession.requireUnlocked(session);
        return auditVault();
      }));
      return;
    }
    if (method === "GET" && url === "/health") {
      sendJson(response, 200, { ok: true });
      return;
    }

    if (method === "GET" && url === "/vault/status") {
      sendJson(response, 200, getVaultStatus());
      return;
    }

    if (method === "POST" && url === "/vault/setup") {
      const intent = vaultSession.requireGeneration(sessionId);
      const payload = await readJsonBody(request);
      vaultSession.requireGeneration(intent);
      sendJson(response, 201, await setupVault(payload));
      return;
    }

    if (method === "POST" && url === "/vault/unlock") {
      const intent = vaultSession.requireGeneration(sessionId);
      const payload = await readJsonBody(request);
      vaultSession.requireGeneration(intent);
      sendJson(response, 200, await unlockVault(payload));
      return;
    }

    if (method === "POST" && url === "/vault/lock") {
      // A delayed lock from an old view must not lock a newly unlocked generation.
      const intent = vaultSession.requireGeneration(sessionId);
      parseEmptyPayload(await readJsonBody(request));
      sendJson(response, 200, lockVaultForSession(intent));
      return;
    }

    if (method === "POST" && url === "/vault/activity") {
      const session = vaultSession.requireUnlocked(requireSessionId(sessionId));
      parseEmptyPayload(await readJsonBody(request));
      sendJson(response, 200, recordVaultActivity(session));
      return;
    }

    if (method === "POST" && url === "/vault/reset") {
      const intent = vaultSession.requireGeneration(sessionId);
      const payload = await readJsonBody(request);
      vaultSession.requireGeneration(intent);
      sendJson(response, 200, resetVault(payload));
      return;
    }

    if (method === "GET" && url === "/entries") {
      sendJson(response, 200, await withVaultSession(sessionId, () => listEntries()));
      return;
    }

    if (method === "POST" && url === "/entries") {
      sendJson(response, 201, await withVaultSession(sessionId, async (session) => {
        const payload = await readJsonBody(request);
        vaultSession.requireUnlocked(session);
        return createEntry(payload);
      }));
      return;
    }

    if (method === "POST" && url === "/password/generate") {
      sendJson(response, 200, await withVaultSession(sessionId, async (session) => {
        const payload = await readJsonBody(request);
        vaultSession.requireUnlocked(session);
        return generatePassword(payload);
      }));
      return;
    }

    if (entryMatch && method === "GET") {
      sendJson(response, 200, await withVaultSession(sessionId, () => getEntryById(entryMatch[1])));
      return;
    }

    if (entryMatch && method === "PUT") {
      sendJson(response, 200, await withVaultSession(sessionId, async (session) => {
        const payload = await readJsonBody(request);
        vaultSession.requireUnlocked(session);
        return updateEntry(entryMatch[1], payload);
      }));
      return;
    }

    if (entryMatch && method === "DELETE") {
      sendJson(response, 200, await withVaultSession(sessionId, async (session) => {
        parseEmptyPayload(await readJsonBody(request));
        vaultSession.requireUnlocked(session);
        return deleteEntry(entryMatch[1]);
      }));
      return;
    }

    if (method === "GET" && pathname.startsWith("/assets/")) {
      if (tryServeStaticAsset(pathname, response)) {
        return;
      }
    }

    if (method === "GET" && (pathname === "/" || !pathname.startsWith("/vault") && !pathname.startsWith("/entries") && !pathname.startsWith("/password"))) {
      if (tryServeStaticAsset(pathname, response)) {
        return;
      }

      serveAppShell(response);
      return;
    }

    sendJson(response, 404, { error: "見つかりませんでした" });
  } catch (error) {
    if (error instanceof HttpError) {
      if (error.retryAfterSeconds !== undefined) response.setHeader("Retry-After", String(error.retryAfterSeconds));
      sendJson(response, error.statusCode, { error: error.message });
      return;
    }

    sendJson(response, 500, { error: "サーバー内部でエラーが発生しました" });
  }
}
