import type { IncomingMessage, ServerResponse } from "node:http";
import type {
  PasswordGenerationOptions,
  PasswordEntryUpsertPayload,
  VaultSetupPayload,
  VaultUnlockPayload
} from "@password-manager/shared/types";
import { HttpError } from "../lib/errors.js";
import { readJsonBody } from "../lib/json.js";
import { serveAppShell, tryServeStaticAsset } from "../lib/static.js";
import { generatePassword } from "../services/password-service.js";
import { createEntry, deleteEntry, getEntryById, listEntries, updateEntry } from "../services/entry-service.js";
import { getVaultStatus, lockVault, setupVault, unlockVault } from "../services/vault-service.js";

function sendJson(response: ServerResponse, statusCode: number, payload: unknown) {
  response.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(payload));
}

export async function router(request: IncomingMessage, response: ServerResponse) {
  const method = request.method ?? "GET";
  const url = request.url ?? "/";
  const entryMatch = url.match(/^\/entries\/([^/]+)$/);
  const pathname = new URL(url, "http://localhost").pathname;

  try {
    if (method === "GET" && url === "/health") {
      sendJson(response, 200, { ok: true });
      return;
    }

    if (method === "GET" && url === "/vault/status") {
      sendJson(response, 200, getVaultStatus());
      return;
    }

    if (method === "POST" && url === "/vault/setup") {
      const payload = await readJsonBody<VaultSetupPayload>(request);
      sendJson(response, 201, setupVault(payload));
      return;
    }

    if (method === "POST" && url === "/vault/unlock") {
      const payload = await readJsonBody<VaultUnlockPayload>(request);
      sendJson(response, 200, unlockVault(payload));
      return;
    }

    if (method === "POST" && url === "/vault/lock") {
      sendJson(response, 200, lockVault());
      return;
    }

    if (method === "GET" && url === "/entries") {
      sendJson(response, 200, listEntries());
      return;
    }

    if (method === "POST" && url === "/entries") {
      const payload = await readJsonBody<PasswordEntryUpsertPayload>(request);
      sendJson(response, 201, createEntry(payload));
      return;
    }

    if (method === "POST" && url === "/password/generate") {
      const payload = await readJsonBody<PasswordGenerationOptions>(request);
      sendJson(response, 200, generatePassword(payload));
      return;
    }

    if (entryMatch && method === "GET") {
      sendJson(response, 200, getEntryById(entryMatch[1]));
      return;
    }

    if (entryMatch && method === "PUT") {
      const payload = await readJsonBody<PasswordEntryUpsertPayload>(request);
      sendJson(response, 200, updateEntry(entryMatch[1], payload));
      return;
    }

    if (entryMatch && method === "DELETE") {
      sendJson(response, 200, deleteEntry(entryMatch[1]));
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
      sendJson(response, error.statusCode, { error: error.message });
      return;
    }

    sendJson(response, 500, { error: "サーバー内部でエラーが発生しました" });
  }
}
