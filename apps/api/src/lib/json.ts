import type { IncomingMessage } from "node:http";
import { HttpError } from "./errors.js";
import { INPUT_LIMITS } from "./input-validation.js";

export async function readJsonBody(request: IncomingMessage, maxBytes: number = INPUT_LIMITS.requestBytes): Promise<unknown> {
  const declaredLength = request.headers["content-length"];
  if (declaredLength !== undefined && Number(declaredLength) > maxBytes) {
    request.resume();
    throw new HttpError(413, "リクエストの容量が上限を超えています");
  }
  const chunks: Buffer[] = [];
  let size = 0;

  // Keep the HTTP stream usable for a 413 response when a chunk crosses the limit.
  for await (const chunk of request.iterator({ destroyOnReturn: false })) {
    size += Buffer.byteLength(chunk);
    if (size > maxBytes) {
      request.resume();
      throw new HttpError(413, "リクエストの容量が上限を超えています");
    }
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  if (chunks.length === 0) {
    return {};
  }

  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)));
  } catch {
    throw new HttpError(400, "JSONの形式が正しくありません");
  }
}
