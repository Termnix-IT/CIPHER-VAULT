import type { IncomingMessage } from "node:http";
import { HttpError } from "./errors.js";

export async function readJsonBody<T>(request: IncomingMessage, maxBytes = 1024 * 1024): Promise<T> {
  const chunks: Buffer[] = [];
  let size = 0;

  for await (const chunk of request) {
    size += Buffer.byteLength(chunk);
    if (size > maxBytes) throw new HttpError(413, "リクエストの容量が上限を超えています");
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  if (chunks.length === 0) {
    return {} as T;
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf-8")) as T;
  } catch {
    throw new HttpError(400, "JSONの形式が正しくありません");
  }
}
