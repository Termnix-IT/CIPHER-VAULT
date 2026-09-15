import type { IncomingMessage } from "node:http";
import { HttpError } from "./errors.js";

export async function readJsonBody<T>(request: IncomingMessage): Promise<T> {
  const chunks: Buffer[] = [];

  for await (const chunk of request) {
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
