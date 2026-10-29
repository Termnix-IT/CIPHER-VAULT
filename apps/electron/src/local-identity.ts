import { spawn } from "node:child_process";
import { createPrivateKey } from "node:crypto";
import path from "node:path";
import { assertNativeHelperExecutable, nativeHelperEnvironment } from "./native-transport.js";
import type { LocalIdentity } from "./local-client-auth.js";
import { parseLocalPublicCertificate } from "./local-certificates.js";

export type LocalIdentityRole = "host" | "client";
export type IssuedLocalIdentity = LocalIdentity & Readonly<{ role: LocalIdentityRole; expiresAt: number; dispose(): void }>;
export class LocalIdentityError extends Error {
  readonly code = "LOCAL_IDENTITY_UNAVAILABLE";
  constructor() { super("ローカル接続資格を発行できません"); this.name = "LocalIdentityError"; }
}
const begin = Buffer.from("-----BEGIN PRIVATE KEY-----\n"), end = Buffer.from("\n-----END PRIVATE KEY-----");
let generating = false;

function parse(payload: Buffer, processId: number, role: LocalIdentityRole): IssuedLocalIdentity {
  if (payload.length < 4) throw new LocalIdentityError();
  const size = payload.readUInt32BE();
  if (size < 2 || size > 512 || payload.length < 4 + size) throw new LocalIdentityError();
  const frame = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload.subarray(4, 4 + size)));
  if (!frame || typeof frame !== "object" || Array.isArray(frame) ||
      Object.keys(frame).sort().join(",") !== "certificateBytes,event,privateKeyBytes,processId,protocol,role" ||
      frame.protocol !== 1 || frame.event !== "identity" || frame.processId !== processId || frame.role !== role ||
      !Number.isInteger(frame.certificateBytes) || frame.certificateBytes < 128 || frame.certificateBytes > 4096 ||
      !Number.isInteger(frame.privateKeyBytes) || frame.privateKeyBytes < 128 || frame.privateKeyBytes > 2048 ||
      payload.length !== 4 + size + frame.certificateBytes + frame.privateKeyBytes) throw new LocalIdentityError();
  const parsed = parseLocalPublicCertificate(payload.subarray(4 + size, 4 + size + frame.certificateBytes));
  const privatePem = payload.subarray(4 + size + frame.certificateBytes);
  return material(parsed.certificate, privatePem, role, true);
}
function material(publicPem: Buffer, privatePem: Buffer, role: LocalIdentityRole, fresh: boolean): IssuedLocalIdentity {
  if (!Buffer.isBuffer(publicPem) || publicPem.length > 4096 || !Buffer.isBuffer(privatePem) || privatePem.length < 128 || privatePem.length > 2048) throw new LocalIdentityError();
  if (!privatePem.subarray(0, begin.length).equals(begin) || !privatePem.subarray(-end.length).equals(end) ||
      privatePem.subarray(begin.length, -end.length).some(value => !(value >= 65 && value <= 90) && !(value >= 97 && value <= 122) &&
        !(value >= 48 && value <= 57) && ![43, 47, 61, 10].includes(value))) throw new LocalIdentityError();
  const parsed = parseLocalPublicCertificate(publicPem), certificate = parsed.leaf, issuer = parsed.issuer;
  const key = createPrivateKey(privatePem), now = Date.now(), from = Date.parse(certificate.validFrom), until = Date.parse(certificate.validTo);
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1" || !certificate.checkPrivateKey(key) || certificate.ca ||
      !issuer || !/^CN=cipher-vault-issuer-[0-9a-f-]{36}$/.test(issuer.subject) || issuer.publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1" ||
      issuer.keyUsage?.join(",") !== (role === "host" ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2") || !Number.isFinite(from) || !Number.isFinite(until) ||
      from > now || (fresh && from < now - 5 * 60000) || until <= now || until - from > ((role === "host" ? 365 : 90) * 86400000 + 60000) ||
      certificate.keyUsage?.join(",") !== (role === "host" ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2") ||
      (role === "host" ? certificate.subject !== "CN=cipher-vault.local" || certificate.subjectAltName !== "DNS:cipher-vault.local" :
        certificate.subject !== "CN=cipher-vault-client" || certificate.subjectAltName !== undefined)) throw new LocalIdentityError();
  const privateKey = Buffer.from(privatePem);
  return Object.freeze({ certificate: parsed.certificate, privateKey, role, expiresAt: until, dispose() { privateKey.fill(0); } });
}

// Validates an already issued credential without requiring it to have been issued in the last five minutes.
export function importLocalIdentity(certificate: Buffer, privateKey: Buffer, role: LocalIdentityRole): IssuedLocalIdentity {
  try {
    if (!["host", "client"].includes(role) || !Buffer.isBuffer(privateKey) || privateKey.length < 128 || privateKey.length > 2048) throw new LocalIdentityError();
    return material(certificate, privateKey, role, false);
  } catch { throw new LocalIdentityError(); }
}

// Main-process capability, not a renderer/HTTP entrypoint. Does not enroll or persist credentials.
export async function generateLocalIdentity(options: { executable: string; role: LocalIdentityRole; signal?: AbortSignal }): Promise<IssuedLocalIdentity> {
  if (generating) throw new LocalIdentityError();
  generating = true;
  try {
    if (!options || !["host", "client"].includes(options.role) || (options.signal !== undefined && !(options.signal instanceof AbortSignal)) || options.signal?.aborted) throw new LocalIdentityError();
    assertNativeHelperExecutable(options.executable);
    return await new Promise<IssuedLocalIdentity>((resolve, reject) => {
      const child = spawn(options.executable, ["identity", options.role], { cwd: path.dirname(options.executable), env: nativeHelperEnvironment(),
        stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
      const chunks: Buffer[] = []; let length = 0, failed = false;
      const wipe = () => { for (const chunk of chunks) chunk.fill(0); chunks.length = 0; };
      // Issuance owns only memory and pipes: force termination rather than wait on a stuck native crypto call.
      const abort = () => { if (failed) return; failed = true; wipe(); child.kill("SIGKILL"); };
      const timer = setTimeout(abort, 10000);
      options.signal?.addEventListener("abort", abort, { once: true });
      child.on("error", abort); child.stdout.on("error", abort); child.stderr.on("error", abort); child.stderr.resume();
      child.stdout.on("data", (chunk: Buffer) => {
        if (failed || length + chunk.length > 8192) { chunk.fill(0); abort(); return; }
        chunks.push(chunk); length += chunk.length;
      });
      child.once("close", (code, signal) => {
        clearTimeout(timer); options.signal?.removeEventListener("abort", abort);
        let payload: Buffer | undefined;
        try {
          if (failed || options.signal?.aborted || code !== 0 || signal !== null || !child.pid) throw new LocalIdentityError();
          payload = Buffer.concat(chunks, length); resolve(parse(payload, child.pid, options.role));
        } catch { reject(new LocalIdentityError()); }
        finally { payload?.fill(0); wipe(); }
      });
      if (options.signal?.aborted) abort();
    });
  } catch { throw new LocalIdentityError(); }
  finally { generating = false; }
}
