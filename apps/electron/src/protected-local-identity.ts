import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { closeSync, fstatSync, fsyncSync, lstatSync, openSync, readSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import { IdentityStorageError, type DeviceKeyProtector, type DeviceKeyProvider } from "./device-key-protector.js";
import { importLocalIdentity, type IssuedLocalIdentity, type LocalIdentityRole } from "./local-identity.js";
import { parseLocalPublicCertificate } from "./local-certificates.js";

export type LocalIdentityReference = Readonly<{ identityId: string; role: LocalIdentityRole; fingerprint256: string }>;
type Envelope = LocalIdentityReference & { version: 1; cipher: "aes-256-gcm"; certificate: string; provider: DeviceKeyProvider; wrappedKey: string; iv: string; tag: string; data: string };
const maximumBytes = 32768, domain = "CIPHER-VAULT/local-identity/v1";
function reference(value: LocalIdentityReference) {
  if (!value || typeof value !== "object" || Object.keys(value).sort().join(",") !== "fingerprint256,identityId,role" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.identityId) || !["host", "client"].includes(value.role) ||
      !/^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/.test(value.fingerprint256)) throw new IdentityStorageError();
  return Object.freeze({ ...value });
}
function bytes(value: unknown, minimum: number, maximum = minimum) {
  if (typeof value !== "string" || value.length > Math.ceil(maximum / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new IdentityStorageError();
  const result = Buffer.from(value, "base64");
  if (result.length < minimum || result.length > maximum || result.toString("base64") !== value) throw new IdentityStorageError();
  return result;
}
function fileLocation(file: string, expected: LocalIdentityReference) {
  if (typeof file !== "string" || !path.isAbsolute(file) || path.resolve(file) !== file || file.includes("\0") ||
      path.basename(file) !== `identity-${expected.identityId}.cvkey` || realpathSync(path.dirname(file)) !== path.dirname(file)) throw new IdentityStorageError();
}
export function localIdentityFile(directory: string, identityId: string) { return path.join(directory, `identity-${identityId}.cvkey`); }
function aad(value: Omit<Envelope, "iv" | "tag" | "data">) {
  return Buffer.from(JSON.stringify([domain, value.version, value.cipher, value.identityId, value.role, value.fingerprint256, value.certificate, value.provider, value.wrappedKey]));
}
function parse(input: Buffer, expected: LocalIdentityReference): Envelope {
  if (input.length < 1 || input.length > maximumBytes) throw new IdentityStorageError();
  const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(input)) as Envelope;
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== "certificate,cipher,data,fingerprint256,identityId,iv,provider,role,tag,version,wrappedKey" ||
      value.version !== 1 || value.cipher !== "aes-256-gcm" || value.identityId !== expected.identityId || value.role !== expected.role || value.fingerprint256 !== expected.fingerprint256 ||
      !["windows-dpapi", "macos-keychain", "linux-secret-service", "linux-secret-portal"].includes(value.provider)) throw new IdentityStorageError();
  const certificate = parseLocalPublicCertificate(bytes(value.certificate, 128, 4096));
  if (certificate.fingerprint !== expected.fingerprint256 || !certificate.certificate.equals(bytes(value.certificate, 128, 4096))) throw new IdentityStorageError();
  bytes(value.wrappedKey, 20, 2048); bytes(value.iv, 12); bytes(value.tag, 16); bytes(value.data, 128, 2048);
  return value;
}
function read(file: string) {
  const before = lstatSync(file);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > maximumBytes || realpathSync(file) !== file) throw new IdentityStorageError();
  const descriptor = openSync(file, "r");
  const buffer = Buffer.alloc(maximumBytes + 1);
  try {
    const opened = fstatSync(descriptor);
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) throw new IdentityStorageError();
    let length = 0, count: number;
    do { count = readSync(descriptor, buffer, length, buffer.length - length, null); length += count; } while (count > 0 && length < buffer.length);
    if (length !== before.size || length > maximumBytes || fstatSync(descriptor).size !== before.size) throw new IdentityStorageError();
    return Buffer.from(buffer.subarray(0, length));
  } finally { buffer.fill(0); closeSync(descriptor); }
}

// Explicit, immutable record creation. No vault key, implicit startup, plaintext fallback or overwrite.
export class ProtectedLocalIdentityStore {
  private busy = false;
  constructor(private readonly protector: DeviceKeyProtector) {}
  async save(file: string, input: IssuedLocalIdentity, expectedInput: LocalIdentityReference, assertCurrent: () => void, signal?: AbortSignal): Promise<void> {
    if (this.busy) throw new IdentityStorageError(); this.busy = true;
    let identity: IssuedLocalIdentity | undefined, key: Buffer | undefined, wrapped: Buffer | undefined;
    try {
      const expected = reference(expectedInput); fileLocation(file, expected); assertCurrent(); if (signal?.aborted) throw new IdentityStorageError();
      try { lstatSync(file); throw new IdentityStorageError(); } catch (cause) { if ((cause as NodeJS.ErrnoException).code !== "ENOENT") throw cause; }
      identity = importLocalIdentity(input.certificate, input.privateKey, expected.role);
      const certificate = parseLocalPublicCertificate(identity.certificate);
      if (input.role !== expected.role || certificate.fingerprint !== expected.fingerprint256) throw new IdentityStorageError();
      key = randomBytes(32);
      const protectedKey = await this.protector.wrap(key, signal); wrapped = protectedKey.data;
      assertCurrent(); if (signal?.aborted) throw new IdentityStorageError();
      const header = { version: 1 as const, cipher: "aes-256-gcm" as const, ...expected, certificate: certificate.certificate.toString("base64"), provider: protectedKey.provider, wrappedKey: wrapped.toString("base64") };
      const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 }); cipher.setAAD(aad(header));
      const data = Buffer.concat([cipher.update(identity.privateKey), cipher.final()]);
      const envelope: Envelope = { ...header, iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), data: data.toString("base64") };
      const encoded = Buffer.from(JSON.stringify(envelope)); if (encoded.length > maximumBytes) throw new IdentityStorageError();
      assertCurrent(); if (signal?.aborted) throw new IdentityStorageError(); fileLocation(file, expected);
      const descriptor = openSync(file, "wx", 0o600);
      try { writeFileSync(descriptor, encoded); fsyncSync(descriptor); } finally { closeSync(descriptor); }
      if (process.platform !== "win32") { const directory = openSync(path.dirname(file), "r"); try { fsyncSync(directory); } finally { closeSync(directory); } }
    } catch { throw new IdentityStorageError(); }
    finally { identity?.dispose(); key?.fill(0); wrapped?.fill(0); this.busy = false; }
  }
  async load(file: string, expectedInput: LocalIdentityReference, assertCurrent: () => void, signal?: AbortSignal): Promise<{ identity: IssuedLocalIdentity; shouldReEncrypt: boolean }> {
    if (this.busy) throw new IdentityStorageError(); this.busy = true;
    let key: Buffer | undefined, partial: Buffer | undefined, tail: Buffer | undefined, plaintext: Buffer | undefined, identity: IssuedLocalIdentity | undefined;
    try {
      const expected = reference(expectedInput); fileLocation(file, expected); assertCurrent(); if (signal?.aborted) throw new IdentityStorageError();
      const envelope = parse(read(file), expected);
      const unwrapped = await this.protector.unwrap({ provider: envelope.provider, data: bytes(envelope.wrappedKey, 20, 2048) }, signal); key = unwrapped.key;
      assertCurrent(); if (signal?.aborted) throw new IdentityStorageError();
      if (!Buffer.isBuffer(key) || key.length !== 32) throw new IdentityStorageError();
      const decipher = createDecipheriv("aes-256-gcm", key, bytes(envelope.iv, 12), { authTagLength: 16 }); decipher.setAAD(aad(envelope)); decipher.setAuthTag(bytes(envelope.tag, 16));
      partial = decipher.update(bytes(envelope.data, 128, 2048)); tail = decipher.final(); plaintext = Buffer.concat([partial, tail]);
      identity = importLocalIdentity(bytes(envelope.certificate, 128, 4096), plaintext, expected.role);
      assertCurrent(); if (signal?.aborted) throw new IdentityStorageError();
      return { identity, shouldReEncrypt: unwrapped.shouldReEncrypt };
    } catch { identity?.dispose(); throw new IdentityStorageError(); }
    finally { key?.fill(0); partial?.fill(0); tail?.fill(0); plaintext?.fill(0); this.busy = false; }
  }
}
