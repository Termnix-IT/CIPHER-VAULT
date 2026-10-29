import type { SafeStorage } from "electron";

export class IdentityStorageError extends Error {
  readonly code = "LOCAL_IDENTITY_STORAGE_UNAVAILABLE";
  constructor() { super("接続資格の保護または復元に失敗しました"); this.name = "IdentityStorageError"; }
}
export type DeviceKeyProvider = "windows-dpapi" | "macos-keychain" | "linux-secret-service" | "linux-secret-portal";
type Storage = Pick<SafeStorage, "isAsyncEncryptionAvailable" | "encryptStringAsync" | "decryptStringAsync">;
type Host = { isReady(): boolean; platform: string; electronVersion: string | undefined; chromiumVersion: string | undefined; hasSwitch(name: string): boolean };
export type ProtectedDeviceKey = Readonly<{ provider: DeviceKeyProvider; data: Buffer }>;
export interface DeviceKeyProtector {
  wrap(key: Buffer, signal?: AbortSignal): Promise<ProtectedDeviceKey>;
  unwrap(value: ProtectedDeviceKey, signal?: AbortSignal): Promise<{ key: Buffer; shouldReEncrypt: boolean }>;
}
export function electronDeviceKeyProtector(host: { isReady(): boolean; commandLine: { hasSwitch(name: string): boolean } }, storage: Storage) {
  return createDeviceKeyProtector({ isReady: () => host.isReady(), platform: process.platform, electronVersion: process.versions.electron,
    chromiumVersion: process.versions.chrome, hasSwitch: name => host.commandLine.hasSwitch(name) }, storage);
}

// These mappings are an audited native-format contract, not an attestation of a modified runtime.
// Unknown versions/tags fail closed. Do not use the synchronous backend name for the async provider.
export function createDeviceKeyProtector(host: Host, storage: Storage): DeviceKeyProtector {
  let busy = false;
  function supported() {
    if (!host.isReady() || host.electronVersion !== "45.0.0" || host.chromiumVersion !== "156.0.8078.48" ||
        !["win32", "darwin", "linux"].includes(host.platform) || host.hasSwitch("use-mock-keychain")) throw new IdentityStorageError();
  }
  function provider(data: Buffer): DeviceKeyProvider {
    if (!Buffer.isBuffer(data) || data.length < 20 || data.length > 2048) throw new IdentityStorageError();
    const tag = data.subarray(0, 3).toString("ascii");
    if (host.platform === "win32" && tag === "v10") return "windows-dpapi";
    if (host.platform === "darwin" && tag === "v10") return "macos-keychain";
    if (host.platform === "linux" && tag === "v11") return "linux-secret-service";
    if (host.platform === "linux" && tag === "v12") return "linux-secret-portal";
    throw new IdentityStorageError();
  }
  async function run<T>(action: (active: () => void) => Promise<T>, dispose: (value: T) => void, signal?: AbortSignal): Promise<T> {
    supported();
    if (busy || (signal !== undefined && !(signal instanceof AbortSignal)) || signal?.aborted) throw new IdentityStorageError();
    busy = true;
    let cancelled = false, timer: ReturnType<typeof setTimeout> | undefined, rejectCaller: (error: Error) => void = () => {};
    const active = () => { supported(); if (cancelled || signal?.aborted) throw new IdentityStorageError(); };
    const abort = () => { cancelled = true; rejectCaller(new IdentityStorageError()); };
    const interrupted = new Promise<never>((_resolve, reject) => { rejectCaller = reject; timer = setTimeout(abort, 10000); signal?.addEventListener("abort", abort, { once: true }); });
    const job = (async () => {
      let result: T | undefined;
      try {
        active(); if (await storage.isAsyncEncryptionAvailable() !== true) throw new IdentityStorageError(); active();
        result = await action(active); active(); return result;
      } catch { if (result !== undefined) dispose(result); throw new IdentityStorageError(); }
      finally { busy = false; }
    })();
    // A timeout returns promptly but retains the busy gate until the native job settles.
    void job.then(value => { if (cancelled) dispose(value); }, () => {});
    try { return await Promise.race([job, interrupted]); }
    finally { clearTimeout(timer); signal?.removeEventListener("abort", abort); }
  }
  function decode(result: Awaited<ReturnType<Storage["decryptStringAsync"]>>) {
    if (!result || typeof result.result !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(result.result) || typeof result.shouldReEncrypt !== "boolean") throw new IdentityStorageError();
    const key = Buffer.from(result.result, "base64");
    if (key.length !== 32 || key.toString("base64") !== result.result) { key.fill(0); throw new IdentityStorageError(); }
    return { key, shouldReEncrypt: result.shouldReEncrypt };
  }
  return Object.freeze({
    async wrap(input: Buffer, signal?: AbortSignal) {
      if (!Buffer.isBuffer(input) || input.length !== 32) throw new IdentityStorageError();
      const key = Buffer.from(input);
      try {
        return await run(async active => {
          let encrypted: Buffer | undefined, checked: Buffer | undefined;
          try {
            encrypted = await storage.encryptStringAsync(key.toString("base64")); active();
            const kind = provider(encrypted);
            const decoded = decode(await storage.decryptStringAsync(encrypted)); checked = decoded.key; active();
            if (decoded.shouldReEncrypt || !checked.equals(key)) throw new IdentityStorageError();
            return Object.freeze({ provider: kind, data: Buffer.from(encrypted) });
          } finally { encrypted?.fill(0); checked?.fill(0); }
        }, value => value.data.fill(0), signal);
      } finally { key.fill(0); }
    },
    async unwrap(value: ProtectedDeviceKey, signal?: AbortSignal) {
      supported();
      if (!value || provider(value.data) !== value.provider) throw new IdentityStorageError();
      const ciphertext = Buffer.from(value.data);
      try {
        return await run(async active => {
          const result = decode(await storage.decryptStringAsync(ciphertext));
          try { active(); return result; } catch { result.key.fill(0); throw new IdentityStorageError(); }
        }, value => value.key.fill(0), signal);
      } finally { ciphertext.fill(0); }
    }
  });
}
