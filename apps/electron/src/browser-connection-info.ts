import path from "node:path";
import { BrowserConnectionError } from "./browser-message.js";
import { localIdentityCertificate } from "./local-identity.js";
import { parseLocalPublicCertificate } from "./local-certificates.js";

export const browserUuid = (value: unknown): value is string => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
export type BrowserConnectionInfo = Readonly<{ version: 1; clientId: string; clientFingerprint256: string; hostCertificate: string; hostFingerprint256: string; discoveryFile: string }>;
export function parseBrowserConnectionInfo(input: Buffer, clientCertificate: Buffer, historical = false): BrowserConnectionInfo {
  try {
    if (!Buffer.isBuffer(input) || input.length < 1 || input.length > 16384) throw new BrowserConnectionError();
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(input)) as BrowserConnectionInfo;
    const client = parseLocalPublicCertificate(clientCertificate);
    localIdentityCertificate(clientCertificate, "client", historical ? client.from : Date.now());
    if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== "clientFingerprint256,clientId,discoveryFile,hostCertificate,hostFingerprint256,version" ||
        value.version !== 1 || !browserUuid(value.clientId) || value.clientFingerprint256 !== client.fingerprint ||
        typeof value.hostCertificate !== "string" || value.hostCertificate.length > 5464 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value.hostCertificate)) throw new BrowserConnectionError();
    const bytes = Buffer.from(value.hostCertificate, "base64"), publicHost = parseLocalPublicCertificate(bytes);
    const host = localIdentityCertificate(bytes, "host", historical ? publicHost.from : Date.now());
    if (bytes.toString("base64") !== value.hostCertificate || host.fingerprint !== value.hostFingerprint256 || host.fingerprint === client.fingerprint ||
        typeof value.discoveryFile !== "string" || value.discoveryFile.length > 4096 || !path.isAbsolute(value.discoveryFile) || path.resolve(value.discoveryFile) !== value.discoveryFile ||
        /[\x00-\x1f]/.test(value.discoveryFile) || value.discoveryFile.startsWith("\\\\") || value.discoveryFile.startsWith("//") || path.basename(value.discoveryFile) !== "connection.json") throw new BrowserConnectionError();
    return Object.freeze({ version: 1, clientId: value.clientId, clientFingerprint256: value.clientFingerprint256,
      hostCertificate: value.hostCertificate, hostFingerprint256: value.hostFingerprint256, discoveryFile: value.discoveryFile });
  } catch { throw new BrowserConnectionError(); }
}
export function browserDiscoveryEndpoint(input: Buffer, receipt: BrowserConnectionInfo) {
  try {
    if (!Buffer.isBuffer(input) || input.length < 1 || input.length > 16384) throw new BrowserConnectionError();
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(input));
    if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== "clients,generation,hostFingerprint256,version" ||
        value.version !== 1 || !browserUuid(value.generation) || value.hostFingerprint256 !== receipt.hostFingerprint256 || !Array.isArray(value.clients) || value.clients.length > 16) throw new BrowserConnectionError();
    const ids = new Set<string>(), endpoints = new Set<string>(); let selected: string | undefined;
    for (const client of value.clients) {
      if (!client || typeof client !== "object" || Array.isArray(client) || Object.keys(client).sort().join(",") !== "clientId,endpoint" ||
          !browserUuid(client.clientId) || ids.has(client.clientId) || typeof client.endpoint !== "string" || endpoints.has(client.endpoint) ||
          (process.platform === "win32" ? !/^\\\\\.\\pipe\\cipher-vault-[0-9a-f-]{36}$/.test(client.endpoint) :
            !path.isAbsolute(client.endpoint) || path.resolve(client.endpoint) !== client.endpoint || Buffer.byteLength(client.endpoint) > 103 ||
            !/^cv-live-[A-Za-z0-9]+$/.test(path.basename(path.dirname(client.endpoint))) || !/^[0-9a-f-]{36}\.sock$/.test(path.basename(client.endpoint)))) throw new BrowserConnectionError();
      ids.add(client.clientId); endpoints.add(client.endpoint); if (client.clientId === receipt.clientId) selected = client.endpoint;
    }
    if (!selected) throw new BrowserConnectionError(); return selected;
  } catch { throw new BrowserConnectionError(); }
}
