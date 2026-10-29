import Database from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { closeSync, lstatSync, openSync, realpathSync } from "node:fs";
import path from "node:path";
import { parseLocalPublicCertificate } from "./local-certificates.js";
import { localIdentityCertificate } from "./local-identity.js";
import type { LocalIdentityReference } from "./protected-local-identity.js";

export const LOCAL_CLIENT_LIMITS = Object.freeze({ active: 16, retained: 256, certificateBytes: 16384 });
type Code = "INVALID_INPUT" | "INVALID_STORE" | "UNAVAILABLE" | "CONFLICT" | "LIMIT" | "DENIED" | "CLOSED";
export class LocalClientRegistryError extends Error {
  constructor(readonly code: Code) { super("クライアント登録を利用できません"); this.name = "LocalClientRegistryError"; }
}
const fail = (code: Code): never => { throw new LocalClientRegistryError(code); };
const applicationId = 0x43564c52;
const tables = {
  local_host: `CREATE TABLE local_host (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  fingerprint TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision BETWEEN 0 AND 2147483647)
) STRICT`,
  local_clients: `CREATE TABLE local_clients (
  client_id TEXT PRIMARY KEY NOT NULL,
  display_name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('agent', 'browser')),
  certificate BLOB NOT NULL,
  fingerprint TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
) STRICT`
};
const configurationTable = `CREATE TABLE local_connection_config (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  identity_id TEXT NOT NULL,
  certificate BLOB NOT NULL,
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
) STRICT`;
type HostConfiguration = Readonly<{ identityId: string; certificate: Buffer }>;
export type LocalClientRegistration = Readonly<{
  clientId: string; displayName: string; kind: "agent" | "browser"; fingerprint256: string;
  createdAt: number; expiresAt: number; revokedAt: number | null;
}>;
export type ClientEnrollment = Readonly<{ displayName: string; kind: "agent" | "browser"; certificate: Buffer; expiresAt: number }>;
type StoredClient = LocalClientRegistration & Readonly<{ certificate: Buffer }>;
export type LocalClientSnapshot = Readonly<{ revision: number; clients: readonly StoredClient[]; enabled?: boolean }>;
export interface LocalClientStore {
  readonly hostFingerprint: string;
  read(): LocalClientSnapshot;
  enroll(expectedRevision: number, input: ClientEnrollment, now: number): LocalClientRegistration;
  revoke(expectedRevision: number, clientId: string | null, now: number): void;
  close(): void;
}
export interface ManagedLocalClientStore extends LocalClientStore {
  configuration(): Readonly<{ reference: LocalIdentityReference; certificate: Buffer; enabled: boolean }>;
  setEnabled(expectedRevision: number, enabled: boolean): void;
}
function timestamp(value: unknown): value is number { return Number.isSafeInteger(value) && (value as number) > 0 && (value as number) <= 8640000000000000; }
export function publicLocalCertificate(input: Buffer) {
  try {
    if (!Buffer.isBuffer(input) || input.length < 1 || input.length > LOCAL_CLIENT_LIMITS.certificateBytes) fail("INVALID_INPUT");
    return parseLocalPublicCertificate(input);
  } catch { return fail("INVALID_INPUT"); }
}
function enrollment(input: ClientEnrollment, now: number) {
  if (!input || typeof input !== "object" || Object.keys(input).sort().join(",") !== "certificate,displayName,expiresAt,kind" ||
      typeof input.displayName !== "string" || input.displayName.trim() !== input.displayName || input.displayName.length < 1 || input.displayName.length > 80 ||
      /[\p{C}\p{Zl}\p{Zp}]/u.test(input.displayName) || !["agent", "browser"].includes(input.kind) || !timestamp(now) ||
      !timestamp(input.expiresAt) || input.expiresAt <= now) fail("INVALID_INPUT");
  const certificate = publicLocalCertificate(input.certificate);
  if (now < certificate.from || now >= certificate.until || input.expiresAt > certificate.until) fail("INVALID_INPUT");
  return certificate;
}
function location(input: string) {
  if (typeof input !== "string" || !path.isAbsolute(input) || input.includes("\0") || path.resolve(input) !== input) fail("INVALID_INPUT");
  if (realpathSync(path.dirname(input)) !== path.dirname(input)) fail("INVALID_INPUT");
  return input;
}
function regularFile(file: string) {
  const info = lstatSync(file);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || realpathSync(file) !== file) fail("INVALID_STORE");
}
function error(input: unknown): never { if (input instanceof LocalClientRegistryError) throw input; return fail("UNAVAILABLE"); }

// Explicit paths only. No environment, vault schema changes, private keys or implicit creation on import/open.
export function createLocalClientStore(file: string, hostCertificate: Buffer): LocalClientStore {
  const host = publicLocalCertificate(hostCertificate);
  try {
    location(file); closeSync(openSync(file, "wx", 0o600));
    return open(file, host.fingerprint, true);
  } catch (cause) { return error(cause); }
}
export function openLocalClientStore(file: string, hostCertificate: Buffer): LocalClientStore {
  const host = publicLocalCertificate(hostCertificate);
  try { location(file); return open(file, host.fingerprint, false); }
  catch (cause) { return error(cause); }
}
export function createManagedLocalClientStore(file: string, host: HostConfiguration): ManagedLocalClientStore {
  try {
    if (!host || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(host.identityId)) fail("INVALID_INPUT");
    const certificate = localIdentityCertificate(host.certificate, "host");
    location(file); closeSync(openSync(file, "wx", 0o600));
    return open(file, certificate.fingerprint, true, { identityId: host.identityId, certificate: certificate.certificate }) as ManagedLocalClientStore;
  } catch (cause) { return error(cause); }
}
export function openManagedLocalClientStore(file: string): ManagedLocalClientStore {
  try { location(file); return open(file, null, false, true) as ManagedLocalClientStore; }
  catch (cause) { return error(cause); }
}
function readConfiguration(database: Database.Database) {
  const rows = database.prepare("SELECT singleton, identity_id, CASE WHEN length(certificate) <= 4096 THEN certificate END AS certificate, enabled FROM local_connection_config LIMIT 2").all() as { singleton: number; identity_id: string; certificate: Buffer; enabled: number }[];
  if (rows.length !== 1 || rows[0].singleton !== 1 || ![0, 1].includes(rows[0].enabled) || typeof rows[0].identity_id !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(rows[0].identity_id)) fail("INVALID_STORE");
  const certificate = publicLocalCertificate(rows[0].certificate);
  // Expired public configuration remains readable for stopping/revoking. Private-key restoration still checks current time.
  localIdentityCertificate(rows[0].certificate, "host", certificate.from);
  return { identityId: rows[0].identity_id, certificate, enabled: rows[0].enabled === 1 };
}
function open(file: string, fingerprint: string | null, create: boolean, managed?: HostConfiguration | true): LocalClientStore {
  regularFile(file);
  const database = new Database(file, { fileMustExist: true, timeout: 0 });
  try {
    database.pragma("trusted_schema = OFF");
    database.pragma("synchronous = EXTRA"); database.pragma("secure_delete = ON");
    database.pragma("locking_mode = EXCLUSIVE");
    if (database.pragma("synchronous", { simple: true }) !== 3 || database.pragma("locking_mode", { simple: true }) !== "exclusive" ||
        database.pragma("journal_mode", { simple: true }) !== "delete") fail("INVALID_STORE");
    database.transaction(() => {
      if (create) {
        database.exec(Object.values(tables).join(";\n") + ";");
        database.pragma(`application_id = ${applicationId}`); database.pragma("user_version = 2");
        database.prepare("INSERT INTO local_host VALUES (1, ?, 0)").run(fingerprint);
        if (managed && managed !== true) {
          database.exec(configurationTable);
          database.prepare("INSERT INTO local_connection_config VALUES (1, ?, ?, 0)").run(managed.identityId, managed.certificate);
          database.pragma("user_version = 3");
        }
      }
      if (managed) { schema(database, true); fingerprint ??= readConfiguration(database).certificate.fingerprint; }
      inspect(database, fingerprint!, Boolean(managed));
    }).exclusive();
    return adapter(database, fingerprint!, Boolean(managed));
  } catch (cause) { database.close(); return error(cause); }
}
function schema(database: Database.Database, managed: boolean) {
  const version = database.pragma("user_version", { simple: true });
  if (database.pragma("application_id", { simple: true }) !== applicationId || !(managed ? version === 3 : [1, 2].includes(version as number))) fail("INVALID_STORE");
  const objects = database.prepare("SELECT type, name, sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' LIMIT 4").all() as { type: string; name: string; sql: string }[];
  if (objects.length !== (managed ? 3 : 2) || objects.some(row => row.type !== "table" || (managed && row.name === "local_connection_config" ? row.sql !== configurationTable :
      !Object.hasOwn(tables, row.name) || row.sql !== tables[row.name as keyof typeof tables]))) fail("INVALID_STORE");
  return version;
}
function inspect(database: Database.Database, fingerprint: string, managed = false): LocalClientSnapshot {
  const version = schema(database, managed), configuration = managed ? readConfiguration(database) : undefined;
  if (configuration && configuration.certificate.fingerprint !== fingerprint) fail("INVALID_STORE");
  const headers = database.prepare("SELECT * FROM local_host LIMIT 2").all() as { singleton: number; fingerprint: string; revision: number }[];
  if (headers.length !== 1 || headers[0].singleton !== 1 || headers[0].fingerprint !== fingerprint ||
      !Number.isInteger(headers[0].revision) || headers[0].revision < 0 || headers[0].revision > 2147483647) fail("INVALID_STORE");
  const rows = database.prepare("SELECT * FROM local_clients ORDER BY client_id LIMIT ?").all(LOCAL_CLIENT_LIMITS.retained + 1) as {
    client_id: string; display_name: string; kind: "agent" | "browser"; certificate: Buffer; fingerprint: string; created_at: number; expires_at: number; revoked_at: number | null
  }[];
  if (rows.length > LOCAL_CLIENT_LIMITS.retained) fail("INVALID_STORE");
  const clients = rows.map(row => {
    try {
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(row.client_id)) fail("INVALID_STORE");
      const cert = enrollment({ displayName: row.display_name, kind: row.kind, certificate: row.certificate, expiresAt: row.expires_at }, row.created_at);
      if (!cert.stored.equals(row.certificate) || (version === 1 && cert.issuer) || cert.fingerprint !== row.fingerprint || cert.fingerprint === fingerprint ||
          (row.revoked_at !== null && (!timestamp(row.revoked_at) || row.revoked_at < row.created_at))) fail("INVALID_STORE");
      return Object.freeze({ clientId: row.client_id, displayName: row.display_name, kind: row.kind, certificate: cert.certificate,
        fingerprint256: cert.fingerprint, createdAt: row.created_at, expiresAt: row.expires_at, revokedAt: row.revoked_at });
    } catch { return fail("INVALID_STORE"); }
  });
  return Object.freeze({ revision: headers[0].revision, clients: Object.freeze(clients), ...(configuration ? { enabled: configuration.enabled } : {}) });
}
export function registrationSummary({ certificate: _certificate, ...summary }: StoredClient): LocalClientRegistration { return Object.freeze(summary); }
function adapter(database: Database.Database, fingerprint: string, managed = false): LocalClientStore {
  let faulted = false;
  function run<T>(action: () => T): T {
    if (!database.open) fail("CLOSED"); if (faulted) fail("UNAVAILABLE");
    try { return action(); }
    catch (cause) {
      if (!(cause instanceof LocalClientRegistryError) || ["INVALID_STORE", "UNAVAILABLE"].includes(cause.code)) faulted = true;
      return error(cause);
    }
  }
  function current(expected: number) {
    const value = inspect(database, fingerprint, managed);
    if (!Number.isInteger(expected) || value.revision !== expected || expected >= 2147483647) fail("CONFLICT");
    return value;
  }
  const base: LocalClientStore = { hostFingerprint: fingerprint,
    read: () => run(() => inspect(database, fingerprint, managed)),
    enroll(expectedRevision, input, now) {
      const cert = enrollment(input, now);
      return run(() => database.transaction(() => {
        const snapshot = current(expectedRevision);
        if (cert.fingerprint === fingerprint || snapshot.clients.some(client => client.fingerprint256 === cert.fingerprint)) fail("CONFLICT");
        if (snapshot.clients.length >= LOCAL_CLIENT_LIMITS.retained || snapshot.clients.filter(client => client.revokedAt === null && client.expiresAt > now).length >= LOCAL_CLIENT_LIMITS.active) fail("LIMIT");
        const clientId = randomUUID();
        database.prepare("INSERT INTO local_clients VALUES (?, ?, ?, ?, ?, ?, ?, NULL)")
          .run(clientId, input.displayName, input.kind, cert.stored, cert.fingerprint, now, input.expiresAt);
        if (cert.issuer && !managed) database.pragma("user_version = 2");
        database.prepare("UPDATE local_host SET revision = revision + 1 WHERE singleton = 1").run();
        return registrationSummary(inspect(database, fingerprint, managed).clients.find(client => client.clientId === clientId)!);
      }).immediate());
    },
    revoke(expectedRevision, clientId, now) {
      if (!timestamp(now) || (clientId !== null && (typeof clientId !== "string" || clientId.length > 64))) fail("INVALID_INPUT");
      run(() => database.transaction(() => {
        const snapshot = current(expectedRevision);
        if (clientId !== null && !snapshot.clients.some(client => client.clientId === clientId)) fail("CONFLICT");
        if (snapshot.clients.some(client => client.createdAt > now)) fail("DENIED");
        const result = clientId === null ? database.prepare("UPDATE local_clients SET revoked_at = ? WHERE revoked_at IS NULL").run(now) :
          database.prepare("UPDATE local_clients SET revoked_at = ? WHERE client_id = ? AND revoked_at IS NULL").run(now, clientId);
        if (result.changes) database.prepare("UPDATE local_host SET revision = revision + 1 WHERE singleton = 1").run();
      }).immediate());
    },
    close() { try { if (database.open) database.close(); } catch { return fail("UNAVAILABLE"); } }
  };
  if (!managed) return Object.freeze(base);
  return Object.freeze<ManagedLocalClientStore>({ ...base,
    configuration: () => run(() => {
      inspect(database, fingerprint, true); const value = readConfiguration(database);
      return Object.freeze({ reference: Object.freeze({ identityId: value.identityId, role: "host" as const, fingerprint256: fingerprint }),
        certificate: Buffer.from(value.certificate.certificate), enabled: value.enabled });
    }),
    setEnabled(expectedRevision, enabled) {
      if (typeof enabled !== "boolean") fail("INVALID_INPUT");
      run(() => database.transaction(() => {
        current(expectedRevision);
        if (database.prepare("UPDATE local_connection_config SET enabled = ? WHERE singleton = 1 AND enabled <> ?").run(Number(enabled), Number(enabled)).changes)
          database.prepare("UPDATE local_host SET revision = revision + 1 WHERE singleton = 1").run();
        inspect(database, fingerprint, true);
      }).immediate());
    }
  });
}
