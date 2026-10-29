import Database from "better-sqlite3";
import { closeSync, lstatSync, openSync, realpathSync } from "node:fs";
import { BrowserConnectionError } from "./browser-message.js";
import { browserUuid, parseBrowserConnectionInfo, type BrowserConnectionInfo } from "./browser-connection-info.js";
import { localIdentityCertificate } from "./local-identity.js";
import { parseLocalPublicCertificate } from "./local-certificates.js";
import { localPublicPath } from "./local-public-files.js";
import type { LocalIdentityReference } from "./protected-local-identity.js";

const applicationId = 0x43564c43;
const ddl = `CREATE TABLE browser_client (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  revision INTEGER NOT NULL CHECK (revision BETWEEN 0 AND 2147483647),
  identity_id TEXT,
  certificate BLOB,
  receipt BLOB
) STRICT`;
export type BrowserClientSnapshot = Readonly<{ revision: number; credential: null | Readonly<{ reference: LocalIdentityReference; certificate: Buffer; receipt: BrowserConnectionInfo | null }> }>;
export interface BrowserClientStore {
  read(): BrowserClientSnapshot;
  replace(expectedRevision: number, identityId: string, certificate: Buffer): void;
  importReceipt(expectedRevision: number, content: Buffer): void;
  close(): void;
}

// Public metadata only. The immutable cvkey file must be durably protected before its reference
// is committed here. Unknown/partial stores are never replaced, repaired or adopted automatically.
export function openBrowserClientStore(file: string, create = false): BrowserClientStore {
  let database: Database.Database | undefined;
  try {
    localPublicPath(file);
    if (create) closeSync(openSync(file, "wx", 0o600));
    const info = lstatSync(file);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > 1024 * 1024 || realpathSync(file) !== file) throw new BrowserConnectionError();
    database = new Database(file, { fileMustExist: true, timeout: 0 }); const db = database;
    db.pragma("trusted_schema = OFF"); db.pragma("synchronous = EXTRA"); db.pragma("secure_delete = ON"); db.pragma("locking_mode = EXCLUSIVE");
    if (db.pragma("synchronous", { simple: true }) !== 3 || db.pragma("locking_mode", { simple: true }) !== "exclusive" || db.pragma("journal_mode", { simple: true }) !== "delete") throw new BrowserConnectionError();
    let faulted = false;
    const read = (): BrowserClientSnapshot => {
      const objects = db.prepare("SELECT type,name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' LIMIT 2").all() as { type: string; name: string; sql: string }[];
      if (db.pragma("application_id", { simple: true }) !== applicationId || db.pragma("user_version", { simple: true }) !== 1 ||
          objects.length !== 1 || objects[0].type !== "table" || objects[0].name !== "browser_client" || objects[0].sql !== ddl) throw new BrowserConnectionError();
      const rows = db.prepare("SELECT singleton,revision,identity_id, CASE WHEN length(certificate) <= 4096 THEN certificate END AS certificate, CASE WHEN length(receipt) <= 16384 THEN receipt END AS receipt, length(certificate) AS certificate_size, length(receipt) AS receipt_size FROM browser_client LIMIT 2").all() as {
        singleton: number; revision: number; identity_id: string | null; certificate: Buffer | null; receipt: Buffer | null; certificate_size: number | null; receipt_size: number | null
      }[];
      const row = rows[0];
      if (rows.length !== 1 || row.singleton !== 1 || !Number.isInteger(row.revision) || row.revision < 0 || row.revision > 2147483647 ||
          (row.certificate_size !== null && !Buffer.isBuffer(row.certificate)) || (row.receipt_size !== null && !Buffer.isBuffer(row.receipt))) throw new BrowserConnectionError();
      if (row.identity_id === null && row.certificate === null && row.receipt === null) return Object.freeze({ revision: row.revision, credential: null });
      if (!browserUuid(row.identity_id) || !Buffer.isBuffer(row.certificate)) throw new BrowserConnectionError();
      const certificate = parseLocalPublicCertificate(row.certificate); localIdentityCertificate(row.certificate, "client", certificate.from);
      const reference = Object.freeze({ identityId: row.identity_id, role: "client" as const, fingerprint256: certificate.fingerprint });
      return Object.freeze({ revision: row.revision, credential: Object.freeze({ reference, certificate: certificate.certificate,
        receipt: row.receipt === null ? null : parseBrowserConnectionInfo(row.receipt, certificate.certificate, true) }) });
    };
    db.transaction(() => {
      if (create) { db.exec(ddl); db.pragma(`application_id = ${applicationId}`); db.pragma("user_version = 1"); db.prepare("INSERT INTO browser_client VALUES (1,0,NULL,NULL,NULL)").run(); }
      read();
    }).exclusive();
    function run<T>(action: () => T): T {
      if (!db.open || faulted) throw new BrowserConnectionError();
      try { return action(); } catch { faulted = true; throw new BrowserConnectionError(); }
    }
    const current = (revision: number) => { const value = read(); if (!Number.isInteger(revision) || revision < 0 || revision >= 2147483647 || value.revision !== revision) throw new BrowserConnectionError(); return value; };
    return Object.freeze({
      read: () => run(read),
      replace(revision: number, identityId: string, certificate: Buffer) {
        if (!browserUuid(identityId)) throw new BrowserConnectionError(); localIdentityCertificate(certificate, "client");
        run(() => db.transaction(() => {
          const value = current(revision);
          if (value.credential?.reference.identityId === identityId || value.credential?.reference.fingerprint256 === parseLocalPublicCertificate(certificate).fingerprint) throw new BrowserConnectionError();
          db.prepare("UPDATE browser_client SET revision=revision+1,identity_id=?,certificate=?,receipt=NULL WHERE singleton=1").run(identityId, certificate); read();
        }).immediate());
      },
      importReceipt(revision: number, content: Buffer) {
        run(() => db.transaction(() => {
          const value = current(revision); if (!value.credential) throw new BrowserConnectionError();
          const receipt = parseBrowserConnectionInfo(content, value.credential.certificate);
          // An imported file may complete the existing pairing, but cannot silently change its host/client binding.
          if (value.credential.receipt && JSON.stringify(value.credential.receipt) !== JSON.stringify(receipt)) throw new BrowserConnectionError();
          db.prepare("UPDATE browser_client SET revision=revision+1,receipt=? WHERE singleton=1").run(Buffer.from(JSON.stringify(receipt))); read();
        }).immediate());
      },
      close() { if (db.open) db.close(); }
    });
  } catch { database?.close(); throw new BrowserConnectionError(); }
}
