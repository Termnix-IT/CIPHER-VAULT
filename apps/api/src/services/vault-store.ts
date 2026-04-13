import type { VaultMetadataRecord } from "../../../../packages/shared/src/types.js";
import { database } from "../db/database.js";

type VaultMetadataRow = {
  id: number;
  password_salt: string;
  password_verifier: string;
  kdf_params: string;
  created_at: string;
  updated_at: string;
};

const selectVaultMetadataStatement = database.prepare(
  `SELECT id, password_salt, password_verifier, kdf_params, created_at, updated_at
   FROM vault_metadata
   WHERE id = 1`
);

const upsertVaultMetadataStatement = database.prepare(
  `INSERT INTO vault_metadata (id, password_salt, password_verifier, kdf_params, created_at, updated_at)
   VALUES (@id, @password_salt, @password_verifier, @kdf_params, @created_at, @updated_at)
   ON CONFLICT(id) DO UPDATE SET
     password_salt = excluded.password_salt,
     password_verifier = excluded.password_verifier,
     kdf_params = excluded.kdf_params,
     updated_at = excluded.updated_at`
);

function mapRowToRecord(row: VaultMetadataRow): VaultMetadataRecord {
  return {
    id: row.id,
    passwordSalt: row.password_salt,
    passwordVerifier: row.password_verifier,
    kdfParams: row.kdf_params,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

export function getVaultMetadata() {
  const row = selectVaultMetadataStatement.get() as VaultMetadataRow | undefined;

  return row ? mapRowToRecord(row) : null;
}

export function saveVaultMetadata(record: VaultMetadataRecord) {
  upsertVaultMetadataStatement.run({
    id: record.id,
    password_salt: record.passwordSalt,
    password_verifier: record.passwordVerifier,
    kdf_params: record.kdfParams,
    created_at: record.createdAt,
    updated_at: record.updatedAt
  });
}
