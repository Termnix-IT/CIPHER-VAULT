CREATE TABLE IF NOT EXISTS vault_metadata (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  password_salt TEXT NOT NULL,
  password_verifier TEXT NOT NULL,
  kdf_params TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS password_entries (
  id TEXT PRIMARY KEY,
  service_name TEXT NOT NULL,
  login_id TEXT NOT NULL,
  encrypted_password TEXT NOT NULL,
  encrypted_notes TEXT,
  url TEXT,
  tags TEXT NOT NULL,
  group_name TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
