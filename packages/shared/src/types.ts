export type PasswordEntrySummary = {
  type?: "login";
  id: string;
  serviceName: string;
  loginId: string;
  tags: string[];
  group: string | null;
  updatedAt: string;
};

export type PasswordEntry = PasswordEntrySummary & {
  passwordChangedAt: string | null;
  password: string;
  notes: string;
  url: string;
  createdAt: string;
};

export type PasswordEntryUpsertPayload = {
  serviceName: string;
  loginId: string;
  password: string;
  notes?: string;
  url?: string;
  tags?: string[];
  group?: string;
};

export type VaultEntryType = "login" | "apiKey" | "creditCard";
type AdditionalEntrySummary = Omit<PasswordEntrySummary, "type" | "loginId"> & { loginId?: never };
type AdditionalEntry = Omit<PasswordEntry, "type" | "loginId" | "password" | "passwordChangedAt"> & {
  loginId?: never; password?: never; passwordChangedAt?: never;
};
type AdditionalEntryPayload = Omit<PasswordEntryUpsertPayload, "loginId" | "password">;
export type ApiKeyEntry = AdditionalEntry & {
  type: "apiKey";
  apiKey: { key: string; keyId: string; expiresOn: string | null };
};
export type CreditCardEntry = AdditionalEntry & {
  type: "creditCard";
  card: { number: string; cardholder: string; expiryMonth: string | null; securityCode: string };
};
export type VaultEntry = PasswordEntry | ApiKeyEntry | CreditCardEntry;
export type VaultEntrySummary = PasswordEntrySummary | (AdditionalEntrySummary & { type: "apiKey" }) |
  (AdditionalEntrySummary & { type: "creditCard"; cardLast4: string });
export type VaultEntryUpsertPayload = PasswordEntryUpsertPayload |
  (AdditionalEntryPayload & { type: "apiKey"; apiKey: { key: string; keyId?: string; expiresOn?: string } }) |
  (AdditionalEntryPayload & { type: "creditCard"; card: { number: string; cardholder?: string; expiryMonth?: string; securityCode?: string } });

export type PasswordGenerationOptions = {
  length?: number;
  includeUppercase?: boolean;
  includeLowercase?: boolean;
  includeNumbers?: boolean;
  includeSymbols?: boolean;
};

export type PasswordGenerationResult = {
  password: string;
};

export type VaultLockReason = "manual" | "idle" | "clock-change" | "reset" | "window-closed" | "renderer-gone" | "update"
  | "screen-lock" | "screen-unlock" | "suspend" | "resume";

export type VaultSessionState = {
  sessionId: string;
  isUnlocked: boolean;
  idleTimeoutMs: number;
  lockReason?: VaultLockReason;
};

export type VaultStatus = VaultSessionState & {
  isConfigured: boolean;
  maintenance?: VaultMaintenanceState;
};

export type VaultMaintenanceOperation = "migrate" | "rekey" | "reset" | "recover";
export type VaultMaintenanceState = {
  state: "ready" | "running" | "recovery-required";
  format: "legacy" | "v2" | "unknown";
  operation?: VaultMaintenanceOperation;
  recoveryOperation?: "migrate" | "rekey" | "reset";
  sourceSessionId?: string;
};
export type VaultMaintenancePayload = {
  operation: VaultMaintenanceOperation;
  masterPassword: string;
  newMasterPassword: string;
  confirmNewMasterPassword: string;
  backupPassphrase: string;
  confirmBackupPassphrase?: string;
  confirmation?: "RESET_ALL_DATA";
};

export type VaultSetupPayload = {
  masterPassword: string;
};

export type VaultUnlockPayload = {
  masterPassword: string;
};

export type VaultResetPayload = {
  confirmation: "RESET_ALL_DATA";
};

export type VaultMetadataRecord = {
  id: number;
  passwordSalt: string;
  passwordVerifier: string;
  kdfParams: string;
  createdAt: string;
  updatedAt: string;
};

export type PasswordManagerDesktopApi = {
  getLocalConnections: (sessionId: string) => Promise<LocalConnectionsState>;
  setLocalConnectionsEnabled: (enabled: boolean, revision: number, sessionId: string) => Promise<LocalConnectionsState>;
  selectLocalPairingRequest: (sessionId: string) => Promise<LocalConnectionsState>;
  approveLocalPairing: (approval: LocalPairingApproval, sessionId: string) => Promise<LocalConnectionsState>;
  cancelLocalPairing: (pendingId: string, sessionId: string) => Promise<LocalConnectionsState>;
  revokeLocalClient: (clientId: string, revision: number, sessionId: string) => Promise<LocalConnectionsState>;
  saveLocalConnectionInfo: (clientId: string, sessionId: string) => Promise<boolean>;
  runVaultMaintenance: (payload: VaultMaintenancePayload, sessionId: string) => Promise<VaultStatus>;
  exportBackup: (payload: BackupExportPayload, sessionId: string) => Promise<BackupFile>;
  restoreBackup: (payload: BackupRestorePayload, sessionId: string) => Promise<{ restoredCount: number }>;
  auditVault: (sessionId: string) => Promise<SecurityAudit>;
  getUpdateState: () => Promise<AppUpdateState>;
  checkForUpdates: () => Promise<void>;
  downloadUpdate: () => Promise<void>;
  installUpdate: (hasUnsavedChanges: boolean) => Promise<false | void>;
  openReleasePage: () => Promise<void>;
  onUpdateState: (listener: (state: AppUpdateState) => void) => () => void;
  fetchVaultStatus: () => Promise<VaultStatus>;
  onVaultState: (listener: (state: VaultStatus) => void) => () => void;
  recordVaultActivity: (sessionId: string) => Promise<VaultStatus>;
  setupVault: (payload: VaultSetupPayload, sessionId: string) => Promise<VaultStatus>;
  unlockVault: (payload: VaultUnlockPayload, sessionId: string) => Promise<VaultStatus>;
  lockVault: (sessionId: string) => Promise<VaultStatus>;
  resetVault: (payload: VaultResetPayload, sessionId: string) => Promise<VaultStatus>;
  fetchEntries: (sessionId: string) => Promise<{ items: VaultEntrySummary[] }>;
  fetchEntry: (id: string, sessionId: string) => Promise<VaultEntry>;
  createEntry: (payload: VaultEntryUpsertPayload, sessionId: string) => Promise<VaultEntry>;
  updateEntry: (id: string, payload: VaultEntryUpsertPayload, sessionId: string) => Promise<VaultEntry>;
  deleteEntry: (id: string, sessionId: string) => Promise<{ success: boolean }>;
  generatePassword: (options: PasswordGenerationOptions, sessionId: string) => Promise<PasswordGenerationResult>;
  copyText: (value: string, sessionId: string) => Promise<void>;
};

export type LocalPairingReview = Readonly<{ pendingId: string; displayName: string; kind: "agent" | "browser"; fingerprint256: string; expiresAt: number; registrationExpiresAt: number; revision: number }>;
export type LocalPairingApproval = Readonly<{ pendingId: string; expectedRevision: number; fingerprint256: string; confirmation: "MATCHED_FINGERPRINT" }>;
export type LocalConnectionsState = Readonly<{
  status: "disabled" | "paused" | "locked" | "starting" | "ready" | "unavailable";
  enabled: boolean;
  revision: number;
  clients: readonly Readonly<{ clientId: string; displayName: string; kind: "agent" | "browser"; fingerprint256: string; createdAt: number; expiresAt: number; revokedAt: number | null; state: "active" | "revoked" | "expired" }>[];
  review: LocalPairingReview | null;
}>;

export type BackupExportPayload = { passphrase: string };
export type BackupFile = { fileName: string; content: string };
export type BackupRestorePayload = BackupExportPayload & { content: string };
export type AuditIssue = "weak" | "duplicate" | "oldPassword" | "missingUrl" | "staleEntry";
export type SecurityAudit = {
  score: number | null;
  total: number;
  checkedAt: string;
  unknownPasswordAgeCount: number;
  counts: Record<AuditIssue, number>;
  items: { id: string; serviceName: string; loginId: string; issues: AuditIssue[] }[];
};

export type AppUpdateState = {
  status: "idle" | "checking" | "available" | "current" | "downloading" | "downloaded" | "installing" | "error" | "unsupported";
  currentVersion: string;
  latestVersion?: string;
  releaseNotes?: string;
  progress?: number;
  message?: string;
};
