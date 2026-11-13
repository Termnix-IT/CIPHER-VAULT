export type PasswordEntrySummary = {
  type?: "login";
  id: string;
  serviceName: string;
  loginId: string;
  tags: string[];
  group: string | null;
  updatedAt: string;
  /** The list icon, kept inside the entry. Without it the list shows the first letter. */
  icon?: EntryIcon;
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

export type VaultEntryType = "login" | "apiKey" | "creditCard" | "financial";
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
export type FinancialExtraSecret = { label: string; value: string };
export type FinancialEntry = AdditionalEntry & {
  type: "financial";
  financial: { loginId: string; loginPassword: string; tradingPassword: string; extraSecrets: FinancialExtraSecret[] };
};
export type VaultEntry = PasswordEntry | ApiKeyEntry | CreditCardEntry | FinancialEntry;
export type VaultEntrySummary = PasswordEntrySummary | (AdditionalEntrySummary & { type: "apiKey" }) |
  (AdditionalEntrySummary & { type: "creditCard"; cardLast4: string }) | (AdditionalEntrySummary & { type: "financial" });
export type VaultEntryUpsertPayload = PasswordEntryUpsertPayload |
  (AdditionalEntryPayload & { type: "apiKey"; apiKey: { key: string; keyId?: string; expiresOn?: string } }) |
  (AdditionalEntryPayload & { type: "creditCard"; card: { number: string; cardholder?: string; expiryMonth?: string; securityCode?: string } }) |
  (AdditionalEntryPayload & { type: "financial"; financial: { loginId: string; loginPassword: string; tradingPassword?: string; extraSecrets?: FinancialExtraSecret[] } });

/** The list icon of one entry. Colors and symbols are preset names; an image is a PNG data URL of at most 32 KB. */
export type EntryIcon =
  | { kind: "letter"; color: string }
  | { kind: "symbol"; symbol: string; color: string }
  | { kind: "image"; image: string };

/** group null removes the items from their group. */
export type EntriesGroupPayload = { ids: string[]; group: string | null };

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
  /** Only before setup: a vault of the legacy format is in the data folder, which this version cannot open. */
  legacyVaultFound?: boolean;
  maintenance?: VaultMaintenanceState;
};

export type VaultMaintenanceOperation = "rekey" | "reset" | "recover";
export type VaultMaintenanceState = {
  state: "ready" | "running" | "recovery-required";
  format: "v2" | "unknown";
  operation?: VaultMaintenanceOperation;
  recoveryOperation?: "rekey" | "reset";
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

export type VaultMetadataRecord = {
  id: number;
  passwordSalt: string;
  passwordVerifier: string;
  kdfParams: string;
  createdAt: string;
  updatedAt: string;
};

export type PasswordManagerDesktopApi = {
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
  fetchEntries: (sessionId: string) => Promise<{ items: VaultEntrySummary[] }>;
  fetchEntry: (id: string, sessionId: string) => Promise<VaultEntry>;
  createEntry: (payload: VaultEntryUpsertPayload, sessionId: string) => Promise<VaultEntry>;
  updateEntry: (id: string, payload: VaultEntryUpsertPayload, sessionId: string) => Promise<VaultEntry>;
  deleteEntry: (id: string, sessionId: string) => Promise<{ success: boolean }>;
  setEntriesGroup: (payload: EntriesGroupPayload, sessionId: string) => Promise<{ updatedCount: number }>;
  setEntryIcon: (id: string, icon: EntryIcon | null, sessionId: string) => Promise<VaultEntrySummary>;
  generatePassword: (options: PasswordGenerationOptions, sessionId: string) => Promise<PasswordGenerationResult>;
  copyText: (value: string, sessionId: string) => Promise<void>;
  minimizeWindow: () => Promise<void>;
  toggleMaximizeWindow: () => Promise<void>;
  closeWindow: () => Promise<void>;
  isWindowMaximized: () => Promise<boolean>;
};

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
