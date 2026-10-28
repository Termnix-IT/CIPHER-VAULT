export type PasswordEntrySummary = {
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
  fetchEntries: (sessionId: string) => Promise<{ items: PasswordEntrySummary[] }>;
  fetchEntry: (id: string, sessionId: string) => Promise<PasswordEntry>;
  createEntry: (payload: PasswordEntryUpsertPayload, sessionId: string) => Promise<PasswordEntry>;
  updateEntry: (id: string, payload: PasswordEntryUpsertPayload, sessionId: string) => Promise<PasswordEntry>;
  deleteEntry: (id: string, sessionId: string) => Promise<{ success: boolean }>;
  generatePassword: (options: PasswordGenerationOptions, sessionId: string) => Promise<PasswordGenerationResult>;
  copyText: (value: string, sessionId: string) => Promise<void>;
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
