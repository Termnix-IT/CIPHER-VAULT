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

export type VaultStatus = {
  isConfigured: boolean;
  isUnlocked: boolean;
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
  exportBackup: (payload: BackupExportPayload) => Promise<BackupFile>;
  restoreBackup: (payload: BackupRestorePayload) => Promise<{ restoredCount: number }>;
  auditVault: () => Promise<SecurityAudit>;
  getUpdateState: () => Promise<AppUpdateState>;
  checkForUpdates: () => Promise<void>;
  downloadUpdate: () => Promise<void>;
  installUpdate: (hasUnsavedChanges: boolean) => Promise<false | void>;
  openReleasePage: () => Promise<void>;
  onUpdateState: (listener: (state: AppUpdateState) => void) => () => void;
  fetchVaultStatus: () => Promise<VaultStatus>;
  setupVault: (payload: VaultSetupPayload) => Promise<VaultStatus>;
  unlockVault: (payload: VaultUnlockPayload) => Promise<{ isUnlocked: boolean }>;
  lockVault: () => Promise<{ isUnlocked: boolean }>;
  resetVault: (payload: VaultResetPayload) => Promise<VaultStatus>;
  fetchEntries: () => Promise<{ items: PasswordEntrySummary[] }>;
  fetchEntry: (id: string) => Promise<PasswordEntry>;
  createEntry: (payload: PasswordEntryUpsertPayload) => Promise<PasswordEntry>;
  updateEntry: (id: string, payload: PasswordEntryUpsertPayload) => Promise<PasswordEntry>;
  deleteEntry: (id: string) => Promise<{ success: boolean }>;
  generatePassword: (options?: PasswordGenerationOptions) => Promise<PasswordGenerationResult>;
  copyText: (value: string) => Promise<void>;
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
