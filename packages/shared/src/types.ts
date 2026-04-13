export type PasswordEntrySummary = {
  id: string;
  serviceName: string;
  loginId: string;
  tags: string[];
  group: string | null;
  updatedAt: string;
};

export type PasswordEntry = PasswordEntrySummary & {
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

export type VaultMetadataRecord = {
  id: number;
  passwordSalt: string;
  passwordVerifier: string;
  kdfParams: string;
  createdAt: string;
  updatedAt: string;
};
