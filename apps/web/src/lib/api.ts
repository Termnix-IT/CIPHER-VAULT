import type {
  PasswordGenerationOptions,
  PasswordGenerationResult,
  PasswordEntry,
  PasswordEntrySummary,
  PasswordEntryUpsertPayload,
  VaultSetupPayload,
  VaultStatus,
  VaultUnlockPayload
} from "../../../../packages/shared/src/types";

type ApiErrorPayload = {
  error?: string;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    headers: {
      "Content-Type": "application/json"
    },
    ...init
  });

  if (!response.ok) {
    const payload = (await response.json().catch(() => ({}))) as ApiErrorPayload;
    throw new Error(payload.error ?? "リクエストに失敗しました");
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

export function fetchVaultStatus() {
  return request<VaultStatus>("/vault/status");
}

export function setupVault(payload: VaultSetupPayload) {
  return request<VaultStatus>("/vault/setup", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export function unlockVault(payload: VaultUnlockPayload) {
  return request<{ isUnlocked: boolean }>("/vault/unlock", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export function lockVault() {
  return request<{ isUnlocked: boolean }>("/vault/lock", {
    method: "POST"
  });
}

export function fetchEntries() {
  return request<{ items: PasswordEntrySummary[] }>("/entries");
}

export function fetchEntry(id: string) {
  return request<PasswordEntry>(`/entries/${id}`);
}

export function createEntry(payload: PasswordEntryUpsertPayload) {
  return request<PasswordEntry>("/entries", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export function updateEntry(id: string, payload: PasswordEntryUpsertPayload) {
  return request<PasswordEntry>(`/entries/${id}`, {
    method: "PUT",
    body: JSON.stringify(payload)
  });
}

export function deleteEntry(id: string) {
  return request<{ success: boolean }>(`/entries/${id}`, {
    method: "DELETE"
  });
}

export function generatePassword(options: PasswordGenerationOptions = {}) {
  return request<PasswordGenerationResult>("/password/generate", {
    method: "POST",
    body: JSON.stringify(options)
  });
}
