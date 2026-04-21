import type {
  PasswordGenerationOptions,
  PasswordGenerationResult,
  PasswordManagerDesktopApi,
  PasswordEntry,
  PasswordEntrySummary,
  PasswordEntryUpsertPayload,
  VaultSetupPayload,
  VaultStatus,
  VaultUnlockPayload
} from "@password-manager/shared/types";

type ApiErrorPayload = {
  error?: string;
};

function getDesktopApi(): PasswordManagerDesktopApi | null {
  if (typeof window === "undefined") {
    return null;
  }

  return window.passwordManager ?? null;
}

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
  const desktopApi = getDesktopApi();
  if (desktopApi) {
    return desktopApi.fetchVaultStatus();
  }

  return request<VaultStatus>("/vault/status");
}

export function setupVault(payload: VaultSetupPayload) {
  const desktopApi = getDesktopApi();
  if (desktopApi) {
    return desktopApi.setupVault(payload);
  }

  return request<VaultStatus>("/vault/setup", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export function unlockVault(payload: VaultUnlockPayload) {
  const desktopApi = getDesktopApi();
  if (desktopApi) {
    return desktopApi.unlockVault(payload);
  }

  return request<{ isUnlocked: boolean }>("/vault/unlock", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export function lockVault() {
  const desktopApi = getDesktopApi();
  if (desktopApi) {
    return desktopApi.lockVault();
  }

  return request<{ isUnlocked: boolean }>("/vault/lock", {
    method: "POST"
  });
}

export function fetchEntries() {
  const desktopApi = getDesktopApi();
  if (desktopApi) {
    return desktopApi.fetchEntries();
  }

  return request<{ items: PasswordEntrySummary[] }>("/entries");
}

export function fetchEntry(id: string) {
  const desktopApi = getDesktopApi();
  if (desktopApi) {
    return desktopApi.fetchEntry(id);
  }

  return request<PasswordEntry>(`/entries/${id}`);
}

export function createEntry(payload: PasswordEntryUpsertPayload) {
  const desktopApi = getDesktopApi();
  if (desktopApi) {
    return desktopApi.createEntry(payload);
  }

  return request<PasswordEntry>("/entries", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export function updateEntry(id: string, payload: PasswordEntryUpsertPayload) {
  const desktopApi = getDesktopApi();
  if (desktopApi) {
    return desktopApi.updateEntry(id, payload);
  }

  return request<PasswordEntry>(`/entries/${id}`, {
    method: "PUT",
    body: JSON.stringify(payload)
  });
}

export function deleteEntry(id: string) {
  const desktopApi = getDesktopApi();
  if (desktopApi) {
    return desktopApi.deleteEntry(id);
  }

  return request<{ success: boolean }>(`/entries/${id}`, {
    method: "DELETE"
  });
}

export function generatePassword(options: PasswordGenerationOptions = {}) {
  const desktopApi = getDesktopApi();
  if (desktopApi) {
    return desktopApi.generatePassword(options);
  }

  return request<PasswordGenerationResult>("/password/generate", {
    method: "POST",
    body: JSON.stringify(options)
  });
}

export async function copyText(value: string) {
  const desktopApi = getDesktopApi();

  if (desktopApi) {
    await desktopApi.copyText(value);
    return;
  }

  await navigator.clipboard.writeText(value);
}
