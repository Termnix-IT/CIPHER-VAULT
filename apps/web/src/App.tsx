import { useEffect, useRef, useState } from "react";
import type {
  PasswordEntry,
  PasswordEntrySummary,
  PasswordEntryUpsertPayload,
  VaultStatus
} from "../../../packages/shared/src/types";
import {
  createEntry,
  deleteEntry,
  fetchEntries,
  fetchEntry,
  fetchVaultStatus,
  generatePassword,
  lockVault,
  setupVault,
  unlockVault,
  updateEntry
} from "./lib/api";
import { LockScreen } from "./pages/LockScreen";
import { VaultDashboard } from "./pages/VaultDashboard";

const AUTO_LOCK_TIMEOUT_MS = 5 * 60 * 1000;

export function App() {
  const [vaultStatus, setVaultStatus] = useState<VaultStatus | null>(null);
  const [entries, setEntries] = useState<PasswordEntrySummary[]>([]);
  const [selectedEntry, setSelectedEntry] = useState<PasswordEntry | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isLoadingEntries, setIsLoadingEntries] = useState(false);
  const [isCreatingEntry, setIsCreatingEntry] = useState(false);
  const [isUpdatingEntry, setIsUpdatingEntry] = useState(false);
  const [isDeletingEntry, setIsDeletingEntry] = useState(false);
  const [isLoadingEntryDetail, setIsLoadingEntryDetail] = useState(false);
  const [isGeneratingPassword, setIsGeneratingPassword] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [copyMessage, setCopyMessage] = useState("");
  const autoLockTimerRef = useRef<number | null>(null);

  useEffect(() => {
    void refreshVaultStatus();
  }, []);

  useEffect(() => {
    if (!vaultStatus?.isUnlocked) {
      clearAutoLockTimer();
      return;
    }

    const handleActivity = () => {
      scheduleAutoLock();
    };

    scheduleAutoLock();

    window.addEventListener("pointerdown", handleActivity);
    window.addEventListener("keydown", handleActivity);
    window.addEventListener("mousemove", handleActivity);
    window.addEventListener("scroll", handleActivity);

    return () => {
      clearAutoLockTimer();
      window.removeEventListener("pointerdown", handleActivity);
      window.removeEventListener("keydown", handleActivity);
      window.removeEventListener("mousemove", handleActivity);
      window.removeEventListener("scroll", handleActivity);
    };
  }, [vaultStatus?.isUnlocked]);

  async function refreshVaultStatus() {
    try {
      setErrorMessage("");
      const status = await fetchVaultStatus();
      setVaultStatus(status);

      if (status.isUnlocked) {
        await refreshEntries();
      } else {
        setEntries([]);
        setSelectedEntry(null);
      }
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "保管庫の状態を読み込めませんでした");
    }
  }

  async function refreshEntries() {
    try {
      setIsLoadingEntries(true);
      const response = await fetchEntries();
      setEntries(response.items);
      setSelectedEntry((current) => {
        if (!current) {
          return null;
        }

        return response.items.some((entry) => entry.id === current.id) ? current : null;
      });
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "エントリ一覧を読み込めませんでした");
    } finally {
      setIsLoadingEntries(false);
    }
  }

  async function handleVaultSubmit(masterPassword: string) {
    try {
      setIsSubmitting(true);
      setErrorMessage("");

      if (vaultStatus?.isConfigured) {
        await unlockVault({ masterPassword });
      } else {
        await setupVault({ masterPassword });
      }

      await refreshVaultStatus();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "保管庫の操作に失敗しました");
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleLockVault() {
    try {
      clearAutoLockTimer();
      setErrorMessage("");
      await lockVault();
      await refreshVaultStatus();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "保管庫をロックできませんでした");
    }
  }

  async function handleCreateEntry(payload: PasswordEntryUpsertPayload) {
    try {
      setIsCreatingEntry(true);
      setErrorMessage("");
      const created = await createEntry(payload);
      setSelectedEntry(created);
      await refreshEntries();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "エントリを作成できませんでした");
      throw error;
    } finally {
      setIsCreatingEntry(false);
    }
  }

  async function handleSelectEntry(id: string) {
    try {
      setIsLoadingEntryDetail(true);
      setErrorMessage("");
      const entry = await fetchEntry(id);
      setSelectedEntry(entry);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "エントリ詳細を読み込めませんでした");
    } finally {
      setIsLoadingEntryDetail(false);
    }
  }

  async function handleUpdateEntry(id: string, payload: PasswordEntryUpsertPayload) {
    try {
      setIsUpdatingEntry(true);
      setErrorMessage("");
      const updated = await updateEntry(id, payload);
      setSelectedEntry(updated);
      await refreshEntries();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "エントリを更新できませんでした");
      throw error;
    } finally {
      setIsUpdatingEntry(false);
    }
  }

  async function handleDeleteEntry(id: string) {
    try {
      setIsDeletingEntry(true);
      setErrorMessage("");
      await deleteEntry(id);
      setSelectedEntry(null);
      await refreshEntries();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "エントリを削除できませんでした");
      throw error;
    } finally {
      setIsDeletingEntry(false);
    }
  }

  async function handleGeneratePassword() {
    try {
      setIsGeneratingPassword(true);
      setErrorMessage("");
      const result = await generatePassword({
        length: 20,
        includeUppercase: true,
        includeLowercase: true,
        includeNumbers: true,
        includeSymbols: true
      });

      return result.password;
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "パスワードを生成できませんでした");
      throw error;
    } finally {
      setIsGeneratingPassword(false);
    }
  }

  async function handleCopyToClipboard(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopyMessage(`${label}をコピーしました`);
      window.setTimeout(() => {
        setCopyMessage("");
      }, 2000);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "クリップボードへコピーできませんでした");
      throw error;
    }
  }

  async function autoLockVault() {
    try {
      clearAutoLockTimer();
      await lockVault();
      setCopyMessage("");
      setErrorMessage("5分間操作がなかったため保管庫をロックしました");
      await refreshVaultStatus();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "自動ロックに失敗しました");
    }
  }

  function scheduleAutoLock() {
    clearAutoLockTimer();
    autoLockTimerRef.current = window.setTimeout(() => {
      void autoLockVault();
    }, AUTO_LOCK_TIMEOUT_MS);
  }

  function clearAutoLockTimer() {
    if (autoLockTimerRef.current !== null) {
      window.clearTimeout(autoLockTimerRef.current);
      autoLockTimerRef.current = null;
    }
  }

  if (vaultStatus === null) {
    return (
      <main className="app-shell">
        <div className="cipher-auth-shell">
          <p className="loading-text">&gt; 保管庫を読み込み中...</p>
        </div>
      </main>
    );
  }

  return (
    <main className="app-shell">
      {vaultStatus.isUnlocked ? (
        <VaultDashboard
          entries={entries}
          isLoading={isLoadingEntries}
          isCreating={isCreatingEntry}
          isUpdating={isUpdatingEntry}
          isDeleting={isDeletingEntry}
          isLoadingDetail={isLoadingEntryDetail}
          isGeneratingPassword={isGeneratingPassword}
          selectedEntry={selectedEntry}
          errorMessage={errorMessage}
          copyMessage={copyMessage}
          onLock={handleLockVault}
          onRefresh={refreshEntries}
          onCreateEntry={handleCreateEntry}
          onSelectEntry={handleSelectEntry}
          onUpdateEntry={handleUpdateEntry}
          onDeleteEntry={handleDeleteEntry}
          onGeneratePassword={handleGeneratePassword}
          onCopyToClipboard={handleCopyToClipboard}
        />
      ) : (
        <LockScreen
          isConfigured={vaultStatus.isConfigured}
          isSubmitting={isSubmitting}
          errorMessage={errorMessage}
          onSubmit={handleVaultSubmit}
        />
      )}
    </main>
  );
}
