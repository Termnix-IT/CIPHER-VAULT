import { app, BrowserWindow, clipboard, ClipboardItem, dialog, ipcMain, powerMonitor, safeStorage, session } from "electron";
import { existsSync, readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { registerUpdateHandlers } from "./update-service.js";
import { createSenderGuard, isTrustedRendererUrl } from "./renderer-security.js";
import { attachVaultWindowLifecycle } from "./vault-lifecycle.js";
import { VaultPowerGuard } from "./vault-power-guard.js";
import { ExpiringClipboard } from "./expiring-clipboard.js";
import { createClipboardPort } from "./clipboard-port.js";
import { installRendererSessionSecurity } from "./renderer-session.js";
import { desktopPlatformCapabilities, desktopVaultDataDirectory } from "./desktop-platform.js";
import { localDevelopmentUrl } from "@password-manager/shared";
import { LocalConnections } from "./local-connections.js";
import { nativeTransportExecutable } from "./native-transport.js";
import { electronDeviceKeyProtector } from "./device-key-protector.js";
import { readSelectedPairingRequest, writeSelectedConnectionInfo } from "./local-pairing-files.js";
import { LocalPairingError } from "./local-pairing.js";
import { approvedCandidateSearch } from "./approved-candidate-search.js";
import type {
  PasswordGenerationOptions,
  VaultEntryUpsertPayload,
  VaultResetPayload,
  VaultSetupPayload,
  VaultUnlockPayload
} from "@password-manager/shared/types";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const rendererDevUrl = process.env.PASSWORD_MANAGER_RENDERER_URL ?? "http://localhost:5173";
const platformCapabilities = desktopPlatformCapabilities({ platform: process.platform, packaged: app.isPackaged, portable: Boolean(process.env.PORTABLE_EXECUTABLE_FILE) });

let mainWindow: BrowserWindow | null = null;
let trustedRendererUrl: string | null = null;
let appServices: AppServices | null = null;
let powerGuard: VaultPowerGuard | null = null;
let quitting = false;
let quitReady = false;
let localConnections: LocalConnections | undefined;
const protectedClipboard = new ExpiringClipboard(createClipboardPort(clipboard, (values) => new ClipboardItem(values)));
const assertTrustedSender = createSenderGuard(() => mainWindow, () => trustedRendererUrl);

type VaultServiceModule = {
  getVaultStatus: () => import("@password-manager/shared/types").VaultStatus;
  setupVault: (payload: VaultSetupPayload) => Promise<import("@password-manager/shared/types").VaultStatus>;
  unlockVault: (payload: VaultUnlockPayload) => Promise<import("@password-manager/shared/types").VaultStatus>;
  lockVault: (reason?: import("@password-manager/shared/types").VaultLockReason) => import("@password-manager/shared/types").VaultStatus;
  lockVaultForSession: (sessionId: unknown) => import("@password-manager/shared/types").VaultStatus;
  resetVault: (payload: VaultResetPayload) => import("@password-manager/shared/types").VaultStatus;
  recordVaultActivity: (sessionId: unknown) => import("@password-manager/shared/types").VaultStatus;
  onVaultState: (listener: (state: import("@password-manager/shared/types").VaultStatus) => void) => () => void;
};

type EntryServiceModule = {
  listEntries: () => { items: import("@password-manager/shared/types").VaultEntrySummary[] };
  getEntryById: (id: string) => import("@password-manager/shared/types").VaultEntry;
  createEntry: (payload: VaultEntryUpsertPayload) => import("@password-manager/shared/types").VaultEntry | Promise<import("@password-manager/shared/types").VaultEntry>;
  updateEntry: (
    id: string,
    payload: VaultEntryUpsertPayload
  ) => import("@password-manager/shared/types").VaultEntry | Promise<import("@password-manager/shared/types").VaultEntry>;
  deleteEntry: (id: string) => { success: boolean };
};

type PasswordServiceModule = {
  generatePassword: (
    options?: PasswordGenerationOptions
  ) => import("@password-manager/shared/types").PasswordGenerationResult;
};

type AppServices = {
  maintenance: {
    runVaultMaintenance: (payload: unknown, sessionId: unknown) => Promise<void>;
    waitForVaultMaintenance: () => Promise<void>;
    stopVaultMaintenance: () => void;
  };
  input: {
    requireArgumentCount: (args: unknown[], count: number) => void;
    parseClipboardText: (value: unknown) => string;
  };
  session: {
    withVaultSession: <T>(sessionId: unknown, action: (sessionId: string) => T | Promise<T>) => Promise<T>;
    vaultSession: { requireGeneration: (sessionId: unknown) => string; requireUnlocked: (sessionId?: string) => string;
      getState: () => import("@password-manager/shared/types").VaultSessionState;
      subscribe: (listener: (state: import("@password-manager/shared/types").VaultSessionState) => void) => () => void };
  };
  backup: {
    exportBackup: (payload: import("@password-manager/shared/types").BackupExportPayload) => Promise<import("@password-manager/shared/types").BackupFile>;
    restoreBackup: (payload: import("@password-manager/shared/types").BackupRestorePayload) => Promise<{ restoredCount: number }>;
  };
  audit: { auditVault: () => Promise<import("@password-manager/shared/types").SecurityAudit> };
  vault: VaultServiceModule;
  entries: EntryServiceModule;
  password: PasswordServiceModule;
};

function findWorkspaceRoot(startDirectory: string) {
  let currentDirectory = path.resolve(startDirectory);

  while (true) {
    const appsDirectory = path.join(currentDirectory, "apps");
    const packageJsonPath = path.join(currentDirectory, "package.json");

    if (
      existsSync(appsDirectory) &&
      existsSync(path.join(appsDirectory, "api")) &&
      existsSync(path.join(appsDirectory, "web")) &&
      existsSync(packageJsonPath)
    ) {
      return currentDirectory;
    }

    const parentDirectory = path.dirname(currentDirectory);

    if (parentDirectory === currentDirectory) {
      return null;
    }

    currentDirectory = parentDirectory;
  }
}

function getAppRoot() {
  if (app.isPackaged) {
    const packagedRoot = app.getAppPath();

    if (existsSync(path.join(packagedRoot, "apps"))) {
      return packagedRoot;
    }
  }

  return findWorkspaceRoot(process.cwd()) ?? findWorkspaceRoot(__dirname);
}

function getApiBuildPath(appRoot: string, relativePath: string) {
  return path.join(appRoot, "apps", "api", "dist", "apps", "api", "src", relativePath);
}

function getWebDistPath(appRoot: string) {
  return path.join(appRoot, "apps", "web", "dist");
}

function getWindowIconPath(appRoot: string) {
  return path.join(appRoot, "build", "icon.png");
}

function probeUrl(targetUrl: string) {
  return new Promise<boolean>((resolve) => {
    const transport = new URL(targetUrl).protocol === "https:" ? https : http;
    const request = transport.get(targetUrl, (response) => {
      response.resume();
      resolve((response.statusCode ?? 500) < 500);
    });

    request.on("error", () => resolve(false));
    request.setTimeout(1500, () => {
      request.destroy();
      resolve(false);
    });
  });
}

async function waitForUrl(targetUrl: string, timeoutMs: number) {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    if (await probeUrl(targetUrl)) {
      return true;
    }

    await new Promise((resolve) => setTimeout(resolve, 250));
  }

  return false;
}

function getPreloadPath() {
  return path.join(__dirname, "preload.cjs");
}

async function importModule<T>(filePath: string) {
  if (!existsSync(filePath)) {
    throw new Error(`Required build output was not found: ${filePath}`);
  }

  return (await import(pathToFileURL(filePath).href)) as T;
}

async function loadAppServices(appRoot: string): Promise<AppServices> {
  const [vault, entries, password, backup, audit, session, input, maintenance] = await Promise.all([
    importModule<VaultServiceModule>(getApiBuildPath(appRoot, "services/vault-service.js")),
    importModule<EntryServiceModule>(getApiBuildPath(appRoot, "services/entry-service.js")),
    importModule<PasswordServiceModule>(getApiBuildPath(appRoot, "services/password-service.js")),
    importModule<AppServices["backup"]>(getApiBuildPath(appRoot, "services/backup-service.js")),
    importModule<AppServices["audit"]>(getApiBuildPath(appRoot, "services/audit-service.js")),
    importModule<AppServices["session"]>(getApiBuildPath(appRoot, "services/vault-session.js")),
    importModule<AppServices["input"]>(getApiBuildPath(appRoot, "lib/input-validation.js")),
    importModule<AppServices["maintenance"]>(getApiBuildPath(appRoot, "services/vault-maintenance-service.js"))
  ]);

  return {
    maintenance,
    input,
    session,
    backup,
    audit,
    vault,
    entries,
    password
  };
}

async function invokeSafely<T>(action: () => Promise<T> | T) {
  try {
    return await action();
  } catch (error) {
    throw new Error(error instanceof Error ? error.message : "処理に失敗しました");
  }
}

function registerIpcHandlers(services: AppServices) {
  const assertAvailable = () => {
    if (quitting) throw new Error("アプリを終了しています");
    powerGuard?.assertAvailable();
  };
  function handle<T extends unknown[]>(channel: string, count: number, action: (...args: T) => unknown) {
    ipcMain.handle(channel, (event, ...args: T) => {
      assertTrustedSender(event);
      return invokeSafely(() => {
        services.input.requireArgumentCount(args, count);
        return action(...args);
      });
    });
  }
  function handleSession<T extends unknown[]>(channel: string, count: number, action: (...args: T) => unknown) {
    handle(channel, count + 1, (sessionId: unknown, ...args: T) => services.session.withVaultSession(sessionId, async () => {
      assertAvailable();
      const result = await action(...args);
      assertAvailable();
      return result;
    }));
  }
  function handleControl<T extends unknown[]>(channel: string, action: (...args: T) => unknown) {
    handle(channel, 2, (sessionId: unknown, ...args: T) => {
      assertAvailable();
      services.session.vaultSession.requireGeneration(sessionId);
      return action(...args);
    });
  }
  function connectionHandle(channel: string, count: number, action: (id: string, ...args: unknown[]) => unknown) {
    handle(channel, count + 1, (id: unknown, ...args: unknown[]) => services.session.withVaultSession(id, async sessionId => {
      assertAvailable(); if (!localConnections) throw new LocalPairingError();
      const result = await action(sessionId, ...args); assertAvailable(); return result;
    }));
  }
  const connections = () => { if (!localConnections) throw new LocalPairingError(); return localConnections; };
  const clientId = (value: unknown) => {
    if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)) throw new LocalPairingError(); return value;
  };
  const revision = (value: unknown) => { if (!Number.isInteger(value) || (value as number) < 0 || (value as number) >= 2147483647) throw new LocalPairingError(); return value as number; };
  connectionHandle("connections:state", 0, id => connections().state(id));
  connectionHandle("connections:enabled", 2, async (id, enabled, expected) => {
    if (typeof enabled !== "boolean") throw new LocalPairingError(); await connections().setEnabled(id, revision(expected), enabled); return connections().state(id);
  });
  connectionHandle("connections:select", 0, async id => {
    try {
      const selected = await dialog.showOpenDialog(mainWindow!, { title: "接続リクエストを選択", filters: [{ name: "CIPHER VAULT 接続リクエスト", extensions: ["cvpair"] }], properties: ["openFile", "dontAddToRecent", "noResolveAliases"] });
      services.session.vaultSession.requireUnlocked(id); assertAvailable();
      if (!selected.canceled && selected.filePaths.length === 1) connections().stage(id, readSelectedPairingRequest(selected.filePaths[0]));
      return connections().state(id);
    } catch { throw new LocalPairingError(); }
  });
  connectionHandle("connections:approve", 1, async (id, approval) => { await connections().approve(id, approval as import("@password-manager/shared/types").LocalPairingApproval); return connections().state(id); });
  connectionHandle("connections:cancel", 1, (id, pending) => { connections().cancel(id, clientId(pending)); return connections().state(id); });
  connectionHandle("connections:revoke", 2, async (id, client, expected) => { await connections().revoke(id, revision(expected), clientId(client)); return connections().state(id); });
  connectionHandle("connections:save", 1, async (id, client) => {
    try {
      const selectedId = clientId(client), selected = await dialog.showSaveDialog(mainWindow!, { title: "接続情報を保存", defaultPath: "cipher-vault.cvconnection", filters: [{ name: "CIPHER VAULT 接続情報", extensions: ["cvconnection"] }] });
      services.session.vaultSession.requireUnlocked(id); assertAvailable(); if (selected.canceled || !selected.filePath) return false;
      writeSelectedConnectionInfo(selected.filePath, connections().connectionInfo(id, selectedId)); return true;
    } catch { throw new LocalPairingError(); }
  });
  handleSession("backup:export", 1, services.backup.exportBackup);
  handleSession("backup:restore", 1, services.backup.restoreBackup);
  handleSession("vault:audit", 0, services.audit.auditVault);
  handle("vault:getStatus", 0, services.vault.getVaultStatus);
  handleControl("vault:setup", services.vault.setupVault);
  handleControl("vault:unlock", services.vault.unlockVault);
  // Lock intentionally ends the session; it must not use the post-return guard.
  handle("vault:lock", 1, services.vault.lockVaultForSession);
  handle("vault:activity", 1, (id: unknown) => { assertAvailable(); return services.vault.recordVaultActivity(id); });
  handleControl("vault:reset", services.vault.resetVault);
  handle("vault:maintenance", 2, async (sessionId: unknown, payload: unknown) => {
    assertAvailable(); services.session.vaultSession.requireGeneration(sessionId);
    await services.maintenance.runVaultMaintenance(payload, sessionId);
    assertAvailable(); return services.vault.getVaultStatus();
  });
  handleSession("entries:list", 0, services.entries.listEntries);
  handleSession("entries:getById", 1, services.entries.getEntryById);
  handleSession("entries:create", 1, services.entries.createEntry);
  handleSession("entries:update", 2, services.entries.updateEntry);
  handleSession("entries:delete", 1, services.entries.deleteEntry);
  handleSession("password:generate", 1, services.password.generatePassword);
  handle("clipboard:writeText", 2, (id: unknown, value: unknown) => services.session.withVaultSession(id, (session) => {
    assertAvailable();
    const text = services.input.parseClipboardText(value);
    return protectedClipboard.copy(text, () => {
      assertAvailable();
      services.session.vaultSession.requireUnlocked(session);
    });
  }));
}

async function loadRenderer(window: BrowserWindow, appRoot: string) {
  if (!app.isPackaged) localDevelopmentUrl(rendererDevUrl);
  if (!app.isPackaged && await waitForUrl(rendererDevUrl, 15000)) {
    trustedRendererUrl = new URL(rendererDevUrl).href;
    await window.loadURL(rendererDevUrl);
    return;
  }

  const webDistPath = getWebDistPath(appRoot);
  const indexPath = path.join(webDistPath, "index.html");

  if (!existsSync(indexPath)) {
    throw new Error(`Web build output was not found: ${indexPath}`);
  }

  trustedRendererUrl = pathToFileURL(indexPath).href;
  await window.loadFile(indexPath);
}

async function createMainWindow(appRoot: string, services: AppServices) {
  if (mainWindow) {
    mainWindow.focus();
    return;
  }

  const iconPath = getWindowIconPath(appRoot);

  mainWindow = new BrowserWindow({
    width: 1200,
    height: 780,
    minWidth: 1000,
    minHeight: 680,
    autoHideMenuBar: true,
    backgroundColor: "#121416",
    icon: existsSync(iconPath) ? iconPath : undefined,
    titleBarStyle: "hidden",
    titleBarOverlay: {
      color: "#121416",
      symbolColor: "#9ba3ab",
      height: 38
    },
    webPreferences: {
      preload: getPreloadPath(),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  attachVaultWindowLifecycle(mainWindow, (reason) => { services.vault.lockVault(reason); });
  mainWindow.on("closed", () => {
    mainWindow = null;
    trustedRendererUrl = null;
  });

  mainWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  mainWindow.webContents.on("will-frame-navigate", (event) => {
    if (!event.isMainFrame || !isTrustedRendererUrl(event.url, trustedRendererUrl)) event.preventDefault();
  });
  mainWindow.webContents.on("will-redirect", (event) => {
    if (!event.isMainFrame || !isTrustedRendererUrl(event.url, trustedRendererUrl)) event.preventDefault();
  });
  mainWindow.webContents.on("will-attach-webview", (event) => event.preventDefault());

  await loadRenderer(mainWindow, appRoot);
}

async function bootstrap() {
  const appRoot = getAppRoot();

  if (!appRoot) {
    throw new Error("Application root was not found");
  }

  process.env.PASSWORD_MANAGER_DATA_DIR = desktopVaultDataDirectory(app);
  const storage = await importModule<{ openApplicationVault: () => void; closeApplicationVault: () => void }>(getApiBuildPath(appRoot, "services/vault-maintenance-service.js"));
  storage.openApplicationVault();
  // Register cleanup before loading services or the renderer, including failed startup.
  app.on("will-quit", () => {
    try {
      powerGuard?.dispose();
    } finally { storage.closeApplicationVault(); }
  });
  const services = await loadAppServices(appRoot);
  appServices = services;
  localConnections = new LocalConnections(app.getPath("userData"), nativeTransportExecutable({ packaged: app.isPackaged, resourcesPath: process.resourcesPath, workspaceRoot: appRoot }),
    electronDeviceKeyProtector(app, safeStorage), services.session.vaultSession, approvedCandidateSearch({
      requireUnlocked: expected => services.session.vaultSession.requireUnlocked(expected),
      list: () => services.entries.listEntries(), detail: id => services.entries.getEntryById(id),
      async confirm(input) {
        if (!mainWindow || mainWindow.isDestroyed()) return false;
        mainWindow.show(); mainWindow.focus();
        const result = await dialog.showMessageBox(mainWindow, { type: "question", title: "MCPの候補検索", message: `${input.displayName} が保管庫の候補検索を要求しています`,
          detail: `検索語: ${input.query}\n\n一致した候補を最大20件返します。返す情報は候補ID・サービス名・サイトのoriginだけです。パスワード、メモ、ログインIDは返しません。今回の検索だけを許可します。`,
          buttons: ["拒否", "今回だけ検索を許可"], defaultId: 0, cancelId: 0, noLink: true });
        return result.response === 1;
      }
    }));
  app.on("will-quit", () => { void localConnections?.close(); });
  installRendererSessionSecurity(session.defaultSession, () => mainWindow?.webContents.id ?? null,
    () => trustedRendererUrl, getWebDistPath(appRoot));
  registerIpcHandlers(services);
  services.vault.onVaultState((state) => {
    if (!state.isUnlocked) void protectedClipboard.clearOwned().then((cleared) => {
      if (!cleared) console.warn("クリップボードの消去を完了できませんでした");
    });
    if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.webContents.isDestroyed() && !mainWindow.webContents.isCrashed()) {
      mainWindow.webContents.send("vault:state", state);
    }
  });
  powerGuard = new VaultPowerGuard(powerMonitor, (reason) => { services.vault.lockVault(reason); });
  const version = app.isPackaged ? app.getVersion() : JSON.parse(readFileSync(path.join(appRoot, "package.json"), "utf8")).version as string;
  registerUpdateHandlers(() => mainWindow, () => { services.vault.lockVault("update"); }, version, assertTrustedSender, platformCapabilities.inAppUpdates);
  app.on("before-quit", (event) => {
    if (quitReady) return;
    event.preventDefault();
    if (quitting) return;
    quitting = true;
    services.vault.lockVault();
    services.maintenance.stopVaultMaintenance();
    let timer: ReturnType<typeof setTimeout> | undefined;
    // Clipboard APIs can be unavailable; never hold application exit indefinitely.
    void Promise.race([
      Promise.all([protectedClipboard.clearOwned(), services.maintenance.waitForVaultMaintenance(), localConnections?.close()]),
      new Promise((resolve) => { timer = setTimeout(resolve, 1500); })
    ]).finally(() => { clearTimeout(timer); quitReady = true; app.quit(); });
  });
  await createMainWindow(appRoot, services);
}

app.on("window-all-closed", () => {
  if (!platformCapabilities.keepAliveAfterLastWindow) {
    app.quit();
  }
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    const appRoot = getAppRoot();

    if (!appRoot) {
      dialog.showErrorBox("Failed to activate PasswordManeger", "Application root was not found");
      return;
    }

    if (appServices) void createMainWindow(appRoot, appServices);
  }
});

void app.whenReady().then(() => bootstrap()).catch((error: Error) => {
  dialog.showErrorBox("Failed to launch PasswordManeger", error.message);
  app.quit();
});
