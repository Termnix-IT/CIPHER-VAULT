import { app, BrowserWindow, clipboard, ClipboardItem, dialog, ipcMain, powerMonitor, session } from "electron";
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
import { localDevelopmentUrl } from "@password-manager/shared";
import type {
  PasswordGenerationOptions,
  PasswordEntryUpsertPayload,
  VaultResetPayload,
  VaultSetupPayload,
  VaultUnlockPayload
} from "@password-manager/shared/types";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const rendererDevUrl = process.env.PASSWORD_MANAGER_RENDERER_URL ?? "http://localhost:5173";

let mainWindow: BrowserWindow | null = null;
let trustedRendererUrl: string | null = null;
let appServices: AppServices | null = null;
let powerGuard: VaultPowerGuard | null = null;
let quitting = false;
let quitReady = false;
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
  listEntries: () => { items: import("@password-manager/shared/types").PasswordEntrySummary[] };
  getEntryById: (id: string) => import("@password-manager/shared/types").PasswordEntry;
  createEntry: (payload: PasswordEntryUpsertPayload) => import("@password-manager/shared/types").PasswordEntry;
  updateEntry: (
    id: string,
    payload: PasswordEntryUpsertPayload
  ) => import("@password-manager/shared/types").PasswordEntry;
  deleteEntry: (id: string) => { success: boolean };
};

type PasswordServiceModule = {
  generatePassword: (
    options?: PasswordGenerationOptions
  ) => import("@password-manager/shared/types").PasswordGenerationResult;
};

type AppServices = {
  input: {
    requireArgumentCount: (args: unknown[], count: number) => void;
    parseClipboardText: (value: unknown) => string;
  };
  session: {
    withVaultSession: <T>(sessionId: unknown, action: (sessionId: string) => T | Promise<T>) => Promise<T>;
    vaultSession: { requireGeneration: (sessionId: unknown) => string; requireUnlocked: (sessionId?: string) => string };
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
  process.env.PASSWORD_MANAGER_DATA_DIR = path.join(app.getPath("userData"), "data");

  const [vault, entries, password, backup, audit, session, input] = await Promise.all([
    importModule<VaultServiceModule>(getApiBuildPath(appRoot, "services/vault-service.js")),
    importModule<EntryServiceModule>(getApiBuildPath(appRoot, "services/entry-service.js")),
    importModule<PasswordServiceModule>(getApiBuildPath(appRoot, "services/password-service.js")),
    importModule<AppServices["backup"]>(getApiBuildPath(appRoot, "services/backup-service.js")),
    importModule<AppServices["audit"]>(getApiBuildPath(appRoot, "services/audit-service.js")),
    importModule<AppServices["session"]>(getApiBuildPath(appRoot, "services/vault-session.js")),
    importModule<AppServices["input"]>(getApiBuildPath(appRoot, "lib/input-validation.js"))
  ]);

  return {
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
    backgroundColor: "#08111d",
    icon: existsSync(iconPath) ? iconPath : undefined,
    titleBarStyle: "hidden",
    titleBarOverlay: {
      color: "#010a0f",
      symbolColor: "#00ffff",
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

  const services = await loadAppServices(appRoot);
  appServices = services;
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
  registerUpdateHandlers(() => mainWindow, () => { services.vault.lockVault("update"); }, version, assertTrustedSender);
  const { database } = await importModule<{ database: { open: boolean; close: () => void } }>(getApiBuildPath(appRoot, "db/database.js"));
  app.on("before-quit", (event) => {
    if (quitReady) return;
    event.preventDefault();
    if (quitting) return;
    quitting = true;
    services.vault.lockVault();
    let timer: ReturnType<typeof setTimeout> | undefined;
    // Clipboard APIs can be unavailable; never hold application exit indefinitely.
    void Promise.race([
      protectedClipboard.clearOwned(),
      new Promise((resolve) => { timer = setTimeout(resolve, 1500); })
    ]).finally(() => { clearTimeout(timer); quitReady = true; app.quit(); });
  });
  app.on("will-quit", () => {
    powerGuard?.dispose();
    services.vault.lockVault();
    if (database.open) database.close();
  });
  await createMainWindow(appRoot, services);
}

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
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
