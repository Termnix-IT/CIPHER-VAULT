import { app, BrowserWindow, clipboard, dialog, ipcMain } from "electron";
import { existsSync, readFileSync } from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { registerUpdateHandlers } from "./update-service.js";
import { createSenderGuard, isTrustedRendererUrl } from "./renderer-security.js";
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
const assertTrustedSender = createSenderGuard(() => mainWindow, () => trustedRendererUrl);

type VaultServiceModule = {
  getVaultStatus: () => { isConfigured: boolean; isUnlocked: boolean };
  setupVault: (payload: VaultSetupPayload) => { isConfigured: boolean; isUnlocked: boolean };
  unlockVault: (payload: VaultUnlockPayload) => { isUnlocked: boolean };
  lockVault: () => { isUnlocked: boolean };
  resetVault: (payload: VaultResetPayload) => { isConfigured: boolean; isUnlocked: boolean };
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
  backup: Pick<import("@password-manager/shared/types").PasswordManagerDesktopApi, "exportBackup" | "restoreBackup">;
  audit: Pick<import("@password-manager/shared/types").PasswordManagerDesktopApi, "auditVault">;
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
    const request = http.get(targetUrl, (response) => {
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
  return path.join(__dirname, "preload.mjs");
}

async function importModule<T>(filePath: string) {
  if (!existsSync(filePath)) {
    throw new Error(`Required build output was not found: ${filePath}`);
  }

  return (await import(pathToFileURL(filePath).href)) as T;
}

async function loadAppServices(appRoot: string): Promise<AppServices> {
  process.env.PASSWORD_MANAGER_DATA_DIR = path.join(app.getPath("userData"), "data");

  const [vault, entries, password, backup, audit] = await Promise.all([
    importModule<VaultServiceModule>(getApiBuildPath(appRoot, "services/vault-service.js")),
    importModule<EntryServiceModule>(getApiBuildPath(appRoot, "services/entry-service.js")),
    importModule<PasswordServiceModule>(getApiBuildPath(appRoot, "services/password-service.js")),
    importModule<AppServices["backup"]>(getApiBuildPath(appRoot, "services/backup-service.js")),
    importModule<AppServices["audit"]>(getApiBuildPath(appRoot, "services/audit-service.js"))
  ]);

  return {
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
  function handle<T extends unknown[]>(channel: string, action: (...args: T) => unknown) {
    ipcMain.handle(channel, (event, ...args: T) => {
      assertTrustedSender(event);
      return invokeSafely(() => action(...args));
    });
  }
  handle("backup:export", services.backup.exportBackup);
  handle("backup:restore", services.backup.restoreBackup);
  handle("vault:audit", services.audit.auditVault);
  handle("vault:getStatus", services.vault.getVaultStatus);
  handle("vault:setup", services.vault.setupVault);
  handle("vault:unlock", services.vault.unlockVault);
  handle("vault:lock", services.vault.lockVault);
  handle("vault:reset", services.vault.resetVault);
  handle("entries:list", services.entries.listEntries);
  handle("entries:getById", services.entries.getEntryById);
  handle("entries:create", services.entries.createEntry);
  handle("entries:update", services.entries.updateEntry);
  handle("entries:delete", services.entries.deleteEntry);
  handle("password:generate", services.password.generatePassword);
  handle("clipboard:writeText", (value: string) => { clipboard.writeText(value); });
}

async function loadRenderer(window: BrowserWindow, appRoot: string) {
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

async function createMainWindow(appRoot: string) {
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
      sandbox: false,
      contextIsolation: true,
      nodeIntegration: false
    }
  });

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
  registerIpcHandlers(services);
  const version = app.isPackaged ? app.getVersion() : JSON.parse(readFileSync(path.join(appRoot, "package.json"), "utf8")).version as string;
  registerUpdateHandlers(() => mainWindow, () => { services.vault.lockVault(); }, version, assertTrustedSender);
  const { database } = await importModule<{ database: { open: boolean; close: () => void } }>(getApiBuildPath(appRoot, "db/database.js"));
  app.on("will-quit", () => {
    services.vault.lockVault();
    if (database.open) database.close();
  });
  await createMainWindow(appRoot);
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

    void createMainWindow(appRoot);
  }
});

void app.whenReady().then(() => bootstrap()).catch((error: Error) => {
  dialog.showErrorBox("Failed to launch PasswordManeger", error.message);
  app.quit();
});
