// Test-only native-dialog boundary. The production dispatcher, host role and message handler run unchanged.
import { app, dialog, BrowserWindow } from "electron";
import assert from "node:assert/strict";
import path from "node:path";
import { tmpdir } from "node:os";
const root = process.env.CIPHER_VAULT_TEST_ROOT, action = process.env.CIPHER_VAULT_BROWSER_FIXTURE;
const relative = path.relative(tmpdir(), root ?? "");
assert.ok(relative.startsWith("cv-browser-host-") && !relative.includes(path.sep));
assert.ok(["prepare", "import", "cancel", "reset", "reset-cancel"].includes(action));
app.on("browser-window-created", () => { console.error("FAIL unexpected Vault window in client role"); app.exit(1); });
app.on("ready", () => assert.equal(BrowserWindow.getAllWindows().length, 0));
dialog.showSaveDialog = async () => ({ canceled: action === "cancel", filePath: path.join(root, "synthetic.cvpair") });
dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [path.join(root, "synthetic.cvconnection")] });
dialog.showMessageBox = async () => ({ response: action === "reset" ? 1 : 0, checkboxChecked: false });
dialog.showErrorBox = () => { console.error("FAIL client dispatcher fell back to desktop"); app.exit(1); };
void import("../apps/electron/dist/apps/electron/src/main.js");
