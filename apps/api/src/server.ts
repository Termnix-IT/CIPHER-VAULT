import { createServer } from "node:http";
import { getVaultStoragePath } from "./db/vault-context.js";
import { closeApplicationVault, getVaultMaintenanceState, openApplicationVault } from "./services/vault-maintenance-service.js";
import { router } from "./routes/router.js";
import { vaultSession } from "./services/vault-session.js";

const host = process.env.PASSWORD_MANAGER_API_HOST ?? "127.0.0.1";
const port = Number(process.env.PASSWORD_MANAGER_API_PORT ?? "3001");
if (process.argv.includes("--dev")) {
  process.env.PASSWORD_MANAGER_WEB_ORIGIN ??= "http://localhost:5173,http://127.0.0.1:5173";
}

openApplicationVault();
const server = createServer((request, response) => {
  void router(request, response);
});

server.listen(port, host, () => {
  if (getVaultMaintenanceState()?.state === "ready") console.log(`Using database at ${getVaultStoragePath()}`);
  else console.log("Vault recovery is required");
  console.log(`Password Manager API listening on http://${host}:${port}`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    vaultSession.lock();
    closeApplicationVault();
    server.close(() => {
      closeApplicationVault();
      process.exit(0);
    });
  });
}

server.once("error", () => {
  vaultSession.lock();
  closeApplicationVault();
  console.error("APIの待受を開始できませんでした");
  process.exitCode = 1;
});
