import { createServer } from "node:http";
import { closeDatabase, getDatabasePath, openDatabase } from "./db/database.js";
import { router } from "./routes/router.js";
import { vaultSession } from "./services/vault-session.js";

const host = process.env.PASSWORD_MANAGER_API_HOST ?? "127.0.0.1";
const port = Number(process.env.PASSWORD_MANAGER_API_PORT ?? "3001");
if (process.argv.includes("--dev")) {
  process.env.PASSWORD_MANAGER_WEB_ORIGIN ??= "http://localhost:5173,http://127.0.0.1:5173";
}

openDatabase();
const server = createServer((request, response) => {
  void router(request, response);
});

server.listen(port, host, () => {
  console.log(`Using database at ${getDatabasePath()}`);
  console.log(`Password Manager API listening on http://${host}:${port}`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    vaultSession.lock();
    server.close(() => {
      closeDatabase();
      process.exit(0);
    });
  });
}

server.once("error", () => {
  vaultSession.lock();
  closeDatabase();
  console.error("APIの待受を開始できませんでした");
  process.exitCode = 1;
});
