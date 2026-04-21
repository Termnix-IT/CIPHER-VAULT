import { createServer } from "node:http";
import { getDatabasePath } from "./db/database.js";
import { router } from "./routes/router.js";

const host = process.env.PASSWORD_MANAGER_API_HOST ?? "127.0.0.1";
const port = Number(process.env.PASSWORD_MANAGER_API_PORT ?? "3001");

const server = createServer((request, response) => {
  void router(request, response);
});

server.listen(port, host, () => {
  console.log(`Using database at ${getDatabasePath()}`);
  console.log(`Password Manager API listening on http://${host}:${port}`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    server.close(() => {
      process.exit(0);
    });
  });
}
