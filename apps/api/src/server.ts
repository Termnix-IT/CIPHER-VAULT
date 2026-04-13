import { createServer } from "node:http";
import { getDatabasePath } from "./db/database.js";
import { router } from "./routes/router.js";

const port = 3001;

const server = createServer((request, response) => {
  void router(request, response);
});

server.listen(port, () => {
  console.log(`Using database at ${getDatabasePath()}`);
  console.log(`Password Manager API listening on http://localhost:${port}`);
});
