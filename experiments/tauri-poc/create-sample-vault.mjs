// Creates synthetic legacy and v2 vaults with the app's own TypeScript code, for trying the prototype.
// Requires `npm run build:api`. Writes only inside the new directory given as an argument.
import { existsSync } from "node:fs";
import path from "node:path";
import { compatibility, createMigratedFixture, v2Password } from "../../tests/v2-runtime-fixture.mjs";

const directory = process.argv[2];
if (!directory) throw new Error("Usage: node create-sample-vault.mjs <new-directory>");
if (existsSync(directory)) throw new Error("The directory must not exist yet");
const root = path.resolve(directory);
const { vaultId } = await createMigratedFixture(root);

const service = (file) => import(new URL(`../../apps/api/dist/apps/api/src/services/${file}`, import.meta.url).href);
const maintenance = await service("vault-maintenance-service.js");
const vault = await service("vault-service.js");
const entries = await service("entry-service.js");
maintenance.openApplicationVault({ dataDirectory: root });
try {
  await vault.unlockVault({ masterPassword: v2Password });
  await entries.createEntry({ type: "apiKey", serviceName: "合成APIキー", url: "https://api.example.test/", tags: ["合成"],
    apiKey: { key: "synthetic-api-key", keyId: "synthetic-key-id", expiresOn: "2029-12-31" } });
  await entries.createEntry({ type: "creditCard", serviceName: "合成カード",
    card: { number: "4111-1111 1111 1111", cardholder: "SYNTHETIC OWNER", expiryMonth: "2029-12", securityCode: "123" } });
  await entries.createEntry({ type: "financial", serviceName: "合成銀行", url: "https://bank.example.test/",
    financial: { loginId: "synthetic-contract", loginPassword: "synthetic-login", tradingPassword: "synthetic-trading", extraSecrets: [{ label: "第2暗証番号", value: "synthetic-extra" }] } });
  vault.lockVault();
} finally { maintenance.closeApplicationVault(); }

// The passwords are fixed synthetic test values from tests/.
console.log(JSON.stringify({ testOnly: true,
  legacy: { database: path.join(root, "password-manager.db"), password: compatibility.legacy.password },
  v2: { database: path.join(root, "vaults", vaultId, "vault.sqlite"), password: v2Password } }, null, 2));
