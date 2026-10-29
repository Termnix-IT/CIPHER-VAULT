// Synthetic, disposable credentials for source and packaged integration tests only.
import assert from "node:assert/strict";
import { mkdtempSync, realpathSync, chmodSync, rmSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";

function openssl() {
  if (spawnSync("openssl", ["version"], { windowsHide: true, stdio: "ignore" }).status === 0) return "openssl";
  const git = spawnSync("git", ["--exec-path"], { windowsHide: true, encoding: "utf8" });
  const candidate = path.resolve(git.stdout.trim(), "../../../usr/bin/openssl.exe");
  assert.ok(process.platform === "win32" && git.status === 0 && existsSync(candidate), "OpenSSL is required for synthetic test certificates");
  return candidate;
}
export function createLocalAuthFixture(executable) {
  const directory = mkdtempSync(path.join(realpathSync(tmpdir()), "cv-auth-")), identities = [];
  if (process.platform !== "win32") chmodSync(directory, 0o700);
  const options = { executable, endpoint: process.platform === "win32" ? `\\\\.\\pipe\\cipher-vault-${randomUUID()}` : path.join(directory, "transport.sock") };
  const config = path.join(directory, "openssl.cnf");
  writeFileSync(config, "[req]\ndistinguished_name=dn\n[dn]\nCN=cipher-vault.local\n[ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyCertSign\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:cipher-vault.local\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n");
  const sources = new WeakMap();
  function identity(name, issuer) {
    const command = openssl();
    const key = path.join(directory, name + ".key"), certificate = path.join(directory, name + ".crt");
    const commands = [["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key]];
    if (issuer) {
      const parent = sources.get(issuer), csr = path.join(directory, name + ".csr"); assert.ok(parent);
      commands.push(["req", "-new", "-key", key, "-out", csr, "-subj", "/CN=cipher-vault.local", "-config", config]);
      commands.push(["x509", "-req", "-in", csr, "-CA", parent.certificate, "-CAkey", parent.key, "-CAcreateserial", "-days", "1", "-sha256", "-out", certificate, "-extfile", config, "-extensions", "ext"]);
    } else commands.push(["req", "-new", "-x509", "-sha256", "-days", "1", "-key", key, "-out", certificate, "-subj", "/CN=cipher-vault.local", "-config", config, "-extensions", "ext"]);
    for (const args of commands) {
      const result = spawnSync(command, args, { windowsHide: true, encoding: "utf8", timeout: 10000 });
      assert.equal(result.status, 0, result.stderr);
    }
    if (issuer) for (const purpose of ["sslclient", "sslserver"]) {
      const verified = spawnSync(command, ["verify", "-CAfile", sources.get(issuer).certificate, "-purpose", purpose, certificate], { windowsHide: true, encoding: "utf8", timeout: 10000 });
      assert.equal(verified.status, 0, "Sibling certificate must pass normal chain validation: " + verified.stderr);
    }
    const value = { certificate: readFileSync(certificate), privateKey: readFileSync(key) }; identities.push(value); sources.set(value, { key, certificate }); return value;
  }
  return { options, identity, dispose() { for (const value of identities) value.privateKey.fill(0);
    assert.equal(path.dirname(directory), realpathSync(tmpdir())); assert.ok(path.basename(directory).startsWith("cv-auth-")); rmSync(directory, { recursive: true, force: true }); } };
}
