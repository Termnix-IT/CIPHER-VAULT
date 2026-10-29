import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

assert.equal(process.argv.length, 2, "Build the native transport on its target OS without arguments");
const platforms = { win32: "win", linux: "linux", darwin: "osx" };
assert.ok(Object.hasOwn(platforms, process.platform) && ["x64", "arm64"].includes(process.arch), "Unsupported native transport target");
const root = fileURLToPath(new URL("../", import.meta.url)), project = path.join(root, "native/local-transport");
const target = `${process.platform}-${process.arch}`, runtime = `${platforms[process.platform]}-${process.arch}`;
const output = path.join(root, "dist-desktop/native-transport", target), intermediate = path.join(root, "dist-desktop/native-transport-build", target);
const cache = path.join(root, "dist-desktop/native-transport-cache");
for (const directory of [output, intermediate, cache]) mkdirSync(directory, { recursive: true });
const env = { ...process.env, DOTNET_CLI_HOME: path.join(cache, "cli"), NUGET_PACKAGES: path.join(cache, "packages"),
  DOTNET_CLI_TELEMETRY_OPTOUT: "1", DOTNET_NOLOGO: "1", DOTNET_GENERATE_ASPNET_CERTIFICATE: "false", DOTNET_ADD_GLOBAL_TOOLS_TO_PATH: "false" };
function run(command, args) {
  const result = spawnSync(command, args, { cwd: project, env, stdio: "inherit", windowsHide: true });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
const native = [];
if (process.platform !== "win32") {
  const object = path.join(intermediate, "unix-os.o"), archive = path.join(intermediate, "libtransportos.a");
  run("clang", ["-O2", "-fPIC", "-Wall", "-Wextra", "-Werror", ...(process.platform === "darwin" ? ["-arch", process.arch === "arm64" ? "arm64" : "x86_64"] : []), "-c", "unix-os.c", "-o", object]);
  run("ar", ["rcs", archive, object]); native.push(`-p:NativeOsLibrary=${archive}`);
}
const version = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")).version;
run("dotnet", ["publish", "Transport.csproj", "-r", runtime, "-c", "Release", "--self-contained", "true", "-o", output,
  `-p:BaseIntermediateOutputPath=${intermediate}${path.sep}`, `-p:BaseOutputPath=${path.join(intermediate, "managed")}${path.sep}`, "-p:UseSharedCompilation=false", `-p:Version=${version}`, ...native]);
const assets = JSON.parse(readFileSync(path.join(intermediate, "project.assets.json"), "utf8"));
const dependency = assets.project.frameworks["net10.0"].downloadDependencies.find(value => value.name === `Microsoft.NETCore.App.Runtime.NativeAOT.${runtime}`);
assert.match(dependency?.version ?? "", /^\[([0-9.]+), \1\]$/);
const runtimeVersion = dependency.version.slice(1, dependency.version.indexOf(","));
const runtimePackage = path.join(env.NUGET_PACKAGES, dependency.name.toLowerCase(), runtimeVersion);
for (const file of ["LICENSE.TXT", "THIRD-PARTY-NOTICES.TXT"]) copyFileSync(path.join(runtimePackage, file), path.join(output, file));
const binary = process.platform === "win32" ? "cipher-vault-transport.exe" : "cipher-vault-transport";
writeFileSync(path.join(output, "native-transport.json"), JSON.stringify({ protocol: 1, platform: process.platform, arch: process.arch, version, runtimeVersion,
  sha256: createHash("sha256").update(readFileSync(path.join(output, binary))).digest("hex") }) + "\n");
