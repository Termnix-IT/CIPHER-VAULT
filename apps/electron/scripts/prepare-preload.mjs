import { readFileSync, writeFileSync, rmSync } from "node:fs";
import ts from "typescript";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const distDirectory = path.resolve(__dirname, "../dist/apps/electron/src");
const sourcePath = path.resolve(__dirname, "../src/preload.ts");
const outputPath = path.join(distDirectory, "preload.cjs");

// tsc has already checked types. Only Electron is imported at runtime; type-only
// shared imports disappear. A local exports object needs no Node globals in sandbox.
const result = ts.transpileModule(readFileSync(sourcePath, "utf8"), {
  fileName: "preload.ts", reportDiagnostics: true,
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, esModuleInterop: true }
});
if (result.diagnostics?.some((diagnostic) => diagnostic.category === ts.DiagnosticCategory.Error)) {
  throw new Error("preload compilation failed");
}
writeFileSync(outputPath, `(function () {\n"use strict";\nconst exports = {};\n${result.outputText}\n})();\n`);
for (const obsolete of ["preload.js", "preload.mjs"]) rmSync(path.join(distDirectory, obsolete), { force: true });
