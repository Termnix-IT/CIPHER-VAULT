import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

// Advisories accepted only while no upstream fix exists. Each entry must stay reachable only through `via`,
// and is rejected once expired or no longer reported, so the exception cannot outlive its reason.
const accepted = [{
  advisory: "GHSA-g3hv-75wg-m249", packageName: "minimatch", via: ["electron-builder"], until: "2026-12-31",
  reason: "Build-time packaging only, with glob patterns from this repository; electron-builder, @electron/asar and dir-compare have no minimatch 11 release yet."
}];

function npm(args) {
  // npm exits non-zero when findings exist, so read its JSON instead of the exit code.
  // Arguments are fixed literals here; a shell resolves npm.cmd on Windows and npm elsewhere.
  const result = spawnSync(`npm ${args.join(" ")}`, { encoding: "utf8", shell: true, maxBuffer: 64 * 1024 * 1024 });
  if (result.error) throw result.error;
  const report = JSON.parse(result.stdout);
  assert.equal(report.error, undefined, `npm ${args[0]} failed: ${JSON.stringify(report.error)}`);
  return report;
}

const audit = npm(["audit", "--package-lock-only", "--json"]);
const vulnerabilities = audit.vulnerabilities ?? {};
const today = new Date().toISOString().slice(0, 10);
const advisoryId = (via) => String(via.url ?? "").split("/").pop();
const findAccepted = (via) => accepted.find(entry => entry.advisory === advisoryId(via) && entry.packageName === via.name);
const memo = new Map(), used = new Set(), failures = [];

// A finding passes only if every advisory behind it, directly or through vulnerable dependencies, is accepted.
function acceptable(name, trail = new Set()) {
  if (memo.has(name)) return memo.get(name);
  if (trail.has(name)) return true;
  trail.add(name);
  const result = (vulnerabilities[name]?.via ?? []).every(via => {
    if (typeof via === "string") return acceptable(via, trail);
    const entry = findAccepted(via);
    if (entry) used.add(entry);
    return entry !== undefined;
  });
  memo.set(name, result);
  return result;
}
for (const name of Object.keys(vulnerabilities)) if (!acceptable(name)) failures.push(`${name}: ${vulnerabilities[name].severity} finding is not accepted`);

for (const entry of accepted) {
  if (!used.has(entry)) { failures.push(`${entry.advisory} is no longer reported; remove its exception`); continue; }
  if (today > entry.until) failures.push(`${entry.advisory} exception expired on ${entry.until}`);
  const tree = npm(["ls", entry.packageName, "--all", "--package-lock-only", "--json"]);
  const roots = Object.keys(tree.dependencies ?? {}).filter(name => !entry.via.includes(name));
  if (roots.length) failures.push(`${entry.packageName} is also reached through ${roots.join(", ")}`);
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
for (const entry of used) console.log(`Accepted ${entry.advisory} (${entry.packageName}) until ${entry.until}: ${entry.reason}`);
console.log(`Dependency audit passed: ${Object.keys(vulnerabilities).length} findings, all covered by accepted advisories`);
