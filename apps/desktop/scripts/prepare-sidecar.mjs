import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const release = process.argv.includes("--release");
const scriptDir = dirname(fileURLToPath(import.meta.url));
const root = resolve(scriptDir, "../../..");
const destinationDir = resolve(scriptDir, "../src-tauri/binaries");

const rustc = spawnSync("rustc", ["-vV"], { encoding: "utf8" });
if (rustc.status !== 0) {
  throw new Error("rustc -vV failed");
}
const host = rustc.stdout
  .split("\n")
  .find((line) => line.startsWith("host: "))
  ?.slice(6)
  .trim();
if (!host) {
  throw new Error("Could not determine the Rust host triple");
}

const profile = release ? "release" : "debug";
const build = spawnSync(
  "cargo",
  ["build", "--locked", "-p", "runtime", "--bin", "unified_server", ...(release ? ["--release"] : [])],
  { cwd: root, stdio: "inherit" },
);
if (build.status !== 0) {
  process.exit(build.status ?? 1);
}

const extension = process.platform === "win32" ? ".exe" : "";
const source = resolve(root, "target", profile, `unified_server${extension}`);
const destination = resolve(destinationDir, `unified_server-${host}${extension}`);
mkdirSync(destinationDir, { recursive: true });
copyFileSync(source, destination);
console.log(`Prepared sidecar: ${destination}`);
