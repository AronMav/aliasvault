#!/usr/bin/env node
// Build the Rust core WASM artifacts the extension bundles.
//
// Exists because npm runs scripts through cmd.exe on Windows, where a shell
// script is not something that can be executed: `./build.sh` fails with "'.' is
// not recognized as an internal or external command". Naming bash instead is not
// enough either, because `bash` on PATH is often System32\bash.exe -- the WSL
// launcher, which would run the script inside a Linux distribution that has
// neither this checkout nor a Rust toolchain.
//
// Usage:
//   node scripts/build-rust.mjs [extra build.sh args]

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { argv, env, exit, platform } from "node:process";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const extensionDir = path.resolve(scriptDir, "..");
const rustDir = path.resolve(extensionDir, "..", "..", "core", "rust");

/**
 * Resolve a POSIX shell able to run the build script.
 * @returns {string} Path to the shell, or the bare command on non-Windows hosts.
 */
function resolveShell() {
  if (platform !== "win32") {
    return "bash";
  }

  const candidates = [
    path.join(env.ProgramFiles ?? "", "Git", "bin", "bash.exe"),
    path.join(env["ProgramFiles(x86)"] ?? "", "Git", "bin", "bash.exe"),
    path.join(env.LOCALAPPDATA ?? "", "Programs", "Git", "bin", "bash.exe"),
  ];

  const found = candidates.find((candidate) => candidate && existsSync(candidate));
  if (!found) {
    console.error(
      "Building the Rust core on Windows needs Git for Windows (bash.exe); none was found."
    );
    exit(1);
  }

  return found;
}

const args = argv.slice(2);
const buildArgs = args.length > 0 ? args : ["--browser"];

const result = spawnSync(resolveShell(), ["./build.sh", ...buildArgs], {
  cwd: rustDir,
  stdio: "inherit",
});

if (result.error) {
  console.error(result.error.message);
  exit(1);
}

exit(result.status ?? 1);
