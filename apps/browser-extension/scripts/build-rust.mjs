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
const buildArgs = args.length > 0 ? args : ["--browser-extension"];

/**
 * Environment for the build. The WASM build compiles the bundled SQLite with cc-rs,
 * which needs an LLVM clang that has the WebAssembly backend. The standard MSVC
 * toolchain has none, and LLVM is not on PATH by default when installed to
 * "C:\Program Files\LLVM", so point CC/AR at it explicitly when it is there.
 *
 * @returns {object} The environment to spawn the build script with.
 */
function buildEnv() {
  const env = { ...process.env };
  const llvmCandidates = [
    env["ProgramFiles"] ? `${env["ProgramFiles"]}\\LLVM\\bin` : null,
    env["ProgramFiles(x86)"] ? `${env["ProgramFiles(x86)"]}\\LLVM\\bin` : null,
  ].filter(Boolean);
  for (const bin of llvmCandidates) {
    if (existsSync(`${bin}\\clang.exe`)) {
      env["CC_wasm32_unknown_unknown"] = "clang";
      env["AR_wasm32_unknown_unknown"] = "llvm-ar";
      env["PATH"] = `${bin};${env["PATH"] ?? ""}`;
      break;
    }
  }
  // The build script computes paths with POSIX pwd and hands them to wasm-pack and
  // cargo, which are native binaries. With MSYS path conversion disabled (a common
  // global setting: MSYS_NO_PATHCONV=1) those arrive as "/d/...", get resolved
  // relative to the current drive and end up in a literal "D:\d\..." directory.
  delete env["MSYS_NO_PATHCONV"];
  delete env["MSYS2_ARG_CONV_EXCL"];
  return env;
}

const result = spawnSync(resolveShell(), ["./build.sh", ...buildArgs], {
  cwd: rustDir,
  stdio: "inherit",
  env: buildEnv(),
});

if (result.error) {
  console.error(result.error.message);
  exit(1);
}

exit(result.status ?? 1);
