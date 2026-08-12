/**
 * Single source of truth for the Argon2id key derivation parameters shared across every
 * AliasVault client.
 *
 * This file is distributed by core/models/build.sh to all platforms including:
 *   - `core/rust/src/argon2/defaults.rs` (Rust core)
 *   - `apps/server/Utilities/Cryptography/AliasVault.Cryptography.Client/Argon2Defaults.cs` (C#)
 *   - `apps/mobile-app/android/app/src/androidTest/java/net/aliasvault/app/EncryptionDefaults.kt`
 *   - `apps/mobile-app/ios/AliasVaultUITests/EncryptionDefaults.swift`
 *
 * The TypeScript clients (browser extension, mobile app) import the constants directly
 * from `@/utils/dist/core/models/defaults`.
 *
 * A vault opens only under the parameters its key was derived with, so a client that
 * disagrees with this file derives a key none of the others can reproduce.
 */

/** Degree of parallelism (lanes) for Argon2id. */
export const ARGON2ID_DEGREE_OF_PARALLELISM = 1;

/** Memory cost for Argon2id, in KiB. */
export const ARGON2ID_MEMORY_SIZE = 65536;

/** Number of Argon2id passes over memory. */
export const ARGON2ID_ITERATIONS = 3;

/** Key derivation algorithm recorded against a vault. */
export const ENCRYPTION_TYPE = 'Argon2Id';

/**
 * The settings exactly as they are stored against a vault and compared by every client.
 * Key order is part of the value and must stay DegreeOfParallelism, MemorySize, Iterations.
 */
export const ENCRYPTION_SETTINGS = JSON.stringify({
  DegreeOfParallelism: ARGON2ID_DEGREE_OF_PARALLELISM,
  MemorySize: ARGON2ID_MEMORY_SIZE,
  Iterations: ARGON2ID_ITERATIONS,
});
