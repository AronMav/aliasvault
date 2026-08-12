//! Argon2id password hashing.
//!
//! Derives the password hash that feeds into SRP private key derivation.
//! Parameters must stay identical across all AliasVault clients.

use thiserror::Error;

use crate::hex::bytes_to_hex;

pub mod defaults;

pub use defaults::{ARGON2ID_DEGREE_OF_PARALLELISM, ARGON2ID_ITERATIONS, ARGON2ID_MEMORY_SIZE};

/// Argon2-related errors.
#[derive(Error, Debug, Clone)]
pub enum Argon2Error {
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
}

/// Length of the derived key in bytes.
const OUTPUT_LENGTH: usize = 32;

/// Derive a key from a password using Argon2Id with explicit parameters.
///
/// A vault records the parameters its key was derived under and hands them back at login, so
/// callers opening an existing vault have to pass those rather than the defaults below.
///
/// # Arguments
/// * `password` - The password to hash
/// * `salt` - Salt as a string (will be UTF-8 encoded, minimum 8 bytes)
/// * `memory_kib` - Memory cost in KiB
/// * `iterations` - Number of iterations
/// * `parallelism` - Degree of parallelism
///
/// # Returns
/// Derived key as uppercase hex string (64 characters = 32 bytes)
pub fn argon2_derive_key(
    password: &str,
    salt: &str,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<String, Argon2Error> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(memory_kib, iterations, parallelism, Some(OUTPUT_LENGTH))
        .map_err(|e| Argon2Error::InvalidParameter(format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; OUTPUT_LENGTH];
    argon2
        .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut output)
        .map_err(|e| Argon2Error::InvalidParameter(format!("Argon2 hash failed: {}", e)))?;

    Ok(bytes_to_hex(&output))
}

/// Derive a key from a password using Argon2Id and the AliasVault default parameters.
///
/// # Arguments
/// * `password` - The password to hash
/// * `salt` - Salt as a string (will be UTF-8 encoded, minimum 8 bytes)
///
/// # Returns
/// Derived key as uppercase hex string (64 characters = 32 bytes)
pub fn argon2_hash_password(password: &str, salt: &str) -> Result<String, Argon2Error> {
    argon2_derive_key(
        password,
        salt,
        ARGON2ID_MEMORY_SIZE,
        ARGON2ID_ITERATIONS,
        ARGON2ID_DEGREE_OF_PARALLELISM,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_password_deterministic() {
        let hash1 = argon2_hash_password("password123", "somesalt12345678").unwrap();
        let hash2 = argon2_hash_password("password123", "somesalt12345678").unwrap();

        assert_eq!(hash1.len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_password_varies_with_inputs() {
        let base = argon2_hash_password("password123", "somesalt12345678").unwrap();
        let other_password = argon2_hash_password("password124", "somesalt12345678").unwrap();
        let other_salt = argon2_hash_password("password123", "somesalt12345679").unwrap();

        assert_ne!(base, other_password);
        assert_ne!(base, other_salt);
    }

    #[test]
    fn test_parameters_change_the_result() {
        let with_defaults = argon2_hash_password("password123", "somesalt12345678").unwrap();
        let explicit_defaults = argon2_derive_key(
            "password123",
            "somesalt12345678",
            ARGON2ID_MEMORY_SIZE,
            ARGON2ID_ITERATIONS,
            ARGON2ID_DEGREE_OF_PARALLELISM,
        )
        .unwrap();
        let other_memory = argon2_derive_key(
            "password123",
            "somesalt12345678",
            19456,
            ARGON2ID_ITERATIONS,
            ARGON2ID_DEGREE_OF_PARALLELISM,
        )
        .unwrap();
        let other_iterations = argon2_derive_key(
            "password123",
            "somesalt12345678",
            ARGON2ID_MEMORY_SIZE,
            2,
            ARGON2ID_DEGREE_OF_PARALLELISM,
        )
        .unwrap();

        assert_eq!(with_defaults, explicit_defaults);
        assert_ne!(with_defaults, other_memory);
        assert_ne!(with_defaults, other_iterations);
    }

    /// Pins the derived key for both the current and the previous default parameters.
    ///
    /// The same vectors are asserted in the managed implementation (SrpArgonEncryptionTests in
    /// AliasVault.UnitTests). A vault derived by one client has to open in all of them, so if
    /// these two ever disagree, one side has stopped producing keys the other can reproduce.
    #[test]
    fn test_matches_pinned_vectors() {
        const PASSWORD: &str = "correct horse battery staple";
        const SALT: &str = "0123456789ABCDEF";

        assert_eq!(
            argon2_derive_key(PASSWORD, SALT, 19456, 2, 1).unwrap(),
            "608B39E3CD889D3FADA5857D4AEA0DBEB3AFBA963DEEB0EA0D0911D68E7CA5E7"
        );
        assert_eq!(
            argon2_derive_key(PASSWORD, SALT, 65536, 3, 1).unwrap(),
            "B0168741041AA4390DD51D7FFDD2DDAF4D45DA508CC88C844CA3AFCF07BC8F0D"
        );
    }

    #[test]
    fn test_short_salt_fails() {
        // Argon2 requires a salt of at least 8 bytes
        let result = argon2_hash_password("password123", "short");
        assert!(matches!(result, Err(Argon2Error::InvalidParameter(_))));
    }
}
