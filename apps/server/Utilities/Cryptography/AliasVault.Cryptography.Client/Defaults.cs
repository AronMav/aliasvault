//-----------------------------------------------------------------------
// <copyright file="Defaults.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Cryptography.Client;

/// <summary>
/// Cryptography defaults.
/// </summary>
/// <remarks>
/// The values live in <see cref="Argon2Defaults"/>, which is generated from
/// core/models/src/defaults/EncryptionDefaults.ts. This class stays hand-written so it can
/// hold defaults that are not part of that generated set, and so the names the rest of the
/// server already calls do not depend on the generator's casing.
/// </remarks>
public static class Defaults
{
    /// <summary>
    /// Gets the default encryption type.
    /// </summary>
    public static string EncryptionType { get; } = Argon2Defaults.EncryptionType;

    /// <summary>
    /// Gets the default degree of parallelism for Argon2id.
    /// </summary>
    public static int Argon2IdDegreeOfParallelism { get; } = Argon2Defaults.Argon2idDegreeOfParallelism;

    /// <summary>
    /// Gets the default memory size for Argon2id (in KB).
    /// </summary>
    public static int Argon2IdMemorySize { get; } = Argon2Defaults.Argon2idMemorySize;

    /// <summary>
    /// Gets the default number of iterations for Argon2id.
    /// </summary>
    public static int Argon2IdIterations { get; } = Argon2Defaults.Argon2idIterations;

    /// <summary>
    /// Gets the default encryption settings.
    /// </summary>
    public static string EncryptionSettings { get; } = Argon2Defaults.EncryptionSettings;
}
