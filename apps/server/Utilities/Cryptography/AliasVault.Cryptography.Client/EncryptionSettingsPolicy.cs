//-----------------------------------------------------------------------
// <copyright file="EncryptionSettingsPolicy.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Cryptography.Client;

using System.Text.Json;

/// <summary>
/// Parses and bounds the Argon2id parameters a client reports having used.
/// </summary>
/// <remarks>
/// A vault is only openable with the parameters it was encrypted under, so whatever a client
/// reports here is handed straight back to every client at the next login. That makes this the
/// point where a value has to be checked: parameters below the current minimum would weaken the
/// key derivation for the account from then on, and absurdly high ones would leave a vault that
/// no device can afford to open. Both are rejected rather than clamped, because a client whose
/// parameters are not stored verbatim would derive a different key than the one on record.
/// </remarks>
public static class EncryptionSettingsPolicy
{
    /// <summary>
    /// Lowest memory size accepted, in KiB. This is the OWASP minimum for Argon2id at two
    /// iterations, and was the AliasVault default up to and including 0.25, so every existing
    /// vault satisfies it.
    /// </summary>
    public const int MinMemorySize = 19456;

    /// <summary>
    /// Lowest iteration count accepted.
    /// </summary>
    public const int MinIterations = 2;

    /// <summary>
    /// Lowest degree of parallelism accepted.
    /// </summary>
    public const int MinDegreeOfParallelism = 1;

    /// <summary>
    /// Highest memory size accepted, in KiB (1 GiB). Above this a vault stops being openable on
    /// the phones and browser tabs that also have to open it.
    /// </summary>
    public const int MaxMemorySize = 1048576;

    /// <summary>
    /// Highest iteration count accepted.
    /// </summary>
    public const int MaxIterations = 10;

    /// <summary>
    /// Highest degree of parallelism accepted.
    /// </summary>
    public const int MaxDegreeOfParallelism = 4;

    /// <summary>
    /// Checks that a client-reported encryption type and settings pair is one this server is
    /// willing to record against a vault.
    /// </summary>
    /// <param name="encryptionType">The encryption type reported by the client.</param>
    /// <param name="encryptionSettings">The encryption settings JSON reported by the client.</param>
    /// <returns>True when the pair is usable and within bounds.</returns>
    public static bool IsAcceptable(string? encryptionType, string? encryptionSettings)
    {
        if (!string.Equals(encryptionType, Defaults.EncryptionType, StringComparison.Ordinal))
        {
            return false;
        }

        if (!TryParse(encryptionSettings, out var parameters))
        {
            return false;
        }

        return parameters.MemorySize >= MinMemorySize
            && parameters.MemorySize <= MaxMemorySize
            && parameters.Iterations >= MinIterations
            && parameters.Iterations <= MaxIterations
            && parameters.DegreeOfParallelism >= MinDegreeOfParallelism
            && parameters.DegreeOfParallelism <= MaxDegreeOfParallelism;
    }

    /// <summary>
    /// Reads the three Argon2id parameters out of a settings JSON string.
    /// </summary>
    /// <remarks>
    /// All three have to be present. Filling a missing one in from the defaults would record
    /// parameters the client never used, which is the failure this whole type exists to prevent.
    /// </remarks>
    /// <param name="encryptionSettings">The encryption settings JSON string.</param>
    /// <param name="parameters">The parsed parameters when parsing succeeds.</param>
    /// <returns>True when the string parsed into a complete set of parameters.</returns>
    public static bool TryParse(string? encryptionSettings, out (int DegreeOfParallelism, int MemorySize, int Iterations) parameters)
    {
        parameters = default;

        if (string.IsNullOrWhiteSpace(encryptionSettings))
        {
            return false;
        }

        Dictionary<string, int>? properties;
        try
        {
            properties = JsonSerializer.Deserialize<Dictionary<string, int>>(encryptionSettings);
        }
        catch (JsonException)
        {
            return false;
        }

        if (properties is null
            || !properties.TryGetValue("DegreeOfParallelism", out var degreeOfParallelism)
            || !properties.TryGetValue("MemorySize", out var memorySize)
            || !properties.TryGetValue("Iterations", out var iterations))
        {
            return false;
        }

        parameters = (degreeOfParallelism, memorySize, iterations);
        return true;
    }
}
