//-----------------------------------------------------------------------
// <copyright file="EncryptionSettingsPolicy.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Cryptography.Client;

using System.Text.Json;

/// <summary>
/// Decides whether the Argon2id parameters a client reports having used can be recorded against a vault.
/// </summary>
/// <remarks>
/// A vault is only openable with the parameters it was encrypted under, so whatever is accepted here
/// is handed back to every client at the next login. Two things have to be kept out: parameters that
/// cost the account less work than the ones it already had, and parameters so expensive that no phone
/// or browser tab can open the vault again.
///
/// The lower bound is the account's own current parameters rather than a fixed number, because a
/// deployment chooses what it registers accounts with (see CryptographyOverride in the client config)
/// and a password change must not quietly overrule that choice in either direction. Values are
/// rejected rather than clamped: the client has already derived its key, so recording anything other
/// than what it reports produces a vault it cannot open.
/// </remarks>
public static class EncryptionSettingsPolicy
{
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
    /// Lowest memory size the Argon2id specification allows for a given degree of parallelism, per lane.
    /// </summary>
    private const int MinMemorySizePerLane = 8;

    /// <summary>
    /// Checks that the parameters a client reports can be recorded against a vault that currently
    /// holds the given ones.
    /// </summary>
    /// <param name="encryptionType">The encryption type reported by the client.</param>
    /// <param name="encryptionSettings">The encryption settings JSON reported by the client.</param>
    /// <param name="currentEncryptionSettings">
    /// The settings the vault holds today. The reported parameters may not cost less work than these.
    /// When they cannot be parsed, only the absolute bounds apply, since there is nothing to compare to.
    /// </param>
    /// <returns>True when the reported parameters are usable and no weaker than the current ones.</returns>
    public static bool IsAcceptable(string? encryptionType, string? encryptionSettings, string? currentEncryptionSettings)
    {
        if (!string.Equals(encryptionType, Defaults.EncryptionType, StringComparison.Ordinal))
        {
            return false;
        }

        if (!TryParse(encryptionSettings, out var parameters))
        {
            return false;
        }

        if (parameters.MemorySize > MaxMemorySize
            || parameters.Iterations is < 1 or > MaxIterations
            || parameters.DegreeOfParallelism is < 1 or > MaxDegreeOfParallelism
            || parameters.MemorySize < MinMemorySizePerLane * parameters.DegreeOfParallelism)
        {
            return false;
        }

        if (!TryParse(currentEncryptionSettings, out var current))
        {
            return true;
        }

        // Compare the work a guess costs rather than each parameter on its own, so trading memory
        // for passes is allowed as long as the total does not fall.
        return (long)parameters.MemorySize * parameters.Iterations >= (long)current.MemorySize * current.Iterations;
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
