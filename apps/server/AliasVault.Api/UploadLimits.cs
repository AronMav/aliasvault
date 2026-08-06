//-----------------------------------------------------------------------
// <copyright file="UploadLimits.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Api;

/// <summary>
/// The server's upload size limit, read once from the environment.
/// </summary>
/// <remarks>
/// Both the Kestrel/form limits and the value reported to clients read from here.
/// Parsing it in two places would let the enforced limit and the advertised limit
/// drift apart, which would show up as an unexplained HTTP 413 on the client.
/// </remarks>
public static class UploadLimits
{
    /// <summary>
    /// Default limit in megabytes when MAX_UPLOAD_SIZE_MB is unset or invalid.
    /// </summary>
    private const int DefaultMaxUploadSizeMb = 100;

    /// <summary>
    /// Gets the maximum upload size in megabytes.
    /// </summary>
    public static int MaxUploadSizeMb { get; } =
        int.TryParse(Environment.GetEnvironmentVariable("MAX_UPLOAD_SIZE_MB"), out var parsedMb) && parsedMb > 0
            ? parsedMb
            : DefaultMaxUploadSizeMb;

    /// <summary>
    /// Gets the maximum upload size in bytes.
    /// </summary>
    public static long MaxUploadSizeBytes => (long)MaxUploadSizeMb * 1024 * 1024;
}
