//-----------------------------------------------------------------------
// <copyright file="MobileLoginApproval.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Api.Services;

using System.Security.Cryptography;
using System.Text;

/// <summary>Purpose-bound mobile approval payload, shared with the mobile client.</summary>
public static class MobileLoginApproval
{
    /// <summary>Builds a deterministic payload without ambiguous JSON serialization.</summary>
    /// <param name="requestId">The unique login request.</param>
    /// <param name="publicKey">The requesting device's exact public JWK.</param>
    /// <param name="encryptedKey">The vault key encrypted for that device.</param>
    /// <returns>The UTF-8 text to sign with RSA-PSS SHA-256 (32-byte salt).</returns>
    public static string CreatePayload(string requestId, string publicKey, string encryptedKey)
    {
        var publicKeyHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(publicKey)));
        var encryptedKeyHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(encryptedKey)));
        return $"aliasvault:mobile-login:v1\n{requestId}\n{publicKeyHash}\n{encryptedKeyHash}";
    }
}
