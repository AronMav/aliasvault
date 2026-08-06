//-----------------------------------------------------------------------
// <copyright file="AuthHelper.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Api.Helpers;

using System.Security.Cryptography;
using System.Text;
using AliasServerDb;
using AliasVault.Api.Headers;
using AliasVault.Auth;
using AliasVault.Cryptography.Client;
using Microsoft.Extensions.Caching.Memory;
using SecureRemotePassword;

/// <summary>
/// AuthHelper class which contains helper methods for authentication.
/// </summary>
public static class AuthHelper
{
    /// <summary>
    /// Cache prefix for storing generated login ephemeral.
    /// </summary>
    public static readonly string CachePrefixEphemeral = "LoginEphemeral_";

    /// <summary>
    /// Password the fake verifier for a non-existent user is derived from. Its value is irrelevant as
    /// long as it is fixed: no client can ever produce a proof that matches the resulting verifier.
    /// </summary>
    private const string FakePassword = "fakePassword";

    /// <summary>
    /// Domain separation labels so the salt and the SRP identity of a username derive from
    /// independent values.
    /// </summary>
    private const string FakeSaltLabel = "fake-srp-salt";

    /// <summary>
    /// Domain separation label for the derived SRP identity. See <see cref="FakeSaltLabel"/>.
    /// </summary>
    private const string FakeIdentityLabel = "fake-srp-identity";

    /// <summary>
    /// Helper method that validates the SRP session based on provided SRP identity, ephemeral and proof.
    /// </summary>
    /// <param name="cache">IMemoryCache instance.</param>
    /// <param name="user">The user object.</param>
    /// <param name="clientEphemeral">The client ephemeral value.</param>
    /// <param name="clientSessionProof">The client session proof.</param>
    /// <returns>SrpSession if validation succeeds, null otherwise.</returns>
    public static SrpSession? ValidateSrpSession(IMemoryCache cache, AliasVaultUser user, string clientEphemeral, string clientSessionProof)
    {
        // Get or create SRP identity. For existing users without SrpIdentity, fall back to username (lowercase).
        var srpIdentity = user.SrpIdentity ?? user.UserName!.ToLowerInvariant();

        if (!cache.TryGetValue(CachePrefixEphemeral + srpIdentity, out var serverSecretEphemeral) || serverSecretEphemeral is not string)
        {
            return null;
        }

        // Retrieve latest vault of user which contains the current salt and verifier.
        var latestVaultEncryptionSettings = GetUserLatestVaultEncryptionSettings(user);

        // Use SrpIdentity for the SRP session derivation. This is the fixed identity that was used
        // when the verifier was originally created, ensuring username changes don't break authentication.
        var serverSession = Srp.DeriveSessionServer(
            serverSecretEphemeral.ToString() ?? string.Empty,
            clientEphemeral,
            latestVaultEncryptionSettings.Salt,
            srpIdentity,
            latestVaultEncryptionSettings.Verifier,
            clientSessionProof);

        if (serverSession is null)
        {
            return null;
        }

        return serverSession;
    }

    /// <summary>
    /// Get the user's latest vault which contains the current salt and verifier.
    /// </summary>
    /// <param name="user">User object.</param>
    /// <returns>Tuple with salt, verifier, encryption type and encryption settings.</returns>
    public static (string Salt, string Verifier, string EncryptionType, string EncryptionSettings) GetUserLatestVaultEncryptionSettings(AliasVaultUser user)
    {
        // Retrieve latest vault of user which contains the encryption settings.
        var latestVault = user.Vaults.OrderByDescending(x => x.RevisionNumber).Select(x => new { x.Salt, x.Verifier, x.EncryptionType, x.EncryptionSettings }).First();
        return (latestVault.Salt, latestVault.Verifier, latestVault.EncryptionType, latestVault.EncryptionSettings);
    }

    /// <summary>
    /// Derives the SRP values that the login endpoint returns for a username that has no account, so
    /// that response is indistinguishable from the response for a real one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every field a caller can observe is produced in the same shape a client would have registered it
    /// in: the salt as uppercase hex of 32 bytes, the SRP identity as a version 4 UUID. A fake value in a
    /// different shape than a real one turns this response into the enumeration oracle it exists to prevent.
    /// </para>
    /// <para>
    /// The values are derived from a server-side secret instead of being generated once and cached,
    /// because the username comes from an unauthenticated request. Caching per username lets any caller
    /// grow server memory without limit by submitting names that do not exist, while deriving them keeps
    /// the values stable per username at no stored cost.
    /// </para>
    /// </remarks>
    /// <param name="username">The username that was submitted.</param>
    /// <param name="serverSecret">Server-side secret the values are derived from.</param>
    /// <returns>Tuple with the salt, verifier and SRP identity to return for this username.</returns>
    public static (string Salt, string Verifier, string SrpIdentity) DeriveFakeSrpCredentials(string username, string serverSecret)
    {
        var normalizedUsername = UsernameHelper.NormalizeUsername(username);

        var salt = Convert.ToHexString(DeriveFakeBytes(normalizedUsername, serverSecret, FakeSaltLabel));
        var srpIdentity = DeriveFakeSrpIdentity(normalizedUsername, serverSecret);

        // Real verifiers are derived with the SRP identity as identity, not with the username.
        var privateKey = Srp.DerivePrivateKey(salt, srpIdentity, FakePassword);
        var verifier = new SrpClient().DeriveVerifier(privateKey);

        return (salt, verifier, srpIdentity);
    }

    /// <summary>
    /// Generate a device identifier based on request headers. This is used to associate refresh tokens
    /// with a specific device for a specific user.
    ///
    /// The identifier includes the client type (web app, browser extension, mobile app) to prevent
    /// conflicts when a user is logged in on multiple clients from the same browser/device.
    /// For example, logging out from the browser extension won't affect the web app session.
    ///
    /// When the optional X-AliasVault-AppInstanceId header is present (currently only sent by the
    /// Android app to support multiple User Profiles on the same physical device), it is appended
    /// to keep device identifiers unique across those profiles.
    ///
    /// Device identifier format examples:
    /// - Web/Browser: "chrome|Mozilla/5.0...|en-US"
    /// - Android: "android|Dalvik/2.1.0...|en-US|550e8400e29b41d4a716446655440000"
    /// - iOS: "ios|AliasVault/1.0...|en-US"
    ///
    /// NOTE: This implementation ensures only one refresh token can be valid for a
    /// specific user/device combo at a time.
    /// </summary>
    /// <param name="request">The HttpRequest instance for the request that the client used.</param>
    /// <returns>Unique device identifier as string.</returns>
    public static string GenerateDeviceIdentifier(HttpRequest request)
    {
        var clientInfo = ClientHeaderInfo.Parse(request.Headers[ClientHeaderInfo.HeaderName].ToString());
        var appInstanceInfo = AppInstanceIdHeaderInfo.Parse(request.Headers[AppInstanceIdHeaderInfo.HeaderName].ToString());

        List<string?> parts =
        [
            clientInfo.ClientName,
            request.Headers.UserAgent.ToString(),
            request.Headers.AcceptLanguage.ToString(),
        ];

        if (appInstanceInfo.AppInstanceId is not null)
        {
            parts.Add(appInstanceInfo.AppInstanceId);
        }

        return string.Join('|', parts);
    }

    /// <summary>
    /// Derives the SRP identity returned for a username that has no account.
    /// </summary>
    /// <param name="normalizedUsername">The normalized username.</param>
    /// <param name="serverSecret">Server-side secret the identity is derived from.</param>
    /// <returns>A version 4 UUID, the same shape clients generate for a real registration.</returns>
    private static string DeriveFakeSrpIdentity(string normalizedUsername, string serverSecret)
    {
        var bytes = DeriveFakeBytes(normalizedUsername, serverSecret, FakeIdentityLabel)[..16];

        // Clients use crypto.randomUUID()/Guid.NewGuid(), which both produce a version 4 UUID. Stamp the
        // version and variant bits so a derived identity is not recognizable by the nibbles that a real
        // one always has fixed. Guid(byte[]) reads the first three groups little-endian, which puts the
        // version nibble in the high half of byte 7 and the variant bits at the top of byte 8.
        bytes[7] = (byte)((bytes[7] & 0x0F) | 0x40);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);

        return new Guid(bytes).ToString();
    }

    /// <summary>
    /// Derives a block of bytes for a username from the server secret.
    /// </summary>
    /// <param name="normalizedUsername">The normalized username.</param>
    /// <param name="serverSecret">Server-side secret to derive from.</param>
    /// <param name="label">Domain separation label keeping derived values independent of each other.</param>
    /// <returns>32 derived bytes.</returns>
    private static byte[] DeriveFakeBytes(string normalizedUsername, string serverSecret, string label)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(serverSecret));
        return hmac.ComputeHash(Encoding.UTF8.GetBytes(label + '|' + normalizedUsername));
    }
}
