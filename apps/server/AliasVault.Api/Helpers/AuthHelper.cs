//-----------------------------------------------------------------------
// <copyright file="AuthHelper.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Api.Helpers;

using System.Buffers.Binary;
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
    /// How long an unused server ephemeral stays valid, in minutes.
    /// </summary>
    public const int EphemeralLifetimeMinutes = 5;

    /// <summary>
    /// Cache prefix for storing generated login ephemeral.
    /// </summary>
    public static readonly string CachePrefixEphemeral = "LoginEphemeral_";

    /// <summary>
    /// Cache prefix for the refresh token most recently issued in place of a given one.
    /// </summary>
    public static readonly string CachePrefixRotatedToken = "RotatedRefreshToken_";

    /// <summary>
    /// Length of an SRP verifier for the 2048-bit group the clients use, in bytes.
    /// </summary>
    private const int VerifierByteLength = 256;

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
    /// Domain separation label for the derived verifier. See <see cref="FakeSaltLabel"/>.
    /// </summary>
    private const string FakeVerifierLabel = "fake-srp-verifier";

    /// <summary>
    /// Domain separation label for the drawn encryption settings. See <see cref="FakeSaltLabel"/>.
    /// </summary>
    private const string FakeEncryptionSettingsLabel = "fake-encryption-settings";

    /// <summary>
    /// Number of locks the ephemeral sets are spread across.
    /// </summary>
    private const int EphemeralSetLockStripes = 64;

    /// <summary>
    /// Guards creation of an account's ephemeral set so two concurrent logins cannot each create one
    /// and have the first lose its secret.
    /// </summary>
    /// <remarks>
    /// Striped by account rather than a single lock for the whole instance. Only two logins for the
    /// same account can race here, so one global lock made every login on the instance queue behind
    /// every other one for a conflict that can only happen within an account.
    /// </remarks>
    private static readonly Lock[] EphemeralSetCreationLocks =
        [.. Enumerable.Range(0, EphemeralSetLockStripes).Select(_ => new Lock())];

    /// <summary>
    /// Helper method that validates the SRP session based on provided SRP identity, ephemeral and proof.
    /// </summary>
    /// <param name="cache">IMemoryCache instance.</param>
    /// <param name="user">The user object.</param>
    /// <param name="clientEphemeral">The client ephemeral value.</param>
    /// <param name="clientSessionProof">The client session proof.</param>
    /// <returns>Tuple with the SrpSession (null if validation failed) and whether an active SRP session existed.</returns>
    public static (SrpSession? Session, bool ActiveSessionFound) ValidateSrpSession(IMemoryCache cache, AliasVaultUser user, string clientEphemeral, string clientSessionProof)
    {
        var srpIdentity = GetSrpIdentity(user);

        if (!cache.TryGetValue(CachePrefixEphemeral + srpIdentity, out var cached) || cached is not SrpEphemeralSet ephemeralSet)
        {
            // No login was initiated for this user, or the server ephemeral has expired. Return false to indicate that no active session was found.
            return (null, false);
        }

        // Retrieve latest vault of user which contains the current salt and verifier.
        var latestVaultEncryptionSettings = GetUserLatestVaultEncryptionSettings(user);

        // An account can have several exchanges in flight, so the proof is checked against each
        // live secret rather than against one the newest login happened to leave behind. Only the
        // secret the client actually proved against produces a session; the rest return null.
        foreach (var serverSecretEphemeral in ephemeralSet.GetSecrets())
        {
            // Use SrpIdentity for the SRP session derivation. This is the fixed identity that was used
            // when the verifier was originally created, ensuring username changes don't break authentication.
            var serverSession = Srp.DeriveSessionServer(
                serverSecretEphemeral,
                clientEphemeral,
                latestVaultEncryptionSettings.Salt,
                srpIdentity,
                latestVaultEncryptionSettings.Verifier,
                clientSessionProof);

            if (serverSession is not null)
            {
                return (serverSession, true);
            }
        }

        // The proof matched none of the live secrets: an exchange was started for this account, so
        // this was a real password attempt and not a validate call for a session that never existed.
        return (null, true);
    }

    /// <summary>
    /// Stores a freshly generated server ephemeral for the exchange that is starting.
    /// </summary>
    /// <remarks>
    /// Added to the account's live set rather than replacing it. Anyone who knows a username can
    /// start an exchange, and replacing meant that single request cancelled whatever exchange the
    /// account owner had in progress.
    /// </remarks>
    /// <param name="cache">IMemoryCache instance.</param>
    /// <param name="srpIdentity">The SRP identity the exchange belongs to.</param>
    /// <param name="serverSecretEphemeral">The server ephemeral secret to store.</param>
    public static void StoreSrpEphemeral(IMemoryCache cache, string srpIdentity, string serverSecretEphemeral)
    {
        var cacheKey = CachePrefixEphemeral + srpIdentity;

        // Creating the set is the one step two concurrent logins can race on. The lock is held only
        // for the lookup-or-create, never for the SRP work, and a lost race would cost one ephemeral
        // and a retried login rather than anyone else's request.
        SrpEphemeralSet ephemeralSet;
        lock (EphemeralSetCreationLocks[(uint)cacheKey.GetHashCode(StringComparison.Ordinal) % EphemeralSetLockStripes])
        {
            if (!cache.TryGetValue(cacheKey, out var cached) || cached is not SrpEphemeralSet existing)
            {
                ephemeralSet = new SrpEphemeralSet();
            }
            else
            {
                ephemeralSet = existing;
            }

            // Written back on every exchange, not only when the set is created, so the entry always
            // has the full lifetime ahead of it. Setting it once would give an exchange started in
            // the fourth minute only the remainder of the first one's clock.
            cache.Set(cacheKey, ephemeralSet, TimeSpan.FromMinutes(EphemeralLifetimeMinutes));
        }

        ephemeralSet.Add(serverSecretEphemeral);
    }

    /// <summary>
    /// Hashes a refresh token for storage and lookup, so the database holds no value that can be
    /// presented as a session.
    /// </summary>
    /// <remarks>
    /// A single SHA-256 pass is the right amount of work here. A refresh token is 32 bytes straight
    /// from the CSPRNG, so there is no guessable input to protect against with a slow KDF; using one
    /// would only add latency to every token refresh. The hash is deterministic on purpose, so the
    /// lookup stays an indexed equality match.
    /// </remarks>
    /// <param name="token">The refresh token as the client presents it.</param>
    /// <returns>The value to store and compare against.</returns>
    public static string HashRefreshToken(string token)
    {
        return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    }

    /// <summary>
    /// Drops the cached server ephemeral for a user, so it cannot be used a second time.
    /// </summary>
    /// <remarks>
    /// Call this once the exchange the ephemeral was issued for has finished. It is deliberately not
    /// called from <see cref="ValidateSrpSession"/>: a login with two-factor authentication validates
    /// the same proof twice, once to check the password and once alongside the second factor, and a
    /// mistyped second factor has to stay retryable. Until this runs the entry lives for its full five
    /// minutes, which is long enough for a captured proof to be replayed.
    /// </remarks>
    /// <param name="cache">IMemoryCache instance.</param>
    /// <param name="user">The user whose ephemeral should be dropped.</param>
    public static void InvalidateSrpSession(IMemoryCache cache, AliasVaultUser user)
    {
        var cacheKey = CachePrefixEphemeral + GetSrpIdentity(user);

        // Clear the set as well as removing the entry: another request may already hold a reference
        // to this instance, and clearing is what makes the secrets in it unusable to that caller too.
        if (cache.TryGetValue(cacheKey, out var cached) && cached is SrpEphemeralSet ephemeralSet)
        {
            ephemeralSet.Clear();
        }

        cache.Remove(cacheKey);
    }

    /// <summary>
    /// Gets the SRP identity for a user. For existing users without one, this falls back to the
    /// lowercased username, which is what the verifier was originally created with.
    /// </summary>
    /// <param name="user">The user object.</param>
    /// <returns>The SRP identity.</returns>
    public static string GetSrpIdentity(AliasVaultUser user)
    {
        return user.SrpIdentity ?? user.UserName!.ToLowerInvariant();
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
        var verifier = DeriveFakeVerifier(normalizedUsername, serverSecret);

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
    /// Picks the key derivation parameters to report for a username that has no account.
    /// </summary>
    /// <remarks>
    /// The parameters a vault was encrypted under are returned to the caller at login, and an
    /// account keeps the ones it was registered with until its password is changed. An instance
    /// whose default has moved therefore holds a mix of them, and answering every unknown username
    /// with the current default would say "no account here" for every account registered before the
    /// move. Draw from the parameters the instance actually holds instead, weighted by how common
    /// each one is, so an unknown username looks like an account picked at random.
    ///
    /// The draw is deterministic in the username, so repeating a request cannot reveal that the
    /// answer was made up, and it is keyed on the server secret, so the caller cannot work out
    /// which value a given username should have produced.
    /// </remarks>
    /// <param name="username">The username that was submitted.</param>
    /// <param name="serverSecret">Server-side secret the draw is keyed on.</param>
    /// <param name="distribution">
    /// The encryption type and settings pairs in use on this instance with the number of vaults
    /// holding each. An empty distribution falls back to the current defaults, which is the only
    /// honest answer when the instance has no vaults to imitate.
    /// </param>
    /// <returns>The encryption type and settings to report.</returns>
    public static (string EncryptionType, string EncryptionSettings) DeriveFakeEncryptionSettings(
        string username,
        string serverSecret,
        IReadOnlyList<(string EncryptionType, string EncryptionSettings, int Count)> distribution)
    {
        var total = 0L;
        foreach (var entry in distribution)
        {
            if (entry.Count > 0)
            {
                total += entry.Count;
            }
        }

        if (total == 0)
        {
            return (Defaults.EncryptionType, Defaults.EncryptionSettings);
        }

        var normalizedUsername = UsernameHelper.NormalizeUsername(username);
        var draw = BinaryPrimitives.ReadUInt64BigEndian(DeriveFakeBytes(normalizedUsername, serverSecret, FakeEncryptionSettingsLabel)) % (ulong)total;

        var cumulative = 0UL;
        foreach (var entry in distribution)
        {
            if (entry.Count <= 0)
            {
                continue;
            }

            cumulative += (ulong)entry.Count;
            if (draw < cumulative)
            {
                return (entry.EncryptionType, entry.EncryptionSettings);
            }
        }

        // Unreachable while the counts above sum to total, but a fallback keeps a rounding
        // mistake from throwing on an unauthenticated request.
        return (Defaults.EncryptionType, Defaults.EncryptionSettings);
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
    /// Derives the SRP verifier used to answer a username that has no account.
    /// </summary>
    /// <remarks>
    /// A real verifier is g^x mod N, and computing one here would cost a modular exponentiation on top
    /// of the server ephemeral the response also needs. A real account costs one, because its verifier
    /// is read from its vault, so deriving a genuine verifier makes an unknown username take roughly
    /// twice as long to answer as a known one --- the enumeration oracle this whole path exists to close.
    ///
    /// The value is derived and reduced into the group instead. Nothing outside the server ever sees a
    /// verifier: it is only fed to the ephemeral generator, whose output B = kv + g^b mod N is uniform
    /// whichever way v was produced. Clearing the top bit keeps the value below the group's prime, which
    /// exceeds 2^2047 because its leading byte is 0xAC.
    /// </remarks>
    /// <param name="normalizedUsername">The normalized username.</param>
    /// <param name="serverSecret">Server-side secret the verifier is derived from.</param>
    /// <returns>A verifier in the same shape a real one has: 512 lowercase hex characters.</returns>
    private static string DeriveFakeVerifier(string normalizedUsername, string serverSecret)
    {
        // HKDF is what stretches one derived block into the length needed here; writing the same
        // counter-mode expansion by hand would be more crypto to review for no gain.
        var material = HKDF.Expand(
            HashAlgorithmName.SHA256,
            DeriveFakeBytes(normalizedUsername, serverSecret, FakeVerifierLabel),
            VerifierByteLength);

        material[0] &= 0x7F;

        return Convert.ToHexString(material).ToLowerInvariant();
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
