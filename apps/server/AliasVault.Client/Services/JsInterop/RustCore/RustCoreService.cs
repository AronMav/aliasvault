//-----------------------------------------------------------------------
// <copyright file="RustCoreService.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Client.Services.JsInterop.RustCore;

using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using AliasVault.Client.Main.Models;
using AliasVault.ImportExport.Exceptions;
using AliasVault.ImportExport.Importers;
using AliasVault.ImportExport.Models;
using AliasVault.ImportExport.Models.Imports;
using Microsoft.JSInterop;

/// <summary>
/// JavaScript interop wrapper for the Rust WASM core library.
/// Provides vault merge and credential matching functionality via WASM.
/// </summary>
public class RustCoreService : IAsyncDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = false,
    };

    private readonly IJSRuntime jsRuntime;
    private bool? isAvailable;

    /// <summary>
    /// Initializes a new instance of the <see cref="RustCoreService"/> class.
    /// </summary>
    /// <param name="jsRuntime">The JS runtime for interop.</param>
    public RustCoreService(IJSRuntime jsRuntime)
    {
        this.jsRuntime = jsRuntime;
    }

    /// <summary>
    /// Check if the Rust WASM module is available.
    /// </summary>
    /// <returns>True if the WASM module is loaded and available.</returns>
    public async Task<bool> IsAvailableAsync()
    {
        // Only return cached result if it's true (successful initialization).
        // If false or null, we should try again since WASM might still be loading.
        if (isAvailable == true)
        {
            return true;
        }

        try
        {
            var result = await jsRuntime.InvokeAsync<bool>("rustCoreIsAvailable");
            if (result)
            {
                isAvailable = true;
            }

            return result;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Merge two vaults using Last-Write-Wins (LWW) strategy.
    /// </summary>
    /// <param name="input">The merge input containing local and server tables.</param>
    /// <returns>The merge output with SQL statements to execute.</returns>
    /// <exception cref="InvalidOperationException">Thrown if merge fails or WASM module is unavailable.</exception>
    public async Task<MergeOutput> MergeVaultsAsync(MergeInput input)
    {
        // Wait for WASM to be available with retries, as it may still be loading.
        if (!await WaitForAvailabilityAsync())
        {
            throw new InvalidOperationException("Rust WASM module is not available.");
        }

        var inputJson = JsonSerializer.Serialize(input, JsonOptions);
        var resultJson = await jsRuntime.InvokeAsync<string>("rustCoreMergeVaults", inputJson);

        if (string.IsNullOrEmpty(resultJson))
        {
            throw new InvalidOperationException("Merge operation returned empty result.");
        }

        var result = JsonSerializer.Deserialize<MergeOutput>(resultJson, JsonOptions);
        if (result == null)
        {
            throw new InvalidOperationException("Failed to deserialize merge result.");
        }

        if (!result.Success && !string.IsNullOrEmpty(result.Error))
        {
            throw new InvalidOperationException($"Merge failed: {result.Error}");
        }

        return result;
    }

    /// <summary>
    /// Get the list of table names that need to be synced.
    /// </summary>
    /// <returns>Array of table names.</returns>
    /// <exception cref="InvalidOperationException">Thrown if WASM module is unavailable.</exception>
    public async Task<string[]> GetSyncableTableNamesAsync()
    {
        // Wait for WASM to be available with retries, as it may still be loading.
        if (!await WaitForAvailabilityAsync())
        {
            throw new InvalidOperationException("Rust WASM module is not available.");
        }

        var result = await jsRuntime.InvokeAsync<string[]>("rustCoreGetSyncableTableNames");
        if (result == null || result.Length == 0)
        {
            throw new InvalidOperationException("Failed to get syncable table names from Rust WASM.");
        }

        return result;
    }

    /// <summary>
    /// Get the per-table SELECT queries used to build prune input.
    /// </summary>
    /// <returns>List of table queries.</returns>
    /// <exception cref="InvalidOperationException">Thrown if WASM module is unavailable.</exception>
    public async Task<List<PruneTableQuery>> GetPruneTableQueriesAsync()
    {
        // Wait for WASM to be available with retries, as it may still be loading.
        if (!await WaitForAvailabilityAsync())
        {
            throw new InvalidOperationException("Rust WASM module is not available.");
        }

        var result = await jsRuntime.InvokeAsync<List<PruneTableQuery>>("rustCoreGetPruneTableQueries");
        if (result == null || result.Count == 0)
        {
            throw new InvalidOperationException("Failed to get prune table queries from Rust WASM.");
        }

        return result;
    }

    /// <summary>
    /// Prune expired items from trash.
    /// Items that have been in trash (DeletedAt set) for longer than retentionDays
    /// are permanently deleted (IsDeleted = true).
    /// </summary>
    /// <param name="input">The prune input containing table data and retention period.</param>
    /// <returns>The prune output with SQL statements to execute.</returns>
    /// <exception cref="InvalidOperationException">Thrown if prune fails or WASM module is unavailable.</exception>
    public async Task<PruneOutput> PruneVaultAsync(PruneInput input)
    {
        // Wait for WASM to be available with retries, as it may still be loading.
        if (!await WaitForAvailabilityAsync())
        {
            throw new InvalidOperationException("Rust WASM module is not available.");
        }

        var inputJson = JsonSerializer.Serialize(input, JsonOptions);
        var resultJson = await jsRuntime.InvokeAsync<string>("rustCorePruneVault", inputJson);

        if (string.IsNullOrEmpty(resultJson))
        {
            throw new InvalidOperationException("Prune operation returned empty result.");
        }

        var result = JsonSerializer.Deserialize<PruneOutput>(resultJson, JsonOptions);
        if (result == null)
        {
            throw new InvalidOperationException("Failed to deserialize prune result.");
        }

        if (!result.Success && !string.IsNullOrEmpty(result.Error))
        {
            throw new InvalidOperationException($"Prune failed: {result.Error}");
        }

        return result;
    }

    /// <summary>
    /// Extract domain from URL.
    /// </summary>
    /// <param name="url">The URL to extract domain from.</param>
    /// <returns>The extracted domain.</returns>
    public async Task<string> ExtractDomainAsync(string url)
    {
        if (!await IsAvailableAsync())
        {
            return string.Empty;
        }

        try
        {
            return await jsRuntime.InvokeAsync<string>("rustCoreExtractDomain", url);
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Extract root domain from a domain string.
    /// </summary>
    /// <param name="domain">The domain to extract root from.</param>
    /// <returns>The root domain.</returns>
    public async Task<string> ExtractRootDomainAsync(string domain)
    {
        if (!await IsAvailableAsync())
        {
            return string.Empty;
        }

        try
        {
            return await jsRuntime.InvokeAsync<string>("rustCoreExtractRootDomain", domain);
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Generate a random salt for SRP registration.
    /// </summary>
    /// <returns>64-character uppercase hex string (32 bytes).</returns>
    /// <exception cref="InvalidOperationException">Thrown if WASM module is unavailable.</exception>
    public async Task<string> SrpGenerateSaltAsync()
    {
        if (!await WaitForAvailabilityAsync())
        {
            throw new InvalidOperationException("Rust WASM module is not available.");
        }

        return await jsRuntime.InvokeAsync<string>("rustCoreSrpGenerateSalt");
    }

    /// <summary>
    /// Derive a private key from salt, identity, and password hash.
    /// </summary>
    /// <param name="salt">The salt (hex string).</param>
    /// <param name="identity">The SRP identity (username or GUID), will be lowercased.</param>
    /// <param name="passwordHash">The password hash (hex string).</param>
    /// <returns>64-character uppercase hex string (32 bytes).</returns>
    /// <exception cref="InvalidOperationException">Thrown if WASM module is unavailable.</exception>
    public async Task<string> SrpDerivePrivateKeyAsync(string salt, string identity, string passwordHash)
    {
        if (!await WaitForAvailabilityAsync())
        {
            throw new InvalidOperationException("Rust WASM module is not available.");
        }

        // Make sure the identity is lowercase as the SRP protocol is case sensitive.
        identity = identity.ToLowerInvariant();

        return await jsRuntime.InvokeAsync<string>("rustCoreSrpDerivePrivateKey", salt, identity, passwordHash);
    }

    /// <summary>
    /// Derive a verifier from a private key.
    /// </summary>
    /// <param name="privateKey">The private key (hex string).</param>
    /// <returns>512-character uppercase hex string (256 bytes).</returns>
    /// <exception cref="InvalidOperationException">Thrown if WASM module is unavailable.</exception>
    public async Task<string> SrpDeriveVerifierAsync(string privateKey)
    {
        if (!await WaitForAvailabilityAsync())
        {
            throw new InvalidOperationException("Rust WASM module is not available.");
        }

        return await jsRuntime.InvokeAsync<string>("rustCoreSrpDeriveVerifier", privateKey);
    }

    /// <summary>
    /// Generate client ephemeral keypair.
    /// </summary>
    /// <returns>Ephemeral object with Public and Secret hex strings.</returns>
    /// <exception cref="InvalidOperationException">Thrown if WASM module is unavailable.</exception>
    public async Task<SrpEphemeral> SrpGenerateEphemeralAsync()
    {
        if (!await WaitForAvailabilityAsync())
        {
            throw new InvalidOperationException("Rust WASM module is not available.");
        }

        return await jsRuntime.InvokeAsync<SrpEphemeral>("rustCoreSrpGenerateEphemeral");
    }

    /// <summary>
    /// Derive client session from ephemeral values.
    /// </summary>
    /// <param name="clientSecret">Client ephemeral secret (hex string).</param>
    /// <param name="serverPublic">Server ephemeral public (hex string).</param>
    /// <param name="salt">The salt (hex string).</param>
    /// <param name="identity">The SRP identity, will be lowercased.</param>
    /// <param name="privateKey">The private key (hex string).</param>
    /// <returns>Session object with Key and Proof hex strings.</returns>
    /// <exception cref="InvalidOperationException">Thrown if WASM module is unavailable.</exception>
    public async Task<SrpSession> SrpDeriveSessionAsync(string clientSecret, string serverPublic, string salt, string identity, string privateKey)
    {
        if (!await WaitForAvailabilityAsync())
        {
            throw new InvalidOperationException("Rust WASM module is not available.");
        }

        // Make sure the identity is lowercase as the SRP protocol is case sensitive.
        identity = identity.ToLowerInvariant();

        return await jsRuntime.InvokeAsync<SrpSession>("rustCoreSrpDeriveSession", clientSecret, serverPublic, salt, identity, privateKey);
    }

    /// <summary>
    /// Derive session client-side (convenience method with reordered parameters).
    /// </summary>
    /// <param name="privateKey">The private key.</param>
    /// <param name="clientSecretEphemeral">Client ephemeral secret.</param>
    /// <param name="serverEphemeralPublic">Server public ephemeral.</param>
    /// <param name="salt">Salt.</param>
    /// <param name="identity">Identity.</param>
    /// <returns>SrpSession.</returns>
    public async Task<SrpSession> SrpDeriveSessionClientAsync(string privateKey, string clientSecretEphemeral, string serverEphemeralPublic, string salt, string identity)
    {
        return await SrpDeriveSessionAsync(clientSecretEphemeral, serverEphemeralPublic, salt, identity, privateKey);
    }

    /// <summary>
    /// Verify the server's session proof (M2) on the client side.
    /// </summary>
    /// <param name="clientPublic">Client public ephemeral (A).</param>
    /// <param name="clientSession">Client session containing proof (M1) and key (K).</param>
    /// <param name="serverProof">Server proof (M2) to verify.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <exception cref="InvalidOperationException">Thrown if WASM module is unavailable.</exception>
    /// <exception cref="System.Security.SecurityException">Thrown if verification fails.</exception>
    public async Task SrpVerifySessionAsync(string clientPublic, SrpSession clientSession, string serverProof)
    {
        if (!await WaitForAvailabilityAsync())
        {
            throw new InvalidOperationException("Rust WASM module is not available.");
        }

        var result = await jsRuntime.InvokeAsync<bool>("rustCoreSrpVerifySession", clientPublic, clientSession.Proof, clientSession.Key, serverProof);

        if (!result)
        {
            throw new System.Security.SecurityException("Server session proof verification failed.");
        }
    }

    /// <summary>
    /// Generate a cryptographically random 32-byte RNG seed as a 64-character lowercase hex string.
    /// Supplying the same seed to <see cref="GenerateRandomPasswordAsync"/> yields the same output,
    /// so the UI can re-apply formatting options to the same underlying password/words for easy comparison.
    /// </summary>
    /// <returns>A 64-character lowercase hex string.</returns>
    public string GenerateSeed()
    {
        return Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
    }

    /// <summary>
    /// Generate a password or passphrase using the Rust core.
    /// The <see cref="PasswordSettings.Type"/> field selects the generator ("basic" or "diceware").
    /// </summary>
    /// <param name="settings">The password settings to use.</param>
    /// <param name="seed">Optional 64-character hex RNG seed for deterministic generation; pass null for a fresh random password.</param>
    /// <returns>The generated password/passphrase.</returns>
    /// <exception cref="InvalidOperationException">Thrown if generation fails or WASM module is unavailable.</exception>
    public async Task<string> GenerateRandomPasswordAsync(PasswordSettings settings, string? seed = null)
    {
        if (!await WaitForAvailabilityAsync())
        {
            throw new InvalidOperationException("Rust WASM module is not available.");
        }

        // Serialize to a JSON object. The PasswordSettings properties carry explicit [JsonPropertyName]
        // attributes (PascalCase), which the Rust core expects, so the naming policy is irrelevant here.
        if (JsonSerializer.SerializeToNode(settings) is not JsonObject node)
        {
            throw new InvalidOperationException("Failed to serialize password settings.");
        }

        if (!string.IsNullOrEmpty(seed))
        {
            node["Seed"] = seed;
        }

        // Resolve the effective passphrase language when none is explicitly chosen ("auto"). Pick the
        // most appropriate available Diceware wordlist for the current app language using the shared
        // region-variant table (e.g. "de-CH" -> "de"), falling back to English.
        if (string.Equals(settings.Type, "diceware", StringComparison.OrdinalIgnoreCase)
            && string.IsNullOrWhiteSpace(settings.Language))
        {
            var codes = await GetDicewareLanguagesAsync();
            var appLanguage = System.Globalization.CultureInfo.CurrentCulture.Name;
            node["Language"] = Languages.ResolveDefaultLanguage(appLanguage, codes);
        }

        return await jsRuntime.InvokeAsync<string>("rustCoreGeneratePassword", node.ToJsonString());
    }

    /// <summary>
    /// Get the list of bundled Diceware wordlist language codes (first is the default, English).
    /// </summary>
    /// <returns>Array of language codes.</returns>
    public async Task<string[]> GetDicewareLanguagesAsync()
    {
        if (!await IsAvailableAsync())
        {
            return ["en"];
        }

        try
        {
            var languages = await jsRuntime.InvokeAsync<string[]>("rustCoreGetDicewareLanguages");
            return languages is { Length: > 0 } ? languages : ["en"];
        }
        catch
        {
            return ["en"];
        }
    }

    /// <summary>
    /// Opens a KDBX (KeePass) database in the Rust core and returns its mapped contents.
    /// </summary>
    /// <param name="fileBytes">The .kdbx file contents.</param>
    /// <param name="password">The master password.</param>
    /// <returns>The parsed database contents.</returns>
    /// <exception cref="InvalidImportPasswordException">Thrown when the password does not decrypt the database.</exception>
    /// <exception cref="ImportException">Thrown when the database cannot be read.</exception>
    public async Task<KdbxImportResult> KdbxOpenAsync(byte[] fileBytes, string password)
    {
        if (!await WaitForAvailabilityAsync())
        {
            throw new InvalidOperationException("Rust WASM module is not available.");
        }

        string json;
        try
        {
            json = await jsRuntime.InvokeAsync<string>("rustCoreKdbxOpen", fileBytes, password);
        }
        catch (JSException ex) when (ex.Message.Contains("invalid password", StringComparison.OrdinalIgnoreCase))
        {
            // The message is replaced rather than passed on. The import card copies exception
            // messages, inner ones included, into the diagnostic block that users paste into
            // bug reports, and this message originates outside our control: it is whatever the
            // JavaScript bridge surfaced from the parser. Only text we wrote gets that far.
            throw new InvalidImportPasswordException(
                "The password did not open this database. It may also be protected by a key file, which is not supported.");
        }
        catch (JSException)
        {
            throw new ImportException(ImportStage.Parse, "The database could not be read.");
        }

        return JsonSerializer.Deserialize<KdbxImportResult>(json, JsonOptions)
            ?? throw new ImportException(ImportStage.Parse, "The Rust core returned an empty KDBX result.");
    }

    /// <summary>
    /// Opens a KDBX database and maps its whole contents, attachments included.
    /// </summary>
    /// <remarks>
    /// Owns the session from end to end so that callers cannot leave one open: the blobs stay
    /// in WebAssembly memory until the session is closed, and an import that throws halfway
    /// would otherwise strand them there.
    /// </remarks>
    /// <param name="fileBytes">The .kdbx file contents.</param>
    /// <param name="password">The master password.</param>
    /// <returns>The parsed credentials, per-item failures and informational notes.</returns>
    /// <exception cref="InvalidImportPasswordException">Thrown when the password does not decrypt the database.</exception>
    /// <exception cref="ImportException">Thrown when the database cannot be read.</exception>
    public async Task<ImportFileResult> ImportKdbxAsync(byte[] fileBytes, string password)
    {
        var result = await KdbxOpenAsync(fileBytes, password);

        try
        {
            return await KdbxImporter.MapToCredentials(
                result,
                attachmentId => KdbxTakeAttachmentAsync(result.SessionId, attachmentId));
        }
        finally
        {
            await KdbxCloseAsync(result.SessionId);
        }
    }

    /// <summary>
    /// Takes one attachment blob from an open session, releasing it in the Rust core.
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="attachmentId">The attachment identifier.</param>
    /// <returns>The blob, or null when it was already taken or is unknown.</returns>
    public async Task<byte[]?> KdbxTakeAttachmentAsync(string sessionId, string attachmentId)
    {
        return await jsRuntime.InvokeAsync<byte[]?>("rustCoreKdbxTakeAttachment", sessionId, attachmentId);
    }

    /// <summary>
    /// Releases a session and any blobs it still holds.
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <returns>Async task.</returns>
    public async Task KdbxCloseAsync(string sessionId)
    {
        await jsRuntime.InvokeVoidAsync("rustCoreKdbxClose", sessionId);
    }

    /// <inheritdoc/>
    public ValueTask DisposeAsync()
    {
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Wait for the Rust WASM module to become available with retries.
    /// Uses exponential backoff for more robust loading in slow environments (e.g., E2E tests, mobile devices).
    /// Default timeout is ~30 seconds to handle slow network conditions.
    /// </summary>
    /// <param name="maxRetries">Maximum number of retry attempts.</param>
    /// <param name="initialDelayMs">Initial delay between retries in milliseconds.</param>
    /// <returns>True if the WASM module became available.</returns>
    private async Task<bool> WaitForAvailabilityAsync(int maxRetries = 30, int initialDelayMs = 100)
    {
        var currentDelay = initialDelayMs;

        for (int i = 0; i < maxRetries; i++)
        {
            if (await IsAvailableAsync())
            {
                return true;
            }

            await Task.Delay(currentDelay);

            // Exponential backoff with cap at 2 seconds
            currentDelay = Math.Min(currentDelay * 2, 2000);
        }

        return false;
    }
}
