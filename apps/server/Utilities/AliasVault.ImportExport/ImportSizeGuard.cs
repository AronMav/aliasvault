//-----------------------------------------------------------------------
// <copyright file="ImportSizeGuard.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.ImportExport;

/// <summary>
/// Decides whether an import can still fit within the server's upload limit.
/// </summary>
/// <remarks>
/// Kept out of the UI so the arithmetic is unit testable. Both checks return false
/// when the limit is unknown: an older server does not report one, and refusing an
/// import on a guess would be worse than letting the existing HTTP 413 path handle it.
/// </remarks>
public static class ImportSizeGuard
{
    /// <summary>
    /// Vault size, in bytes, above which saving is expected to fail in the browser.
    /// </summary>
    /// <remarks>
    /// Saving a vault means serializing it into a single upload body, and the browser's
    /// WebAssembly heap is capped at 2 GB. Measured on a desktop browser: a vault of roughly
    /// 38 MB (20 MB of attachments) saved fine, 40 MB of attachments ran out of memory. The
    /// ceiling here sits below the measured pass so that machines with less headroom, or a
    /// vault that already holds other data, still stay on the safe side.
    /// </remarks>
    public const long BrowserVaultCeilingBytes = 30L * 1024 * 1024;

    /// <summary>
    /// Checks whether the source file alone already exceeds the upload limit.
    /// </summary>
    /// <remarks>
    /// Runs before the password prompt. A database this large cannot fit into the
    /// vault under any circumstances, so there is no reason to spend Argon2 on it or
    /// to load it into the browser's 32 bit heap.
    /// </remarks>
    /// <param name="fileSizeBytes">Size of the uploaded file in bytes.</param>
    /// <param name="maxUploadSizeMb">The server's limit in megabytes, or null when unknown.</param>
    /// <returns>True when the file cannot possibly fit.</returns>
    public static bool ExceedsUploadLimit(long fileSizeBytes, int? maxUploadSizeMb)
    {
        if (maxUploadSizeMb is not > 0)
        {
            return false;
        }

        return fileSizeBytes > (long)maxUploadSizeMb.Value * 1024 * 1024;
    }

    /// <summary>
    /// Checks whether the vault would outgrow the upload limit once the import is applied.
    /// </summary>
    /// <remarks>
    /// Runs at the preview step, where the attachment sizes are known. Warning here
    /// keeps the user from ending up with a local vault that can no longer sync.
    /// </remarks>
    /// <param name="vaultSizeBytes">Size of the current vault in bytes, before encoding.</param>
    /// <param name="attachmentBytes">Total size of the attachments about to be imported, before encoding.</param>
    /// <param name="maxUploadSizeMb">The server's limit in megabytes, or null when unknown.</param>
    /// <returns>True when the import would push the vault past the limit.</returns>
    public static bool WouldExceedAfterImport(long vaultSizeBytes, long attachmentBytes, int? maxUploadSizeMb)
    {
        if (maxUploadSizeMb is not > 0)
        {
            return false;
        }

        // The server's limit applies to the request body, which carries the vault base64 encoded, so
        // both parts have to be counted the way they will be sent. Scaling only one of them -- the
        // vault, while the attachments about to be added to it stay raw -- understates the result by
        // a third of the import and lets exactly the case this warns about through.
        return Base64Length(vaultSizeBytes + attachmentBytes) > (long)maxUploadSizeMb.Value * 1024 * 1024;
    }

    /// <summary>
    /// Checks whether the vault would grow past what the browser can save at all.
    /// </summary>
    /// <remarks>
    /// This is a client limit, not a server one, and it applies even when the server accepts
    /// far larger uploads. Without it the user waits through a long import and is then told
    /// the save failed, with an empty vault and no explanation of why.
    /// </remarks>
    /// <param name="vaultSizeBytes">Size of the current vault in bytes, before encoding.</param>
    /// <param name="attachmentBytes">Total size of the attachments about to be imported, before encoding.</param>
    /// <returns>True when the resulting vault would be too large for the browser to save.</returns>
    public static bool WouldExceedBrowserLimit(long vaultSizeBytes, long attachmentBytes)
    {
        // Compared before encoding, because the ceiling was measured against vault sizes.
        return vaultSizeBytes + attachmentBytes > BrowserVaultCeilingBytes;
    }

    /// <summary>
    /// Returns how many bytes a payload of the given size occupies once base64 encoded.
    /// </summary>
    /// <remarks>
    /// Base64 grows the payload by four bytes for every three; the AES-GCM nonce and tag that go with
    /// it are negligible next to that and are not counted.
    /// </remarks>
    /// <param name="byteCount">Size of the payload before encoding.</param>
    /// <returns>Size of the encoded payload in bytes.</returns>
    private static long Base64Length(long byteCount)
    {
        return byteCount / 3 * 4;
    }
}
