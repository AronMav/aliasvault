//-----------------------------------------------------------------------
// <copyright file="KdbxImportCard.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Client.Main.Pages.Settings.ImportExport.Components;

using AliasVault.Client.Services.JsInterop.RustCore;
using AliasVault.ImportExport.Models;

/// <summary>
/// What the KeePass and KeePassXC import cards share.
/// </summary>
/// <remarks>
/// The two cards differ only in their CSV importer and their instructions; the database format is the
/// same one, opened by the same parser. Keeping the .kdbx wiring here means a change to it -- passing
/// the filename through, key file support, different error mapping -- is made once instead of twice
/// in files that would otherwise be free to drift apart without anything noticing.
/// </remarks>
public static class KdbxImportCard
{
    /// <summary>
    /// Gets the file extensions both cards accept.
    /// </summary>
    public static string[] AcceptedExtensions { get; } = [".csv", ".kdbx"];

    /// <summary>
    /// Gets the accepted extensions that need a password before they can be read.
    /// </summary>
    public static string[] PasswordProtectedExtensions { get; } = [".kdbx"];

    /// <summary>
    /// Builds the callback that opens a .kdbx database, pulls its attachments and maps the result.
    /// </summary>
    /// <param name="rustCore">The Rust core service that holds the parser.</param>
    /// <returns>A callback in the shape the import card expects.</returns>
    public static Func<byte[], string, string, Task<ImportFileResult>> DecryptFile(RustCoreService rustCore)
    {
        return (fileBytes, _, password) => rustCore.ImportKdbxAsync(fileBytes, password);
    }
}
