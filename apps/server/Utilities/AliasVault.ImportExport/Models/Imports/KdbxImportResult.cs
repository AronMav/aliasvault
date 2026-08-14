//-----------------------------------------------------------------------
// <copyright file="KdbxImportResult.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.ImportExport.Models.Imports;

/// <summary>
/// Result of parsing a KDBX (KeePass) database in the Rust core.
/// Property names are PascalCase here and travel as snake_case on the wire,
/// which is what the Rust core produces.
/// </summary>
public class KdbxImportResult
{
    /// <summary>
    /// Gets or sets the handle used to fetch attachment blobs and to release the session.
    /// </summary>
    public string SessionId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the mapped entries.
    /// </summary>
    public List<KdbxItem> Items { get; set; } = new();

    /// <summary>
    /// Gets or sets the counts of deliberately ignored content.
    /// </summary>
    public KdbxSkipped Skipped { get; set; } = new();
}

/// <summary>
/// A single mapped KeePass entry.
/// </summary>
public class KdbxItem
{
    /// <summary>
    /// Gets or sets the entry title.
    /// </summary>
    public string Title { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the username.
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// Gets or sets the password.
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// Gets or sets the notes.
    /// </summary>
    public string? Notes { get; set; }

    /// <summary>
    /// Gets or sets the TOTP value, passed through verbatim (usually an otpauth:// URI).
    /// </summary>
    public string? Totp { get; set; }

    /// <summary>
    /// Gets or sets the slash separated path of the containing group, root excluded.
    /// </summary>
    public string? FolderPath { get; set; }

    /// <summary>
    /// Gets or sets the primary URL followed by any additional URLs.
    /// </summary>
    public List<string> Urls { get; set; } = new();

    /// <summary>
    /// Gets or sets the entry tags.
    /// </summary>
    public List<string> Tags { get; set; } = new();

    /// <summary>
    /// Gets or sets the creation time as an ISO 8601 string in UTC.
    /// </summary>
    public string? CreatedAt { get; set; }

    /// <summary>
    /// Gets or sets the last modification time as an ISO 8601 string in UTC.
    /// </summary>
    public string? UpdatedAt { get; set; }

    /// <summary>
    /// Gets or sets the remaining user defined fields.
    /// </summary>
    public List<KdbxCustomField> CustomFields { get; set; } = new();

    /// <summary>
    /// Gets or sets the metadata of this entry's attachments. Blobs are fetched separately.
    /// </summary>
    public List<KdbxAttachmentMeta> Attachments { get; set; } = new();
}

/// <summary>
/// A user defined field that has no dedicated slot in the model.
/// </summary>
public class KdbxCustomField
{
    /// <summary>
    /// Gets or sets the field name as shown in KeePass.
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the field value.
    /// </summary>
    public string Value { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a value indicating whether KeePass stored the value as a protected field.
    /// </summary>
    public bool IsProtected { get; set; }
}

/// <summary>
/// Attachment metadata. The blob is fetched with a separate call.
/// </summary>
public class KdbxAttachmentMeta
{
    /// <summary>
    /// Gets or sets the index of the blob within the session.
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the attachment file name.
    /// </summary>
    public string Filename { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the blob size in bytes.
    /// </summary>
    public long Size { get; set; }
}

/// <summary>
/// Content that was intentionally not imported.
/// </summary>
public class KdbxSkipped
{
    /// <summary>
    /// Gets or sets the number of entries that live in the recycle bin.
    /// </summary>
    public int RecycleBin { get; set; }

    /// <summary>
    /// Gets or sets the number of historical versions of entries.
    /// </summary>
    public int History { get; set; }

    /// <summary>
    /// Gets or sets the number of entries in groups deeper than the maximum supported depth.
    /// </summary>
    public int MaxDepthExceeded { get; set; }
}
