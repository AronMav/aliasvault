//-----------------------------------------------------------------------
// <copyright file="KdbxImporter.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.ImportExport.Importers;

using System.Globalization;
using AliasVault.ImportExport.Models;
using AliasVault.ImportExport.Models.Imports;

/// <summary>
/// Adapts the neutral KDBX model produced by the Rust core into ImportedCredential objects.
/// </summary>
/// <remarks>
/// All knowledge of KeePass field names lives in the Rust core. This class only reshapes
/// the neutral model, which is why it stays free of format specific rules.
/// </remarks>
public static class KdbxImporter
{
    /// <summary>
    /// Maps a parsed KDBX database onto ImportedCredential objects and pulls the attachment blobs.
    /// </summary>
    /// <param name="result">The parse result returned by the Rust core.</param>
    /// <param name="takeAttachment">
    /// Fetches one attachment blob by its id. Returns null when the blob is no longer
    /// available, which is reported as a per-item failure rather than failing the import.
    /// </param>
    /// <returns>The credentials, per-item failures and informational notes.</returns>
    public static async Task<ImportFileResult> MapToCredentials(
        KdbxImportResult result,
        Func<string, Task<byte[]?>> takeAttachment)
    {
        var credentials = new List<ImportedCredential>();
        var failures = new List<ImportFailure>();

        for (var index = 0; index < result.Items.Count; index++)
        {
            var item = result.Items[index];

            credentials.Add(new ImportedCredential
            {
                ServiceName = item.Title,
                ServiceUrls = item.Urls.Count > 0 ? item.Urls : null,
                Username = item.Username,
                Password = item.Password,
                TwoFactorSecret = item.Totp,
                Notes = item.Notes,
                FolderPath = item.FolderPath,
                Tags = item.Tags.Count > 0 ? item.Tags : null,
                CreatedAt = ParseTimestamp(item.CreatedAt),
                UpdatedAt = ParseTimestamp(item.UpdatedAt),
                CustomFieldValues = MapCustomFields(item.CustomFields),
                Attachments = await TakeAttachments(item, index, takeAttachment, failures),
            });
        }

        return new ImportFileResult
        {
            Credentials = credentials,
            FailedItems = failures,
            Notes = BuildNotes(result.Skipped),
        };
    }

    /// <summary>
    /// Reshapes the neutral custom fields, whose shape does not match one to one.
    /// </summary>
    /// <param name="fields">The neutral custom fields.</param>
    /// <returns>The mapped values, or null when the entry has none.</returns>
    private static List<ImportedCustomField>? MapCustomFields(List<KdbxCustomField> fields)
    {
        if (fields.Count == 0)
        {
            return null;
        }

        return fields
            .Select(field => new ImportedCustomField
            {
                // Each field becomes its own definition: KeePass has no notion of
                // multi-value fields sharing one definition.
                DefinitionId = Guid.NewGuid(),
                Label = field.Name,
                Value = field.Value,
                FieldType = field.IsProtected
                    ? AliasClientDb.Models.FieldTypeKind.Password
                    : AliasClientDb.Models.FieldTypeKind.Text,
                IsHidden = field.IsProtected,
            })
            .ToList();
    }

    /// <summary>
    /// Pulls every attachment blob for one item.
    /// </summary>
    /// <param name="item">The item whose attachments are fetched.</param>
    /// <param name="index">Zero-based position of the item, used for failure reporting.</param>
    /// <param name="takeAttachment">Fetches one blob by id.</param>
    /// <param name="failures">Collects blobs that could not be retrieved.</param>
    /// <returns>The attachments that were retrieved, or null when none were.</returns>
    private static async Task<List<ImportedAttachment>?> TakeAttachments(
        KdbxItem item,
        int index,
        Func<string, Task<byte[]?>> takeAttachment,
        List<ImportFailure> failures)
    {
        if (item.Attachments.Count == 0)
        {
            return null;
        }

        var attachments = new List<ImportedAttachment>();

        foreach (var meta in item.Attachments)
        {
            var blob = await takeAttachment(meta.Id);
            if (blob == null)
            {
                // Losing one attachment must not cost the user the whole entry,
                // so this is reported instead of thrown.
                failures.Add(new ImportFailure
                {
                    Index = index,
                    ItemTitle = item.Title,
                    ExceptionType = nameof(InvalidOperationException),
                    Message = $"Attachment '{meta.Filename}' could not be read from the database and was skipped.",
                });
                continue;
            }

            attachments.Add(new ImportedAttachment
            {
                Filename = meta.Filename,
                Blob = blob,
            });
        }

        return attachments.Count > 0 ? attachments : null;
    }

    /// <summary>
    /// Parses an ISO 8601 timestamp produced by the Rust core into a UTC DateTime.
    /// </summary>
    /// <param name="value">The timestamp string, or null.</param>
    /// <returns>The parsed timestamp, or null when absent or unparseable.</returns>
    private static DateTime? ParseTimestamp(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        return DateTime.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal,
            out var parsed)
            ? parsed
            : null;
    }

    /// <summary>
    /// Turns the skip counters into messages for the preview step.
    /// Content that was deliberately left out must be visible, not silently missing.
    /// </summary>
    /// <param name="skipped">The skip counters.</param>
    /// <returns>One message per non-zero counter.</returns>
    private static List<string> BuildNotes(KdbxSkipped skipped)
    {
        var notes = new List<string>();

        if (skipped.RecycleBin > 0)
        {
            notes.Add($"{skipped.RecycleBin} entries in the KeePass recycle bin were not imported.");
        }

        if (skipped.History > 0)
        {
            notes.Add($"{skipped.History} previous versions of entries were not imported, only the current version of each entry.");
        }

        if (skipped.MaxDepthExceeded > 0)
        {
            notes.Add($"{skipped.MaxDepthExceeded} entries in deeply nested groups were not imported. The importer supports up to 100 levels of group nesting.");
        }

        return notes;
    }
}
