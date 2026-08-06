//-----------------------------------------------------------------------
// <copyright file="KdbxImportTests.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.E2ETests.Tests.Client.Shard3;

/// <summary>
/// End-to-end tests for importing a KeePass .kdbx database, including its file attachment.
/// </summary>
/// <remarks>
/// The database is produced by an actual KeePassXC release rather than by our own writer.
/// Attachments are the reason this path exists at all: KeePassXC omits them from both its
/// CSV and its XML exports, so the database file is the only way to carry them over.
/// </remarks>
[Parallelizable(ParallelScope.Self)]
[Category("ClientTests")]
[TestFixture]
public class KdbxImportTests : VaultImportTestsBase
{
    /// <summary>
    /// The master password of the test database. See core/rust/src/kdbx/testdata/README.md.
    /// </summary>
    private const string TestKdbxPassword = "testkdbxpass123";

    /// <summary>
    /// Test that a .kdbx database is imported through the KeePassXC card, and that the
    /// attachment it carries arrives with it.
    /// </summary>
    /// <returns>Async task.</returns>
    [Test]
    [Order(1)]
    public async Task ImportKdbxFileWithAttachment()
    {
        var kdbxBytes = await ResourceReaderUtility.ReadEmbeddedResourceBytesAsync(
            "AliasVault.E2ETests.TestData.TestKeePassWithAttachment.kdbx");

        Assert.That(kdbxBytes, Is.Not.Null);
        Assert.That(kdbxBytes.Length, Is.GreaterThan(0), ".kdbx file should not be empty");

        await NavigateUsingBlazorRouter("settings/import-export");
        await WaitForUrlAsync("settings/import-export", "Import / Export");

        await Page.ClickAsync("[data-import-service='KeePassXC']");
        await Page.WaitForSelectorAsync("input[type='file']", new() { State = WaitForSelectorState.Visible });

        var tempFilePath = Path.Combine(Path.GetTempPath(), $"test-import-{Guid.NewGuid()}.kdbx");
        await File.WriteAllBytesAsync(tempFilePath, kdbxBytes);

        try
        {
            var fileInput = Page.Locator("input[type='file']");
            await fileInput.SetInputFilesAsync(tempFilePath);

            await Page.WaitForSelectorAsync("input[type='password']", new() { State = WaitForSelectorState.Visible, Timeout = 30000 });
            await Page.FillAsync("input[type='password']", TestKdbxPassword);

            // Argon2 runs in the browser here, so this step is measured in seconds
            // rather than milliseconds and needs a longer timeout than the other cards.
            await Page.ClickAsync("button:has-text('Decrypt')");
            await Page.WaitForSelectorAsync("text=Example", new() { State = WaitForSelectorState.Visible, Timeout = 60000 });

            // The preview must report the attachment that a CSV import could never carry. Match the
            // detection count, not the word "attachment": the card's own instructions mention file
            // attachments, so a looser match passes whether or not anything was detected.
            var previewContent = await Page.TextContentAsync("body");
            Assert.That(previewContent, Does.Contain("1 attachment(s)"), "Preview should report the detected attachment");

            await Page.WaitForSelectorAsync("button:has-text('Next')", new() { State = WaitForSelectorState.Visible, Timeout = 10000 });
            await Page.ClickAsync("text=Next");

            await Page.WaitForSelectorAsync("button:has-text('Import')");
            await Page.ClickAsync("button:has-text('Import')");
            await Page.WaitForSelectorAsync("text=Successfully imported", new() { Timeout = 30000 });

            // The imported entry must be visible in the vault itself, not just in the preview.
            await NavigateUsingBlazorRouter("items");
            await WaitForUrlAsync("items", "Example");

            // And the attachment has to have travelled with it. This is the whole reason the
            // .kdbx path exists, so the test is only worth anything if it checks the file landed.
            await Page.ClickAsync("text=Example");
            await Page.WaitForURLAsync("**/items/*", new() { Timeout = 5000 });
            await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

            var itemContent = await Page.TextContentAsync("body");
            Assert.That(itemContent, Does.Contain("notes.txt"), "The attachment from the database should be on the imported item");
        }
        finally
        {
            if (File.Exists(tempFilePath))
            {
                File.Delete(tempFilePath);
            }
        }
    }

    /// <summary>
    /// Test that a wrong master password is reported as such and does not leave the user
    /// staring at a generic failure.
    /// </summary>
    /// <returns>Async task.</returns>
    [Test]
    [Order(2)]
    public async Task ImportKdbxFileWithWrongPassword()
    {
        var kdbxBytes = await ResourceReaderUtility.ReadEmbeddedResourceBytesAsync(
            "AliasVault.E2ETests.TestData.TestKeePassWithAttachment.kdbx");

        await NavigateUsingBlazorRouter("settings/import-export");
        await WaitForUrlAsync("settings/import-export", "Import / Export");

        await Page.ClickAsync("[data-import-service='KeePassXC']");
        await Page.WaitForSelectorAsync("input[type='file']", new() { State = WaitForSelectorState.Visible });

        var tempFilePath = Path.Combine(Path.GetTempPath(), $"test-import-{Guid.NewGuid()}.kdbx");
        await File.WriteAllBytesAsync(tempFilePath, kdbxBytes);

        try
        {
            var fileInput = Page.Locator("input[type='file']");
            await fileInput.SetInputFilesAsync(tempFilePath);

            await Page.WaitForSelectorAsync("input[type='password']", new() { State = WaitForSelectorState.Visible, Timeout = 30000 });
            await Page.FillAsync("input[type='password']", "wrongpassword123");
            await Page.ClickAsync("button:has-text('Decrypt')");

            // Assert on the message the card actually shows for a rejected password. Looking for
            // the word "password" anywhere on the page passes on the password prompt that is
            // already there, so it would stay green while the app blamed the file instead.
            await Page.WaitForSelectorAsync(
                "text=Incorrect password",
                new() { State = WaitForSelectorState.Visible, Timeout = 30000 });

            var pageContent = await Page.TextContentAsync("body");
            Assert.That(
                pageContent,
                Does.Not.Contain("could not be read"),
                "A mistyped password must not be reported as an unreadable file");
        }
        finally
        {
            if (File.Exists(tempFilePath))
            {
                File.Delete(tempFilePath);
            }
        }
    }
}
