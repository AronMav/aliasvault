//-----------------------------------------------------------------------
// <copyright file="AuthPasswordChangeTests.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.E2ETests.Tests.Client.Shard5;

using Microsoft.EntityFrameworkCore;

/// <summary>
/// End-to-end tests for authentication.
/// </summary>
[Parallelizable(ParallelScope.Self)]
[Category("ClientTests")]

[TestFixture]
public class AuthPasswordChangeTests : ClientPlaywrightTest
{
    /// <summary>
    /// Test if changing password works correctly.
    /// </summary>
    /// <returns>Async task.</returns>
    [Test]
    [Order(1)]
    public async Task PasswordChangeTest()
    {
        // Advance time by 1 second manually to ensure the new vault is created in the future.
        ApiTimeProvider.AdvanceBy(TimeSpan.FromSeconds(1));

        var serviceNameBefore = "Item service before";
        await CreateItemEntry(new Dictionary<string, string>
        {
            { "service-name", serviceNameBefore },
        });

        // Check that the service name is present in the content.
        var pageContent = await Page.TextContentAsync("body");
        Assert.That(pageContent, Does.Contain(serviceNameBefore), "Created item service name does not appear on login page.");

        // Attempt to change password.
        await NavigateUsingBlazorRouter("settings/security/change-password");
        await WaitForUrlAsync("settings/security/change-password", "Current Password");

        // Fill in the form.
        var currentPasswordField = await WaitForAndGetElement("input[id='currentPassword']");
        var newPasswordField = await WaitForAndGetElement("input[id='newPassword']");
        var confirmPasswordField = await WaitForAndGetElement("input[id='newPasswordConfirm']");

        var newPassword = TestUserPassword + "123";

        await currentPasswordField.FillAsync(TestUserPassword);
        await newPasswordField.FillAsync(newPassword);
        await confirmPasswordField.FillAsync(newPassword);

        // Advance time by 1 second manually to ensure the new vault (encrypted with new password) is created in the future.
        ApiTimeProvider.AdvanceBy(TimeSpan.FromSeconds(1));

        // Click the change password button.
        var changePasswordButton = Page.Locator("button:has-text('Change Password')");
        await changePasswordButton.ClickAsync();

        // Wait for success message.
        await WaitForUrlAsync("settings/security/change-password**", "Password changed successfully.");

        // Update test user password to new password so next actions will use the new password.
        TestUserPassword = newPassword;

        // Test refresh and unlock with new password.
        await RefreshPageAndUnlockVault();

        // Test logging in again with new password.
        // Logout.
        await Logout();
        await Login();

        // Wait for the items page to load again.
        await WaitForUrlAsync("items**", serviceNameBefore);

        // Check if the service name is still present in the content.
        pageContent = await Page.TextContentAsync("body");
        Assert.That(pageContent, Does.Contain(serviceNameBefore), "Created item service name does not appear on login page after hard page reload. Check if the database is correctly persisted and then loaded from the server.");

        // The vault has to keep the key derivation parameters this instance registers accounts with.
        // This deployment overrides them (see CryptographyOverrideSettings above), and a password
        // change that quietly swapped in the build's own defaults would hand a user a vault whose
        // parameters their deployment never chose --- on a deployment that lowered them for a slow
        // device, one that device can no longer open.
        var vaults = await ApiDbContext.Vaults
            .Where(x => x.User.UserName == TestUserUsername)
            .OrderBy(x => x.RevisionNumber)
            .Select(x => new { x.RevisionNumber, x.EncryptionType, x.EncryptionSettings })
            .ToListAsync();

        Assert.That(vaults, Is.Not.Empty, "No vaults found for the test user.");
        Assert.Multiple(() =>
        {
            foreach (var vault in vaults)
            {
                Assert.That(vault.EncryptionType, Is.EqualTo("Argon2Id"), $"Vault revision {vault.RevisionNumber} records an unexpected encryption type.");
                Assert.That(vault.EncryptionSettings, Is.EqualTo(TestEncryptionSettings), $"Vault revision {vault.RevisionNumber} records different key derivation parameters than the ones this instance registers accounts with.");
            }
        });
    }
}
