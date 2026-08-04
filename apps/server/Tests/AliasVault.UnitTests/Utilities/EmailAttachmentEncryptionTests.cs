//-----------------------------------------------------------------------
// <copyright file="EmailAttachmentEncryptionTests.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.UnitTests.Utilities;

using System.Text;
using AliasServerDb;
using AliasVault.Cryptography.Server;

/// <summary>
/// Tests that attachment metadata is covered by the email encryption, so the server
/// cannot read the names of the files its users receive.
/// </summary>
public class EmailAttachmentEncryptionTests
{
    /// <summary>
    /// Tests that the filename of an attachment is not readable after encryption.
    /// </summary>
    [Test]
    public void AttachmentFilenameIsEncrypted()
    {
        var email = CreateEmailWithAttachment("passport_scan.pdf", "application/pdf");

        EmailEncryption.EncryptEmail(email, CreateEncryptionKey());

        Assert.That(email.Attachments[0].Filename, Is.Not.EqualTo("passport_scan.pdf"));
    }

    /// <summary>
    /// Tests that the MIME type of an attachment is not readable after encryption.
    /// </summary>
    [Test]
    public void AttachmentMimeTypeIsEncrypted()
    {
        var email = CreateEmailWithAttachment("passport_scan.pdf", "application/pdf");

        EmailEncryption.EncryptEmail(email, CreateEncryptionKey());

        Assert.That(email.Attachments[0].MimeType, Is.Not.EqualTo("application/pdf"));
    }

    /// <summary>
    /// Tests that attachment metadata survives an encrypt/decrypt round trip.
    /// </summary>
    [Test]
    public void AttachmentMetadataSurvivesRoundTrip()
    {
        var email = CreateEmailWithAttachment("passport_scan.pdf", "application/pdf");

        EmailEncryption.EncryptEmail(email, CreateEncryptionKey());
        EmailEncryption.DecryptEmail(email, RsaEncryptionTests.PrivateKey);

        Assert.Multiple(() =>
        {
            Assert.That(email.Attachments[0].Filename, Is.EqualTo("passport_scan.pdf"));
            Assert.That(email.Attachments[0].MimeType, Is.EqualTo("application/pdf"));
        });
    }

    /// <summary>
    /// Tests that attachments stored before metadata encryption are still readable. These cannot
    /// be migrated, because the server cannot recover the symmetric key of an existing email.
    /// </summary>
    [Test]
    public void LegacyPlaintextAttachmentMetadataIsReturnedAsIs()
    {
        var email = CreateEmailWithAttachment("passport_scan.pdf", "application/pdf");

        EmailEncryption.EncryptEmail(email, CreateEncryptionKey());

        // Simulate an email that was stored before attachment metadata was encrypted.
        email.Attachments[0].Filename = "legacy_invoice.pdf";
        email.Attachments[0].MimeType = "application/pdf";

        EmailEncryption.DecryptEmail(email, RsaEncryptionTests.PrivateKey);

        Assert.Multiple(() =>
        {
            Assert.That(email.Attachments[0].Filename, Is.EqualTo("legacy_invoice.pdf"));
            Assert.That(email.Attachments[0].MimeType, Is.EqualTo("application/pdf"));
        });
    }

    /// <summary>
    /// Tests that a legacy filename which happens to be valid base64 is not mangled. Such a value
    /// gets past the base64 decode and has to be rejected by the AES-GCM authentication tag.
    /// </summary>
    [Test]
    public void LegacyPlaintextThatLooksLikeBase64IsReturnedAsIs()
    {
        var email = CreateEmailWithAttachment("passport_scan.pdf", "application/pdf");

        EmailEncryption.EncryptEmail(email, CreateEncryptionKey());

        email.Attachments[0].Filename = "SGVsbG9Xb3JsZEZpbGVOYW1lRXhhbXBsZVZhbHVl";

        EmailEncryption.DecryptEmail(email, RsaEncryptionTests.PrivateKey);

        Assert.That(email.Attachments[0].Filename, Is.EqualTo("SGVsbG9Xb3JsZEZpbGVOYW1lRXhhbXBsZVZhbHVl"));
    }

    /// <summary>
    /// Creates an email with a single attachment for use in the tests.
    /// </summary>
    /// <param name="filename">The attachment filename.</param>
    /// <param name="mimeType">The attachment MIME type.</param>
    /// <returns>An unencrypted email object.</returns>
    private static Email CreateEmailWithAttachment(string filename, string mimeType)
    {
        return new Email
        {
            Subject = "Your documents",
            From = "sender@example.com",
            FromLocal = "sender",
            FromDomain = "example.com",
            To = "alias@example.com",
            ToLocal = "alias",
            ToDomain = "example.com",
            MessageSource = "raw mime source",
            Attachments =
            [
                new EmailAttachment
                {
                    Bytes = Encoding.UTF8.GetBytes("file contents"),
                    Filename = filename,
                    MimeType = mimeType,
                    Filesize = 13,
                },
            ],
        };
    }

    /// <summary>
    /// Creates a user encryption key holding the test RSA public key.
    /// </summary>
    /// <returns>A user encryption key.</returns>
    private static UserEncryptionKey CreateEncryptionKey()
    {
        return new UserEncryptionKey
        {
            Id = Guid.NewGuid(),
            PublicKey = RsaEncryptionTests.PublicKey,
        };
    }
}
